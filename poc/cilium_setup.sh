#!/bin/bash
# Cilium NetworkPolicy Bypass Research — Environment Setup
#
# Run this OUTSIDE the cluster with kubectl access.
# Creates the test namespace, pods, NetworkPolicy, and the privileged attack pod.
#
# Usage: ./cilium_setup.sh [setup|baseline|cleanup]

set -euo pipefail

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

NS="cilium-research"
ATTACK_IMAGE="ubuntu:22.04"

info()    { echo -e "${YELLOW}[INFO]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────"; }

# ── prereqs ──────────────────────────────────────────────────────────────────
check_prereqs() {
    section "Checking prerequisites"
    command -v kubectl >/dev/null || { fail "kubectl not found"; exit 1; }
    kubectl cluster-info >/dev/null 2>&1 || { fail "no cluster access"; exit 1; }
    ok "kubectl connected: $(kubectl config current-context)"

    # confirm Cilium is the CNI
    if ! kubectl get pods -n kube-system -l k8s-app=cilium \
            --no-headers 2>/dev/null | grep -q Running; then
        fail "No running Cilium pods found in kube-system — is Cilium the CNI?"
        exit 1
    fi
    CILIUM_POD=$(kubectl get pods -n kube-system -l k8s-app=cilium \
        -o jsonpath='{.items[0].metadata.name}')
    CILIUM_NODE=$(kubectl get pods -n kube-system -l k8s-app=cilium \
        -o jsonpath='{.items[0].spec.nodeName}')
    ok "Cilium is running: pod=$CILIUM_POD  node=$CILIUM_NODE"
    echo "$CILIUM_NODE" > /tmp/cilium_research_node
}

# ── setup ─────────────────────────────────────────────────────────────────────
setup() {
    check_prereqs
    TARGET_NODE=$(cat /tmp/cilium_research_node)
    section "Creating namespace and test pods on node: $TARGET_NODE"

    kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

    # ── target pod (nginx, blocks all ingress except from allowed-source) ──────
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: policy-target
  namespace: $NS
  labels:
    role: policy-target
spec:
  nodeName: $TARGET_NODE
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
EOF

    # ── allowed-source pod (should be able to reach policy-target) ────────────
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: allowed-source
  namespace: $NS
  labels:
    role: allowed-source
spec:
  nodeName: $TARGET_NODE
  containers:
  - name: curl
    image: curlimages/curl:latest
    command: ["sleep", "3600"]
EOF

    # ── blocked-source pod (should be BLOCKED from policy-target) ─────────────
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: blocked-source
  namespace: $NS
  labels:
    role: blocked-source
spec:
  nodeName: $TARGET_NODE
  containers:
  - name: curl
    image: curlimages/curl:latest
    command: ["sleep", "3600"]
EOF

    # ── NetworkPolicy: allow ingress to policy-target ONLY from allowed-source ─
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-only-from-allowed
  namespace: $NS
spec:
  podSelector:
    matchLabels:
      role: policy-target
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: allowed-source
EOF

    # ── privileged attack pod (with all required mounts) ──────────────────────
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: attack-pod
  namespace: $NS
  labels:
    role: attack-pod
spec:
  nodeName: $TARGET_NODE
  hostPID: true
  containers:
  - name: attacker
    image: $ATTACK_IMAGE
    command: ["sleep", "7200"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: bpffs
      mountPath: /sys/fs/bpf
    - name: cgroupfs
      mountPath: /sys/fs/cgroup
    - name: hostproc
      mountPath: /hostproc
  volumes:
  - name: bpffs
    hostPath:
      path: /sys/fs/bpf
  - name: cgroupfs
    hostPath:
      path: /sys/fs/cgroup
  - name: hostproc
    hostPath:
      path: /proc
EOF

    section "Waiting for pods to be Ready"
    kubectl wait --for=condition=Ready pod/policy-target \
        pod/allowed-source pod/blocked-source pod/attack-pod \
        -n "$NS" --timeout=120s
    ok "All pods ready"

    # ── print IPs ─────────────────────────────────────────────────────────────
    TARGET_IP=$(kubectl get pod policy-target -n "$NS" -o jsonpath='{.status.podIP}')
    BLOCKED_IP=$(kubectl get pod blocked-source -n "$NS" -o jsonpath='{.status.podIP}')
    ALLOWED_IP=$(kubectl get pod allowed-source -n "$NS" -o jsonpath='{.status.podIP}')

    echo "$TARGET_IP"  > /tmp/cilium_research_target_ip
    echo "$BLOCKED_IP" > /tmp/cilium_research_blocked_ip
    echo "$ALLOWED_IP" > /tmp/cilium_research_allowed_ip

    section "Pod summary"
    echo -e "  ${GREEN}allowed-source${NC}  $ALLOWED_IP  → should reach  policy-target"
    echo -e "  ${RED}blocked-source${NC}  $BLOCKED_IP  → should be BLOCKED from policy-target"
    echo -e "  ${CYAN}policy-target${NC}   $TARGET_IP   → nginx, NetworkPolicy enforced"
    echo ""
    ok "Setup complete. Run baseline check next: ./cilium_setup.sh baseline"
}

# ── baseline ──────────────────────────────────────────────────────────────────
baseline() {
    check_prereqs
    TARGET_IP=$(cat /tmp/cilium_research_target_ip 2>/dev/null \
        || kubectl get pod policy-target -n "$NS" -o jsonpath='{.status.podIP}')

    section "Baseline: verifying NetworkPolicy is enforced"

    echo -n "  allowed-source → policy-target: "
    if kubectl exec -n "$NS" allowed-source -- \
            curl -s --max-time 3 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
        echo -e "${GREEN}ALLOWED${NC} ✓"
    else
        echo -e "${RED}BLOCKED${NC} (unexpected — policy may not be applied yet)"
    fi

    echo -n "  blocked-source → policy-target: "
    if kubectl exec -n "$NS" blocked-source -- \
            curl -s --max-time 3 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
        echo -e "${RED}ALLOWED${NC} (unexpected — policy not enforced!)"
    else
        echo -e "${GREEN}BLOCKED${NC} ✓  (NetworkPolicy working)"
    fi

    echo ""
    ok "Baseline confirmed. NetworkPolicy is enforced by Cilium."
    info "Now exec into attack-pod and run: bash /attack/cilium_attack.sh"
    info "Copy the attack script first:"
    info "  kubectl cp poc/cilium_attack.sh $NS/attack-pod:/attack/cilium_attack.sh"
}

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    info "Deleting namespace $NS (removes all test resources)"
    kubectl delete namespace "$NS" --ignore-not-found
    rm -f /tmp/cilium_research_*
    ok "Cleaned up"
}

# ── connectivity probe (run repeatedly to watch recovery) ────────────────────
watch_policy() {
    TARGET_IP=$(cat /tmp/cilium_research_target_ip 2>/dev/null \
        || { fail "run setup first"; exit 1; })

    section "Watching NetworkPolicy enforcement (Ctrl+C to stop)"
    info "blocked-source → policy-target  |  timestamp  |  result"
    echo "─────────────────────────────────────────────────────"
    while true; do
        TS=$(date '+%H:%M:%S.%3N')
        if kubectl exec -n "$NS" blocked-source -- \
                curl -s --max-time 2 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
            echo -e "  $TS  ${RED}BYPASSED — connection succeeded (policy not enforced)${NC}"
        else
            echo -e "  $TS  ${GREEN}BLOCKED  — policy enforced${NC}"
        fi
        sleep 2
    done
}

case "${1:-help}" in
    setup)    setup ;;
    baseline) baseline ;;
    watch)    watch_policy ;;
    cleanup)  cleanup ;;
    *)
        echo "Usage: $0 {setup|baseline|watch|cleanup}"
        echo ""
        echo "  setup    — create test namespace, pods, NetworkPolicy, attack pod"
        echo "  baseline — verify NetworkPolicy is enforced before attack"
        echo "  watch    — continuously probe policy enforcement (run during attack)"
        echo "  cleanup  — delete all test resources"
        ;;
esac
