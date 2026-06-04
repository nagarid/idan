#!/bin/bash
# Calico NetworkPolicy Bypass Research — Environment Setup
#
# Run OUTSIDE the cluster with kubectl access.
# Creates the test namespace, pods, NetworkPolicy, and privileged attack pod.
#
# Usage: ./calico_setup.sh [setup|baseline|watch|cleanup]
#
# Install Calico on minikube first:
#   minikube start --network-plugin=cni --cni=false
#   kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
#   kubectl wait --for=condition=Ready pods -n kube-system -l k8s-app=calico-node --timeout=120s

set -euo pipefail

RED='\033[1;31m'; GREEN='\033[1;32m'; CYAN='\033[1;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

NS="calico-research"
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

    # Confirm Calico is the CNI (calico-node DaemonSet in kube-system)
    if ! kubectl get pods -n kube-system -l k8s-app=calico-node \
            --no-headers 2>/dev/null | grep -q Running; then
        fail "No running calico-node pods found — is Calico the CNI?"
        info "Install Calico:"
        info "  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml"
        exit 1
    fi
    CALICO_NODE=$(kubectl get pods -n kube-system -l k8s-app=calico-node \
        -o jsonpath='{.items[0].spec.nodeName}')
    ok "Calico is running  node=$CALICO_NODE"
    echo "$CALICO_NODE" > /tmp/calico_research_node
}

# ── setup ─────────────────────────────────────────────────────────────────────
setup() {
    check_prereqs
    TARGET_NODE=$(cat /tmp/calico_research_node)
    section "Creating test pods on node: $TARGET_NODE"

    kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

    # ── target pod (nginx, blocks all ingress except from allowed-source) ─────
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

    # ── allowed-source pod ────────────────────────────────────────────────────
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

    # ── blocked-source pod ────────────────────────────────────────────────────
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

    # ── NetworkPolicy: allow ingress ONLY from allowed-source ─────────────────
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

    # ── privileged attack pod ─────────────────────────────────────────────────
    # Needs hostPID + /proc mount to nsenter the host network namespace and
    # run iptables/ipset commands against the host (not the pod's netns).
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
    - name: hostproc
      mountPath: /hostproc
    - name: bpffs
      mountPath: /sys/fs/bpf
  volumes:
  - name: hostproc
    hostPath:
      path: /proc
  - name: bpffs
    hostPath:
      path: /sys/fs/bpf
EOF

    section "Waiting for pods"
    kubectl wait --for=condition=Ready pod/policy-target \
        pod/allowed-source pod/blocked-source pod/attack-pod \
        -n "$NS" --timeout=120s
    ok "All pods ready"

    TARGET_IP=$(kubectl get pod policy-target  -n "$NS" -o jsonpath='{.status.podIP}')
    BLOCKED_IP=$(kubectl get pod blocked-source -n "$NS" -o jsonpath='{.status.podIP}')
    ALLOWED_IP=$(kubectl get pod allowed-source -n "$NS" -o jsonpath='{.status.podIP}')

    echo "$TARGET_IP"  > /tmp/calico_research_target_ip
    echo "$BLOCKED_IP" > /tmp/calico_research_blocked_ip
    echo "$ALLOWED_IP" > /tmp/calico_research_allowed_ip

    section "Pod summary"
    echo -e "  ${GREEN}allowed-source${NC}  $ALLOWED_IP  → should reach  policy-target"
    echo -e "  ${RED}blocked-source${NC}  $BLOCKED_IP  → should be BLOCKED from policy-target"
    echo -e "  ${CYAN}policy-target${NC}   $TARGET_IP   → nginx, NetworkPolicy enforced"
    echo ""
    ok "Setup complete. Run: ./calico_setup.sh baseline"
}

# ── baseline ──────────────────────────────────────────────────────────────────
baseline() {
    check_prereqs
    TARGET_IP=$(cat /tmp/calico_research_target_ip 2>/dev/null \
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
    ok "Baseline confirmed."
    info "Copy attack script:"
    info "  kubectl exec -n $NS attack-pod -- mkdir -p /attack"
    info "  kubectl cp poc/calico_attack.sh $NS/attack-pod:/attack/calico_attack.sh"
}

# ── watch ─────────────────────────────────────────────────────────────────────
watch_policy() {
    TARGET_IP=$(cat /tmp/calico_research_target_ip 2>/dev/null \
        || { fail "run setup first"; exit 1; })
    section "Watching NetworkPolicy enforcement (Ctrl+C to stop)"
    while true; do
        TS=$(date '+%H:%M:%S.%3N')
        if kubectl exec -n "$NS" blocked-source -- \
                curl -s --max-time 2 "http://$TARGET_IP" -o /dev/null 2>/dev/null; then
            echo -e "  $TS  ${RED}BYPASSED${NC}"
        else
            echo -e "  $TS  ${GREEN}BLOCKED${NC}"
        fi
        sleep 2
    done
}

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    info "Deleting namespace $NS"
    kubectl delete namespace "$NS" --ignore-not-found
    rm -f /tmp/calico_research_*
    ok "Cleaned up"
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
