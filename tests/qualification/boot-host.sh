#!/usr/bin/env bash
# A real VM: kernel boot ID must change after both reboot and a cold power cycle.
set -Eeuo pipefail
[[ "${VPN_E2E_DISPOSABLE:-}" == 1 && "$EUID" -eq 0 ]] || exit 1
[[ -c /dev/kvm ]] || { echo 'KVM unavailable: boot qualification NOT RUN' >&2; exit 1; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
installer=${1:?}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
work=$(mktemp -d /tmp/vpn-boot.XXXXXX)
chmod 700 "$work"
logs=${VPN_E2E_LOG_DIR:-/tmp/vpn-boot-logs}/boot-$installer
mkdir -p "$logs"
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -s "$work/qemu.pid" ]]; then kill "$(cat "$work/qemu.pid")" 2>/dev/null || true; fi
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT
cd "$work"
image=ubuntu-24.04-server-cloudimg-amd64.img
base=https://cloud-images.ubuntu.com/releases/noble/release
curl --proto '=https' --tlsv1.2 -fSL --retry 3 "$base/SHA256SUMS" -o SHA256SUMS
curl --proto '=https' --tlsv1.2 -fSL --retry 3 "$base/$image" -o "$image"
awk -v file="$image" '$2 == file || $2 == "*" file {print}' SHA256SUMS > image.sha256
[[ -s image.sha256 ]]
sha256sum -c image.sha256
cp image.sha256 "$logs/image.sha256"
printf '%s\n' "$base/$image" > "$logs/image-url.txt"
ssh-keygen -q -t ed25519 -N '' -f key
cat > user-data <<EOF
#cloud-config
ssh_pwauth: false
ssh_authorized_keys:
  - $(cat key.pub)
EOF
printf 'instance-id: vpn-qualification\nlocal-hostname: vpn-qualification\n' > meta-data
cloud-localds seed.img user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$work/$image" disk.qcow2 12G
port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)
boot() {
    rm -f "$work/qemu.pid"
    qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 3072 -display none -daemonize \
        -drive file="$work/disk.qcow2",if=virtio,format=qcow2 \
        -drive file="$work/seed.img",if=virtio,format=raw \
        -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$port"-:22 -device virtio-net-pci,netdev=net0 \
        -serial file:"$work/serial.log" -pidfile "$work/qemu.pid"
}
ssh_args=(-i "$work/key" -p "$port" -o BatchMode=yes -o ConnectTimeout=3
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$work/known_hosts")
remote() { ssh "${ssh_args[@]}" ubuntu@127.0.0.1 "$@"; }
ready() {
    local previous=${1:-} current
    for ((attempt=0;attempt<180;attempt++)); do
        if current=$(remote cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [[ "$current" != "$previous" ]]; then
            printf '%s\n' "$current"
            return 0
        fi
        kill -0 "$(cat "$work/qemu.pid")" || return 1
        sleep 2
    done
    echo 'VM boot/SSH deadline exceeded' >&2
    return 1
}
boot
first=$(ready)
remote sudo cloud-init status --wait >/dev/null
# Strictly retain the first VM's host key across all later boots.
ssh_args=("${ssh_args[@]/StrictHostKeyChecking=accept-new/StrictHostKeyChecking=yes}")
tar -C "$repo" --exclude=.git --exclude=__pycache__ -czf "$work/source.tar.gz" .
remote 'sudo mkdir -p /opt/vpn-test; sudo tar xzf - -C /opt/vpn-test' < "$work/source.tar.gz"
remote "sudo env VPN_E2E_DISPOSABLE=1 bash /opt/vpn-test/tests/qualification/boot-guest.sh install $installer" > "$work/install.log" 2>&1 || {
    echo 'Real installer failed inside VM' >&2
    grep -Ei 'error|failed|failure at line|command not found' "$work/install.log" | tail -20 >&2 || true
    remote 'sudo journalctl --no-pager -u ocserv -n 40' || true
    exit 1
}
remote 'sudo env VPN_E2E_DISPOSABLE=1 bash /opt/vpn-test/tests/qualification/boot-guest.sh lifecycle' | tee "$logs/lifecycle.txt"
remote sudo reboot || true
second=$(ready "$first")
remote 'sudo env VPN_E2E_DISPOSABLE=1 bash /opt/vpn-test/tests/qualification/boot-guest.sh verify' | tee "$logs/reboot.txt"
remote sudo poweroff || true
for ((attempt=0;attempt<60;attempt++)); do
    [[ -s "$work/qemu.pid" ]] && kill -0 "$(cat "$work/qemu.pid")" 2>/dev/null || break
    sleep 1
done
if [[ -s "$work/qemu.pid" ]] && kill -0 "$(cat "$work/qemu.pid")" 2>/dev/null; then
    echo 'VM did not power off' >&2; exit 1
fi
boot
third=$(ready "$second")
[[ "$third" != "$first" ]]
remote 'sudo env VPN_E2E_DISPOSABLE=1 bash /opt/vpn-test/tests/qualification/boot-guest.sh verify' | tee "$logs/cold-boot.txt"
printf '{"passed":true,"boot_ids":["%s","%s","%s"]}\n' "$first" "$second" "$third" > "$logs/summary.json"
echo 'PASS: real systemd install, restart recovery, failed-firewall gating, reboot and cold boot with dual-stack VPN traffic'
