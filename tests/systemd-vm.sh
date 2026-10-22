#!/usr/bin/env bash
# Boots and reboots a real disposable Ubuntu VM; never reboots the Actions runner.
set -Eeuo pipefail
[[ ${VPN_E2E_DISPOSABLE:-} == 1 && $EUID == 0 ]] || exit 2
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
installer=${1:?}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
logs=${VPN_E2E_LOG_DIR:-/tmp/vpn-vm-results}/systemd-$installer
mkdir -p "$logs"
state=$(mktemp -d /tmp/vpn-systemd.XXXXXX)
vm_pid=''; target_pid=''; phase=prepare
cleanup() {
    status=$?
    trap - EXIT
    set +e
    [[ -z $target_pid ]] || kill "$target_pid" 2>/dev/null
    [[ -z $vm_pid ]] || kill "$vm_pid" 2>/dev/null
    [[ -z $vm_pid ]] || wait "$vm_pid" 2>/dev/null
    printf '{"exit_status":%s,"last_phase":"%s","image":"Ubuntu 24.04 amd64"}\n' "$status" "$phase" > "$logs/status.json"
    rm -rf "$state"
    chmod -R a+rX "$logs"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
accel=(-accel tcg,thread=multi -cpu max)
if [[ -c /dev/kvm ]]; then accel=(-enable-kvm -cpu host); fi
printf '%s\n' "${accel[*]}" > "$logs/acceleration.txt"
image=noble-server-cloudimg-amd64.img
base=https://cloud-images.ubuntu.com/noble/current
curl --fail --location --retry 3 "$base/SHA256SUMS" -o "$state/SHA256SUMS"
curl --fail --location --retry 3 "$base/$image" -o "$state/$image"
(cd "$state"; grep -E "^[0-9a-f]{64} [ *]$image$" SHA256SUMS > selected.sha256; test -s selected.sha256; sha256sum --strict -c selected.sha256)
cp "$state/selected.sha256" "$logs/image.sha256"
ssh-keygen -q -t ed25519 -N '' -f "$state/client-key"
ssh-keygen -q -t ed25519 -N '' -f "$state/host-key"
python3 - "$state" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
config = {'users': [{'name': 'ci', 'groups': ['sudo'], 'shell': '/bin/bash',
    'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'ssh_authorized_keys': [(p/'client-key.pub').read_text().strip()]}],
    'ssh_pwauth': False, 'disable_root': True,
    'ssh_keys': {'ed25519_private': (p/'host-key').read_text(), 'ed25519_public': (p/'host-key.pub').read_text().strip()}}
(p/'user-data').write_text('#cloud-config\n' + json.dumps(config))
(p/'meta-data').write_text('instance-id: vpn-systemd-fixture\nlocal-hostname: vpn-systemd\n')
PY
cloud-localds "$state/seed.img" "$state/user-data" "$state/meta-data"
qemu-img create -f qcow2 -F qcow2 -b "$state/$image" "$state/disk.qcow2" 20G
identity=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
[[ $identity =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
printf '[127.0.0.1]:2222 %s\n' "$(cat "$state/host-key.pub")" > "$state/known_hosts"
ssh_opts=(-i "$state/client-key" -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$state/known_hosts" -o ConnectTimeout=5 -o ServerAliveInterval=10 -o ServerAliveCountMax=3)
remote() { ssh "${ssh_opts[@]}" ci@127.0.0.1 "$@"; }
qemu-system-x86_64 "${accel[@]}" -smp 2 -m 4096 -nographic \
    -drive "file=$state/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$state/seed.img,if=virtio,format=raw" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:$identity:4443-:4443,hostfwd=udp:$identity:4443-:4443" \
    -device virtio-net-pci,netdev=net0 > "$state/serial.log" 2>&1 &
vm_pid=$!
phase=first-boot
for ((n=0; n<90; n++)); do
    remote true 2>/dev/null && break
    kill -0 "$vm_pid"
    sleep 2
done
remote 'sudo cloud-init status --wait' > "$state/cloud-init-status" 2>&1
# Transfer only repository files, never .git credentials or runner configuration.
tar -C "$repo" --exclude=.git --exclude=__pycache__ -czf "$state/source.tgz" .
cat "$state/source.tgz" | remote 'mkdir -p /home/ci/source && tar -xzf - -C /home/ci/source'
guest() { remote "sudo env VPN_E2E_DISPOSABLE=1 bash /home/ci/source/tests/systemd-guest.sh $installer $1 $identity"; }
phase=normal-installer
guest install
guest check
remote 'sudo cat /root/vpn-systemd-fixture/password' > "$state/password"
remote 'sudo cat /etc/ocserv/ssl/ca-cert.pem' > "$state/ca.pem"
python3 "$repo/tests/vpn-workload.py" http --bind 127.0.0.1 --port 18080 > "$state/http.log" 2>&1 &
target_pid=$!
docker build -t vpn-external-probe -f "$repo/tests/vpn-probe.Dockerfile" "$repo" > "$state/docker-build.log" 2>&1
probe() {
    local transport=$1 label=$2
    python3 - "$state" "$identity" "$transport" "$repo" <<'PY'
import json, runpy, sys
from pathlib import Path
p = Path(sys.argv[1])
digest = runpy.run_path(sys.argv[4] + '/tests/vpn-workload.py')['DIGEST']
(p/'probe.json').write_text(json.dumps({'endpoint': 'https://' + sys.argv[2] + ':4443/',
    'username': 'boot-test', 'password_file': '/secrets/password', 'ca_file': '/secrets/ca.pem',
    'target_url': 'http://10.0.2.2:18080/payload', 'target_ip': '10.0.2.2',
    'expected_sha256': digest, 'transport': sys.argv[3], 'require_unreachable': True}))
PY
    docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -e VPN_E2E_DISPOSABLE=1 \
        -v "$state:/secrets:ro" -v "$logs:/reports" vpn-external-probe \
        /secrets/probe.json --report "/reports/$label.json"
}
phase=initial-traffic
probe tls initial-tls; probe dtls initial-dtls
phase=service-restart
guest restarted; probe dtls service-restart
phase=crash-recovery
guest crashed; probe tls crash-recovery
phase=stop-start
guest stopped
if probe tls stopped-negative; then echo 'Stopped service accepted VPN traffic' >&2; exit 1; fi
guest started; probe tls restarted-positive
reboot_vm() {
    local before after=''
    before=$(remote cat /proc/sys/kernel/random/boot_id)
    remote 'sudo systemctl reboot' || [[ $? == 255 ]]
    for ((n=0; n<90; n++)); do
        after=$(remote cat /proc/sys/kernel/random/boot_id 2>/dev/null) || true
        [[ -n $after && $after != "$before" ]] && break
        kill -0 "$vm_pid"
        sleep 2
    done
    [[ -n $after && $after != "$before" ]]
    printf '%s -> %s\n' "$before" "$after" >> "$logs/boot-ids.txt"
    remote 'sudo systemctl is-system-running --wait' > "$state/system-state" || \
        grep -q '^degraded$' "$state/system-state"
}
phase=reboot
reboot_vm
guest booted
probe tls after-reboot-tls; probe dtls after-reboot-dtls
phase=uninstall
guest uninstall; guest absent
phase=reboot-after-uninstall
reboot_vm
guest absent
if probe tls uninstalled-negative; then echo 'Uninstalled service accepted VPN traffic' >&2; exit 1; fi
phase=complete
printf 'PASS: real VM normal install, start/stop/restart, crash recovery, boot-ID changes, autostart, traffic and uninstall\n'
