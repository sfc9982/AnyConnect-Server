#!/usr/bin/env bash
# Real account/PKI regressions, isolated from the E2E server and its credentials.
set -euo pipefail
export LC_ALL=C
umask 077
: "${VPN_E2E_DISPOSABLE:?Use a disposable test container}"
[[ "$VPN_E2E_DISPOSABLE" == 1 && "$EUID" -eq 0 ]] || exit 1

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
self="$repo_dir/tests/account-concurrency.sh"
worker_mode=0
if [[ "${1:-}" == --worker ]]; then worker_mode=1; shift; fi
installer="${1:?installer script required}"
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo_dir/$installer"

use_fixture() {
    case_dir="$1"
    conf_file="$case_dir/config"
    conf="$conf_file/ocserv.conf"
    passwd_file="$case_dir/ocpasswd"
    log_file="$case_dir/ocserv.log"
    SSL_DIR="$case_dir/ssl"
    USERS_DIR="$SSL_DIR/users"
    DISABLED_DIR="$SSL_DIR/disabled"
    CA_CERT="$SSL_DIR/ca-cert.pem"
    CA_KEY="$SSL_DIR/ca-key.pem"
    CRL_PEM="$SSL_DIR/crl.pem"
    CRL_TMPL="$SSL_DIR/crl.tmpl"
    REVOKED_PEM="$SSL_DIR/revoked.pem"
    SUSPENDED_PEM="$SSL_DIR/suspended.pem"
    PID_FILE="$case_dir/no-server.pid"
}

if (( worker_mode )); then
    use_fixture "${2:?fixture required}"
    label="${3:?worker label required}"
    action="${4:?worker action required}"
    gate="${5:-}"
    if [[ "$gate" == crl ]]; then
        # Generate a genuine signed CRL, then pause before the helper publishes it.
        # Only timing is controlled; certtool's arguments/output/status are real.
        certtool() {
            local argument is_crl=0 deadline
            for argument in "$@"; do
                [[ "$argument" != --generate-crl ]] || is_crl=1
            done
            command certtool "$@" || return $?
            if (( is_crl )) && [[ ! -e "$case_dir/$label.entered" ]]; then
                : > "$case_dir/$label.entered" || return 1
                deadline=$((SECONDS + 30))
                while [[ ! -e "$case_dir/$label.release" ]]; do
                    (( SECONDS < deadline )) || { echo 'CRL barrier timed out' >&2; return 1; }
                    sleep 0.05
                done
            fi
        }
    fi
    case "$action" in
        init) if Generate_SSL 192.0.2.1 && Ensure_CRL; then result=0; else result=$?; fi ;;
        add) if Add_User; then result=0; else result=$?; fi ;;
        toggle) if Modify_User_disabled; then result=0; else result=$?; fi ;;
        delete) if Del_User; then result=0; else result=$?; fi ;;
        crl) if Rebuild_CRL; then result=0; else result=$?; fi ;;
        *) exit 2 ;;
    esac
    printf '%s\n' "$result" > "$case_dir/$label.status.tmp"
    mv "$case_dir/$label.status.tmp" "$case_dir/$label.status"
    exit "$result"
fi

for executable in certtool ocpasswd openssl flock cmp python3 timeout; do
    command -v "$executable" >/dev/null || { echo "Missing test tool: $executable" >&2; exit 1; }
done
test_root=$(mktemp -d /tmp/ocserv-concurrency.XXXXXX)
declare -A workers=() results=()
cleanup() {
    local result=$? pid log
    trap - EXIT
    for pid in "${workers[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${workers[@]}"; do wait "$pid" 2>/dev/null || true; done
    if (( result )); then
        for log in "$test_root"/*/*.log; do
            [[ -f "$log" ]] || continue
            printf '\n--- %s ---\n' "${log#"$test_root/"}" >&2
            tail -n 35 "$log" >&2
        done
    fi
    rm -rf "$test_root"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { printf 'FAIL: %s: %s\n' "$installer" "$*" >&2; exit 1; }

start_worker() {
    local label="$1" action="$2" input="$3" gate="${4:-}"
    timeout --kill-after=3 90 bash "$self" --worker "$installer" "$case_dir" "$label" "$action" "$gate" \
        < "$input" > "$case_dir/$label.log" 2>&1 &
    workers["$label"]=$!
}

finish_worker() {
    local label="$1" result recorded
    if wait "${workers[$label]}"; then result=0; else result=$?; fi
    unset 'workers[$label]'
    [[ -s "$case_dir/$label.status" ]] || fail "$label exited without a result (status $result)"
    recorded=$(cat "$case_dir/$label.status")
    [[ "$recorded" == "$result" ]] || fail "$label result disagrees with process status"
    results["$label"]="$result"
}

run_success() {
    local label="$1" action="$2" input="$3"
    start_worker "$label" "$action" "$input"
    finish_worker "$label"
    [[ "${results[$label]}" == 0 ]] || fail "$label failed"
}

new_fixture() {
    use_fixture "$test_root/$1"
    mkdir -p "$conf_file" "$case_dir/saved"
    printf 'pid-file = %s\n' "$PID_FILE" > "$conf"
    run_success setup init /dev/null
}

# Poll observed states, never assume that a contender runs within a fixed sleep.
# A contender may finish without waiting (the unsafe implementation does this),
# or block on the real account lock. Either event releases the first writer;
# only the final credentials and signed CRL determine whether the test passes.
wait_for() {
    local mode="$1" label="$2" first="${3:-}" expected="${4:-}"
    python3 - "$mode" "$case_dir" "$label" "$first" "$expected" "${workers[$label]}" <<'PY' || fail "$mode barrier for $label failed"
import os
from pathlib import Path
import sys
import time

mode, directory, label, first, expected, worker_pid = sys.argv[1:]
root = Path(directory)
lock_path = str(root / "ssl" / ".accounts.lock")
observed = {}

def blocked_contender():
    # /proc/locks can hide locks whose original owner exited, and OverlayFS
    # inode identities need not match stat(). Inspect only this worker's live
    # descendants and their actual lock descriptor/kernel wait instead.
    pending = [int(worker_pid)]
    while pending:
        pid = pending.pop()
        process = Path("/proc") / str(pid)
        try:
            pending.extend(map(int, (process / "task" / str(pid) / "children").read_text().split()))
            if Path(os.readlink(process / "exe")).name != "flock":
                continue
            descriptors = {
                int(fd.name) for fd in (process / "fd").iterdir()
                if os.readlink(fd) == lock_path
            }
            if not descriptors:
                continue
            wait_channel = (process / "wchan").read_text().strip()
            observed[pid] = wait_channel
            try:
                syscall = (process / "syscall").read_text().split()
                # All CI images run on the runner's x86_64 kernel: flock=73,
                # with the file descriptor and LOCK_EX (2) as its arguments.
                if (os.uname().machine == "x86_64" and len(syscall) >= 3
                        and int(syscall[0], 0) == 73
                        and int(syscall[1], 0) in descriptors
                        and int(syscall[2], 0) == 2):
                    return True
            except (OSError, ValueError):
                pass
            if wait_channel in {"locks_lock_inode_wait", "flock_lock_inode_wait"}:
                return True
        except OSError:
            # Processes can exit between reads; their recorded result is
            # checked by the surrounding loop and final status assertions.
            continue
    return False

deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    status = root / (label + ".status")
    if mode == "entered" and (root / (label + ".entered")).exists():
        sys.exit(0)
    if mode == "password":
        log = root / (label + ".log")
        if log.exists() and expected in log.read_text(errors="replace"):
            sys.exit(0)
    if mode == "contender":
        if status.exists():
            sys.exit(0)
        if (root / (first + ".status")).exists():
            sys.exit("First writer exited before its barrier was released")
        if blocked_contender():
            sys.exit(0)
    elif status.exists():
        sys.exit("Writer exited before reaching the expected barrier")
    time.sleep(0.05)
sys.exit(f"Timed out waiting for an observed worker state; flock wait channels: {observed}")
PY
}

valid_certificate() {
    openssl verify -CAfile "$CA_CERT" -CRLfile "$CRL_PEM" -crl_check -purpose sslclient "$1" \
        > "$case_dir/verify.log" 2>&1 || fail "expected a valid client certificate: ${1##*/}"
}

revoked_certificate() {
    if openssl verify -CAfile "$CA_CERT" -CRLfile "$CRL_PEM" -crl_check -purpose sslclient "$1" \
        > "$case_dir/verify.log" 2>&1; then
        fail "revoked client certificate is still valid: ${1##*/}"
    fi
    grep -Eq 'error 23 |certificate revoked' "$case_dir/verify.log" ||
        fail 'certificate rejection was not caused by revocation'
}

add_fixture_user() {
    local user="$1"
    printf '%s\n' "$user" > "$case_dir/$user.input"
    openssl rand -hex 16 >> "$case_dir/$user.input"
    run_success "add-$user" add "$case_dir/$user.input"
    cp "$USERS_DIR/$user/$user.cer" "$case_dir/saved/$user.cer"
}

deleted_user() {
    local user="$1" count
    [[ ! -e "$USERS_DIR/$user" ]] || fail "deleted user $user still has an active certificate directory"
    if Find_Suspended_User "$user" >/dev/null; then fail "deleted user $user still has a suspended certificate"; fi
    if [[ -e "$passwd_file" || -L "$passwd_file" ]]; then
        [[ -f "$passwd_file" ]] || fail 'password database is not a regular file'
        count=$(awk -F: -v user="$user" '$1==user {count++} END {print count+0}' "$passwd_file") ||
            fail 'cannot read the password database after deletion'
        [[ "$count" == 0 ]] || fail "deleted user $user still has password credentials"
    fi
}

new_fixture duplicate-add
user=race-user
for label in first second; do
    openssl rand -hex 16 > "$case_dir/$label.password"
    { printf '%s\n' "$user"; cat "$case_dir/$label.password"; } > "$case_dir/$label.input"
done
# Both helpers receive a username. Withhold A's password after its uniqueness
# check, allowing B to attempt the same name before A can publish anything.
mkfifo "$case_dir/first.fifo"
exec {input_fd}<>"$case_dir/first.fifo"
start_worker first add "$case_dir/first.fifo"
printf '%s\n' "$user" >&"$input_fd"
wait_for password first '' "$user"
start_worker second add "$case_dir/second.input"
wait_for contender second first
cat "$case_dir/first.password" >&"$input_fd"
exec {input_fd}>&-
finish_worker first
finish_worker second
if [[ "${results[first]}" == 0 && "${results[second]}" != 0 ]]; then
    winner=first; loser=second
elif [[ "${results[second]}" == 0 && "${results[first]}" != 0 ]]; then
    winner=second; loser=first
else
    fail 'concurrent same-name adds must have exactly one successful publisher'
fi
[[ "$(awk -F: -v user="$user" '$1==user {count++} END {print count+0}' "$passwd_file")" == 1 ]] ||
    fail 'same-name add published an unexpected number of password records'
stored=$(awk -F: -v user="$user" '$1==user {print $NF}' "$passwd_file")
# ocpasswd 1.5 uses SHA-256 crypt, with MD5 crypt as its compatibility fallback.
# Verify the real stored hash using its algorithm/salt; Python crypt was removed.
IFS='$' read -r prefix algorithm salt digest extra <<< "$stored"
[[ -z "$prefix" && -n "$salt" && -n "$digest" && -z "$extra" ]] || fail 'unexpected password hash format'
case "$algorithm" in 1|5|6) ;; *) fail 'unsupported password hash algorithm' ;; esac
[[ "$(openssl passwd "-$algorithm" -salt "$salt" -stdin < "$case_dir/$winner.password")" == "$stored" ]] ||
    fail 'published password does not authenticate the winning add'
[[ "$(openssl passwd "-$algorithm" -salt "$salt" -stdin < "$case_dir/$loser.password")" != "$stored" ]] ||
    fail 'the losing add also authenticates against the published password'
bundle="$USERS_DIR/$user/$user.p12"
openssl pkcs12 -in "$bundle" -passin "file:$case_dir/$winner.password" -noout \
    > "$case_dir/bundle.log" 2>&1 || fail 'winning password does not open the published bundle'
if openssl pkcs12 -in "$bundle" -passin "file:$case_dir/$loser.password" -noout \
    >> "$case_dir/bundle.log" 2>&1; then fail 'losing password opens the published bundle'; fi
openssl pkcs12 -in "$bundle" -passin "file:$case_dir/$winner.password" -clcerts -nokeys \
    -out "$case_dir/saved/bundle.cer" >> "$case_dir/bundle.log" 2>&1
openssl pkcs12 -in "$bundle" -passin "file:$case_dir/$winner.password" -nocerts -nodes \
    -out "$case_dir/saved/bundle.key" >> "$case_dir/bundle.log" 2>&1
[[ "$(openssl x509 -in "$USERS_DIR/$user/$user.cer" -noout -fingerprint -sha256)" == \
    "$(openssl x509 -in "$case_dir/saved/bundle.cer" -noout -fingerprint -sha256)" ]] ||
    fail 'bundle and published certificate differ'
openssl x509 -in "$USERS_DIR/$user/$user.cer" -pubkey -noout > "$case_dir/saved/certificate.pub"
openssl pkey -in "$USERS_DIR/$user/$user-key.pem" -pubout > "$case_dir/saved/private.pub"
openssl pkey -in "$case_dir/saved/bundle.key" -pubout > "$case_dir/saved/bundle.pub"
cmp -s "$case_dir/saved/certificate.pub" "$case_dir/saved/private.pub" || fail 'published certificate/private key mismatch'
cmp -s "$case_dir/saved/certificate.pub" "$case_dir/saved/bundle.pub" || fail 'bundle private key does not match the certificate'
valid_certificate "$USERS_DIR/$user/$user.cer"
printf 'PASS: %s concurrent same-name adds publish exactly one matching password/certificate/key/bundle\n' "$installer"

new_fixture restore-delete
user=restore-user
add_fixture_user "$user"
printf '%s\n' "$user" > "$case_dir/user.input"
run_success suspend toggle "$case_dir/user.input"
revoked_certificate "$case_dir/saved/$user.cer"
start_worker restore toggle "$case_dir/user.input" crl
wait_for entered restore
start_worker delete delete "$case_dir/user.input"
wait_for contender delete restore
: > "$case_dir/restore.release"
finish_worker restore
finish_worker delete
[[ "${results[restore]}" == 0 && "${results[delete]}" == 0 ]] || fail 'restore/delete operations did not both complete'
deleted_user "$user"
revoked_certificate "$case_dir/saved/$user.cer"
printf 'PASS: %s concurrent restore/delete leave no password or certificate and preserve real revocation\n' "$installer"

new_fixture stale-crl
for user in old-revoked new-revoked control-user; do add_fixture_user "$user"; done
printf 'old-revoked\n' > "$case_dir/old.input"
run_success delete-old delete "$case_dir/old.input"
revoked_certificate "$case_dir/saved/old-revoked.cer"
valid_certificate "$case_dir/saved/new-revoked.cer"
valid_certificate "$case_dir/saved/control-user.cer"
start_worker snapshot crl /dev/null crl
wait_for entered snapshot
printf 'new-revoked\n' > "$case_dir/new.input"
start_worker delete-new delete "$case_dir/new.input"
wait_for contender delete-new snapshot
: > "$case_dir/snapshot.release"
finish_worker snapshot
finish_worker delete-new
[[ "${results[snapshot]}" == 0 && "${results[delete-new]}" == 0 ]] || fail 'concurrent CRL rebuild/deletion did not both complete'
deleted_user new-revoked
revoked_certificate "$case_dir/saved/old-revoked.cer"
revoked_certificate "$case_dir/saved/new-revoked.cer"
valid_certificate "$case_dir/saved/control-user.cer"
printf 'PASS: %s concurrent CRL publication retains old and new revocations while the control certificate remains valid\n' "$installer"
printf 'Account concurrency suite complete: %s\n' "$installer"
