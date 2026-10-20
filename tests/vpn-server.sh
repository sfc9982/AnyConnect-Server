#!/usr/bin/env bash
# Invoke actual installer functions inside the isolated server network namespace.
# Match the interactive installer's shell options; assert results explicitly.
set -uo pipefail
: "${VPN_E2E_DISPOSABLE:?Use a disposable test container}"
[[ "$VPN_E2E_DISPOSABLE" == 1 && "$EUID" -eq 0 ]] || exit 1

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${1:?installer script required}"
action="${2:?action required}"
state_dir="${3:?state directory required}"
case "$script" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo_dir/$script"
export TERM=xterm

fail() { echo "$script: $*" >&2; exit 1; }
check_sys

case "$action" in
    configure)
        mkdir -p "$conf_file" || exit 1
        cp "$repo_dir/ocserv.conf" "$conf" || exit 1
        Generate_SSL 192.0.2.1 || fail 'server PKI generation failed'
        Ensure_CRL || fail 'initial CRL generation failed'
        # Stale directives must be replaced, not left active alongside the new ones.
        cat >> "$conf" <<'EOF'
auth = "plain[passwd=/nonexistent]"
enable-auth = "plain[passwd=/stale]"
ca-cert = /stale/ca.pem
crl = /stale/crl.pem
cert-user-oid = 1.2.3.4
EOF
        Configure_Auth || fail 'authentication configuration failed'
        Configure_Auth || fail 'repeated authentication configuration failed'
        for key in auth enable-auth ca-cert crl cert-user-oid; do
            [[ "$(grep -Ec "^[[:space:]]*${key}[[:space:]]*=" "$conf")" -eq 1 ]] ||
                fail "duplicate $key configuration"
        done
        # Keep production routes, auth, TLS policy and VPN address pool. Only fixture
        # endpoints and the deliberate authentication-failure rate need adjustment.
        Set_Conf_Value listen-host 192.0.2.1 || exit 1
        Set_Conf_Value tcp-port 4443 || exit 1
        Set_Conf_Value udp-port 4443 || exit 1
        Set_Conf_Value dns 198.51.100.2 || exit 1
        Set_Conf_Value max-ban-score 0 || exit 1
        "$file" --test-config -c "$conf" || fail 'ocserv rejected generated configuration'
        ;;
    add)
        Add_User < "$state_dir/account.input" || fail 'account creation failed'
        cp "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer" "$state_dir/client.cer" || exit 1
        cp "$USERS_DIR/e2e-susp-user/e2e-susp-user-key.pem" "$state_dir/client-key.pem" || exit 1
        cp "$USERS_DIR/e2e-susp-user/e2e-susp-user.p12" "$state_dir/client.p12" || exit 1
        cp "$CA_CERT" "$state_dir/ca.pem" || exit 1
        Add_User < "$state_dir/control.input" || fail 'control account creation failed'
        ;;
    duplicate)
        before="$(sha256sum "$passwd_file" "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")"
        if Add_User < "$state_dir/account.input"; then
            fail 'duplicate account silently replaced existing credentials'
        fi
        [[ "$before" == "$(sha256sum "$passwd_file" "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")" ]] ||
            fail 'duplicate account attempt changed existing credentials'
        ;;
    firewall)
        printf 'net.ipv4.ip_forward=0\n' > /etc/sysctl.conf || exit 1
        iptables -P FORWARD DROP || exit 1
        Set_iptables || fail 'firewall configuration failed'
        Set_iptables || fail 'repeated firewall configuration failed'
        Add_iptables 4443 4443 || fail 'service port rules failed'
        [[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail 'IPv4 forwarding stayed disabled'
        ;;
    toggle)
        Modify_User_disabled <<< 'e2e-susp-user' || fail 'account toggle failed'
        ;;
    delete)
        Del_User <<< 'e2e-susp-user' || fail 'account deletion failed'
        ;;
    *) fail "unknown action: $action" ;;
esac
