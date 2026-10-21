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
        Set_Conf_Value pid-file "$state_dir/ocserv-test.pid" || exit 1
        Set_Conf_Value occtl-socket-file "$state_dir/occtl-test.socket" || exit 1
        "$file" --test-config -c "$conf" || fail 'ocserv rejected generated configuration'
        ;;
    add|certificate-only)
        Add_User < "$state_dir/account.input" || fail 'account creation failed'
        cp "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer" "$state_dir/client.cer" || exit 1
        cp "$USERS_DIR/e2e-susp-user/e2e-susp-user-key.pem" "$state_dir/client-key.pem" || exit 1
        cp "$USERS_DIR/e2e-susp-user/e2e-susp-user.p12" "$state_dir/client.p12" || exit 1
        cp "$CA_CERT" "$state_dir/ca.pem" || exit 1
        if [[ "$action" == add ]]; then
            Add_User < "$state_dir/control.input" || fail 'control account creation failed'
        else
            pw_delete e2e-susp-user || fail 'certificate-only fixture setup failed'
            if pw_user_exists e2e-susp-user; then
                fail 'certificate-only fixture retained a password account'
            fi
        fi
        ;;
    duplicate)
        before="$(sha256sum "$passwd_file" "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")"
        if Add_User < "$state_dir/account.input"; then
            fail 'duplicate account silently replaced existing credentials'
        fi
        [[ "$before" == "$(sha256sum "$passwd_file" "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")" ]] ||
            fail 'duplicate account attempt changed existing credentials'
        ;;
    add-failed-certificate)
        rm -f "$state_dir/certificate-failure-injected" || exit 1
        certtool() {
            if [[ "${1:-}" == --generate-certificate ]]; then
                touch "$state_dir/certificate-failure-injected" || return 1
                echo 'Injected client certificate generation failure' >&2
                return 72
            fi
            command certtool "$@"
        }
        if Add_User < "$state_dir/account-failure.input"; then
            fail 'account creation concealed a certificate generation failure'
        fi
        [[ -f "$state_dir/certificate-failure-injected" ]] || fail 'account creation failed before certificate generation'
        if pw_user_exists e2e-failed-user || [[ -e "$USERS_DIR/e2e-failed-user" ]]; then
            fail 'failed creation published a partial account'
        fi
        ;;
    add-retry)
        Add_User < "$state_dir/account-failure.input" || fail 'account creation could not be retried'
        ;;
    delete-retried-account)
        Del_User <<< 'e2e-failed-user' || fail 'retried account cleanup failed'
        ;;
    firewall)
        printf 'net.ipv4.ip_forward=0\n' > /etc/sysctl.conf || exit 1
        iptables -P FORWARD DROP || exit 1
        # These administrator-owned rules must survive the full uninstall.
        iptables -A INPUT -p tcp --dport 4444 -m comment --comment unrelated-input -j ACCEPT || exit 1
        iptables -A FORWARD -i vpns+ -s 203.0.113.0/24 -o ve -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
            -m comment --comment unrelated-forward -j ACCEPT || exit 1
        iptables -A FORWARD -i ve -o vpns+ -d 203.0.113.0/24 -m conntrack --ctstate ESTABLISHED,RELATED \
            -m comment --comment unrelated-return -j ACCEPT || exit 1
        iptables -t nat -A POSTROUTING -s 203.0.113.0/24 -o ve \
            -m comment --comment unrelated-nat -j MASQUERADE || exit 1
        iptables-save > "$state_dir/firewall-before-vpn.rules" || exit 1
        Set_iptables || fail 'firewall configuration failed'
        Set_iptables || fail 'repeated firewall configuration failed'
        Add_iptables 4443 4443 || fail 'service port rules failed'
        [[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail 'IPv4 forwarding stayed disabled'
        # Reload the saved setting after resetting runtime state, as a reboot
        # would. A runtime-only sysctl change cannot satisfy this assertion.
        sysctl -w net.ipv4.ip_forward=0 || exit 1
        sysctl -p /etc/sysctl.conf || fail 'persistent forwarding settings did not load'
        [[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail 'IPv4 forwarding was not persisted'
        ;;
    toggle)
        Modify_User_disabled <<< 'e2e-susp-user' || fail 'account toggle failed'
        ;;
    delete)
        Del_User <<< 'e2e-susp-user' || fail 'account deletion failed'
        ;;
    delete-failed-crl|toggle-failed-crl)
        before="$(sha256sum "$CRL_PEM")" || exit 1
        rm -f "$state_dir/crl-failure-injected" || exit 1
        # Exercise a failed CRL update without changing the running server or
        # bypassing the installer's real deletion and retry paths.
        certtool() {
            if [[ "${1:-}" == --generate-crl ]]; then
                touch "$state_dir/crl-failure-injected" || return 1
                echo 'Injected CRL generation failure' >&2
                return 73
            fi
            command certtool "$@"
        }
        operation=Del_User
        [[ "$action" != toggle-failed-crl ]] || operation=Modify_User_disabled
        if "$operation" <<< 'e2e-susp-user'; then
            fail 'account operation concealed a CRL generation failure'
        fi
        [[ -f "$state_dir/crl-failure-injected" ]] || fail 'account operation failed before CRL generation'
        [[ "$before" == "$(sha256sum "$CRL_PEM")" ]] ||
            fail 'failed CRL generation replaced the live CRL'
        pending_status="$(List_User | grep -F 'e2e-susp-user')" || fail 'incomplete account operation disappeared from the user list'
        grep -Eq 'Pending|未完成' <<< "$pending_status" || fail 'incomplete account operation was shown as complete'
        ;;
    restore-failed-reload)
        Find_Suspended_User e2e-susp-user >/dev/null || fail 'restore fixture is not suspended'
        restore_pid="$(Get_Ocserv_PID)" || fail 'restore fixture has no running server'
        rm -f "$state_dir/restore-reload-failure.crl" "$state_dir/rollback-reload-failure.crl" || exit 1
        kill() {
            if [[ "$#" -eq 2 && "${1:-}" == -HUP && "${2:-}" == "$restore_pid" ]]; then
                # Both CRLs were genuinely generated and published. Fail only
                # their reload signal, including the rollback's reload attempt.
                if [[ ! -f "$state_dir/restore-reload-failure.crl" ]]; then
                    cp "$CRL_PEM" "$state_dir/restore-reload-failure.crl" || return 1
                elif [[ ! -f "$state_dir/rollback-reload-failure.crl" ]]; then
                    cp "$CRL_PEM" "$state_dir/rollback-reload-failure.crl" || return 1
                fi
                echo 'Injected published-CRL reload failure' >&2
                return 76
            fi
            builtin kill "$@"
        }
        if Modify_User_disabled <<< 'e2e-susp-user'; then
            fail 'restore concealed a published-CRL reload failure'
        fi
        [[ -s "$state_dir/restore-reload-failure.crl" && -s "$state_dir/rollback-reload-failure.crl" ]] ||
            fail 'restore did not reach both published-CRL reload failures'
        builtin kill -0 "$restore_pid" || fail 'server died during restore failure injection'
        openssl verify -CAfile "$CA_CERT" -CRLfile "$state_dir/restore-reload-failure.crl" \
            -crl_check -purpose sslclient "$state_dir/client.cer" > "$state_dir/restore-crl-verify.log" 2>&1 ||
            fail 'first reload failure did not follow publication of a genuinely restoring CRL'
        if openssl verify -CAfile "$CA_CERT" -CRLfile "$state_dir/rollback-reload-failure.crl" \
            -crl_check -purpose sslclient "$state_dir/client.cer" > "$state_dir/rollback-crl-verify.log" 2>&1; then
            fail 'rollback did not publish a genuinely revoking CRL'
        fi
        grep -Eq 'error 23 |certificate revoked' "$state_dir/rollback-crl-verify.log" ||
            fail 'rollback certificate rejection was not caused by revocation'
        pending_status="$(List_User | grep -F 'e2e-susp-user')" || fail 'failed restore rollback disappeared from the user list'
        grep -Eq 'Pending|未完成' <<< "$pending_status" || fail 'failed restore rollback was shown as complete'
        ;;
    pending-delete-guards)
        before="$(sha256sum "$passwd_file" "$CRL_PEM")" || exit 1
        certificate_before=''
        if [[ -f "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer" ]]; then
            certificate_before="$(sha256sum "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")" || exit 1
        fi
        if Add_User < "$state_dir/account.input"; then
            fail 'replacement account was created before pending deletion finished'
        fi
        [[ "$before" == "$(sha256sum "$passwd_file" "$CRL_PEM")" ]] || fail 'denied replacement changed password or revocation state'
        certificate_after=''
        if [[ -f "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer" ]]; then
            certificate_after="$(sha256sum "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")" || exit 1
        fi
        [[ "$certificate_before" == "$certificate_after" ]] || fail 'denied replacement changed the active certificate'
        ;;
    toggle-failed-disconnect)
        rm -f "$state_dir/disconnect-failure-injected" || exit 1
        occtl() {
            case " $* " in
                *' terminate user '*)
                    touch "$state_dir/disconnect-failure-injected" || return 1
                    echo 'Injected occtl termination failure' >&2
                    return 74 ;;
                *' show users '*|*' show sessions valid '*) return 74 ;;
                *) command occtl "$@" ;;
            esac
        }
        if Modify_User_disabled <<< 'e2e-susp-user'; then
            fail 'account disable concealed a session termination failure'
        fi
        [[ -f "$state_dir/disconnect-failure-injected" ]] || fail 'disable failed before session termination'
        Find_Suspended_User e2e-susp-user >/dev/null || fail 'termination failure did not exercise an archived certificate'
        pending_status="$(List_User | grep -F 'e2e-susp-user')" || fail 'incomplete disable disappeared from the user list'
        grep -Eq 'Pending|未完成' <<< "$pending_status" || fail 'incomplete disable was shown as complete'
        ;;
    legacy-revocation)
        before="$(sha256sum "$passwd_file" "$CRL_PEM" "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")" || exit 1
        occtl() {
            case " $* " in
                *' help '*) touch "$state_dir/legacy-help-injected" || return 1; printf '  disconnect user [NAME]\n' ;;
                *) echo 'Unexpected mutation with legacy occtl capabilities' >&2; return 75 ;;
            esac
        }
        rm -f "$state_dir/legacy-help-injected" || exit 1
        if Modify_User_disabled <<< 'e2e-susp-user'; then
            fail 'legacy server reported complete account disable'
        fi
        [[ -f "$state_dir/legacy-help-injected" ]] || fail 'legacy disable failed before checking server capabilities'
        rm -f "$state_dir/legacy-help-injected" || exit 1
        if Del_User <<< 'e2e-susp-user'; then
            fail 'legacy server reported complete account deletion'
        fi
        [[ -f "$state_dir/legacy-help-injected" ]] || fail 'legacy deletion failed before checking server capabilities'
        [[ "$before" == "$(sha256sum "$passwd_file" "$CRL_PEM" "$USERS_DIR/e2e-susp-user/e2e-susp-user.cer")" ]] ||
            fail 'unsupported session revocation mutated credentials'
        ;;
    uninstall)
        cp "$conf" "$state_dir/uninstall.conf" || exit 1
        # Cleanup must discover the installed egress even after the default route disappears.
        ip route del default || exit 1
        Uninstall_ocserv <<< 'y' || fail 'full uninstall failed'
        [[ ! -e "$file" && ! -e "$conf_file" ]] || fail 'uninstall left the server or configuration installed'
        normalize_rules() {
            sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]/[0:0]/g' "$1"
        }
        normalize_rules "$state_dir/firewall-before-vpn.rules" > "$state_dir/firewall-expected.rules" || exit 1
        iptables-save > "$state_dir/firewall-after-uninstall.rules" || exit 1
        normalize_rules "$state_dir/firewall-after-uninstall.rules" > "$state_dir/firewall-actual.rules" || exit 1
        cmp -s "$state_dir/firewall-expected.rules" "$state_dir/firewall-actual.rules" ||
            fail 'uninstall left VPN rules or changed unrelated firewall rules'
        # Repeating cleanup with the saved configuration must accept absent rules.
        conf="$state_dir/uninstall.conf"
        Remove_VPN_Forwarding_Rules || fail 'repeated forwarding cleanup failed'
        Del_iptables 4443 4443 || fail 'repeated port cleanup failed'
        iptables-save > "$state_dir/firewall-after-repeat.rules" || exit 1
        normalize_rules "$state_dir/firewall-after-repeat.rules" > "$state_dir/firewall-actual.rules" || exit 1
        cmp -s "$state_dir/firewall-expected.rules" "$state_dir/firewall-actual.rules" ||
            fail 'repeated cleanup changed unrelated firewall rules'
        iptables-restore < /etc/iptables.up.rules || fail 'saved uninstall firewall could not be restored'
        iptables-save > "$state_dir/firewall-after-restore.rules" || exit 1
        normalize_rules "$state_dir/firewall-after-restore.rules" > "$state_dir/firewall-actual.rules" || exit 1
        cmp -s "$state_dir/firewall-expected.rules" "$state_dir/firewall-actual.rules" ||
            fail 'saved firewall restored VPN rules or lost unrelated rules'
        ;;
    *) fail "unknown action: $action" ;;
esac
