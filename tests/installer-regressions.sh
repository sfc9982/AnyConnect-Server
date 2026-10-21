#!/usr/bin/env bash
# Fault-inject installer orchestration and service helpers without host services or /etc writes.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/ocserv-installer-test.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_failure() {
    if "$@" > "$case_dir/output.log" 2>&1; then
        fail "$installer: unexpectedly succeeded: $*"
    fi
}
expect_status() {
    local expected="$1" observed=0
    shift
    "$@" > "$case_dir/output.log" 2>&1 || observed=$?
    if [[ "$observed" -ne "$expected" ]]; then
        cat "$case_dir/output.log" >&2
        fail "$installer: $* returned $observed, expected $expected"
    fi
}
fixture() {
    case_dir="$test_root/$installer/$1"
    mkdir -p "$case_dir/units" "$case_dir/tmp"
    file="$case_dir/ocserv"
    conf_file="$case_dir/etc-ocserv"
    conf="$conf_file/ocserv.conf"
    passwd_file="$conf_file/ocpasswd"
    SSL_DIR="$conf_file/ssl"
    USERS_DIR="$SSL_DIR/users"
    DISABLED_DIR="$SSL_DIR/disabled"
    CA_CERT="$SSL_DIR/ca-cert.pem"
    CA_KEY="$SSL_DIR/ca-key.pem"
    CRL_PEM="$SSL_DIR/crl.pem"
    CRL_TMPL="$SSL_DIR/crl.tmpl"
    REVOKED_PEM="$SSL_DIR/revoked.pem"
    SUSPENDED_PEM="$SSL_DIR/suspended.pem"
    PID_FILE="$case_dir/default.pid"
    SYSTEMD_UNIT_DIR="$case_dir/units"
    TMPDIR="$case_dir/tmp"
    trace="$case_dir/trace"
    running="$case_dir/running"
    failure=""
    fail_unit_write=0
    : > "$trace"
}
record() {
    printf '%s\n' "$1" >> "$trace"
    [[ "$failure" != "$1" ]] || return 77
}
write_config() {
    mkdir -p "$conf_file"
    printf '%s\n' "pid-file = $case_dir/custom.pid" \
        'tcp-port = 443' 'udp-port = 443' \
        'max-same-clients = 2' 'max-clients = 16' > "$conf"
}

run_installer_cases() (
    local installer="$1" phase before
    # shellcheck disable=SC1090
    source "$repo_dir/$installer"
    check_root() { return 0; }
    have_systemd() { return 0; }
    sleep() { :; }
    Installation_dependency() { record dependencies; }
    Download_ocserv() {
        record download || return $?
        write_config || return 1
        printf '#!/bin/sh\nexit 0\n' > "$file" || return 1
        chmod +x "$file" || return 1
        [[ "$failure" != partial-download ]] || return 78
    }
    Generate_SSL() {
        record ssl || return $?
        mkdir -p "$SSL_DIR" || return 1
        local name
        for name in ca-cert.pem ca-key.pem server-cert.pem server-key.pem; do
            printf 'test material %s %s\n' "$BASHPID" "$name" > "$SSL_DIR/$name" || return 1
        done
    }
    Ensure_CRL() {
        record crl || return $?
        mkdir -p "$USERS_DIR" "$DISABLED_DIR"
        printf 'test CRL\n' > "$CRL_PEM"
    }
    Configure_Auth() { record auth; }
    Add_User() {
        record account || return $?
        mkdir -p "$USERS_DIR/test-user" || return 1
        printf 'test-user:*:test-placeholder\n' > "$passwd_file" || return 1
        local name
        for name in test-user.cer test-user-key.pem test-user.p12; do
            printf 'test account %s %s\n' "$BASHPID" "$name" > "$USERS_DIR/test-user/$name" || return 1
        done
    }
    pw_user_exists() { [[ "$1" == test-user && -s "$passwd_file" ]]; }
    Set_tcp_port() { record tcp-port || return $?; set_tcp_port=4443; }
    Set_udp_port() { record udp-port || return $?; set_udp_port=4444; }
    Set_iptables() { record firewall; }
    Add_iptables() {
        record ports-firewall || return $?
        [[ "$1" == 4443 && "$2" == 4444 ]]
    }
    Save_iptables() { record save-firewall; }
    Get_Ocserv_PID() {
        [[ -f "$running" ]] || return 1
        printf '12345\n'
    }
    View_Config() { record view; }
    cat() {
        [[ "$fail_unit_write" != 1 || "$#" -ne 0 ]] || return 69
        command cat "$@"
    }
    install() {
        if [[ "$failure" == publish-server-cert && "${*: -1}" == "$SSL_DIR/server-cert.pem.install."* ]]; then
            printf 'partial write\n' > "${*: -1}"
            return 74
        fi
        command install "$@"
    }
    systemctl() {
        record "systemctl $*" || {
            # A failed start/restart must remain an error even if a PID appears.
            case "$1" in start|restart) : > "$running" ;; esac
            return 73
        }
        case "$1" in
            start)
                [[ ! -e "/proc/$BASHPID/fd/9" ]] || return 90
                : > "$running"
                ;;
            restart) : > "$running" ;;
            stop) rm -f "$running" ;;
            is-active) [[ -f "$running" ]] || return 3 ;;
        esac
        return 0
    }

    fixture successful
    expect_status 0 Install_ocserv
    [[ ! -e "$conf_file/.install-state" && -s "$passwd_file" && -s "$CA_CERT" ]] ||
        fail "$installer: successful install did not finalize"
    grep -Fx "PIDFile=$case_dir/custom.pid" "$SYSTEMD_UNIT_DIR/ocserv.service" >/dev/null ||
        fail "$installer: service ignored configured PID path"
    [[ "$(tail -n 2 "$trace")" == $'systemctl start ocserv\nview' ]] ||
        fail "$installer: normal install did not reach actual startup helper"

    for phase in dependencies download partial-download ssl crl auth account tcp-port udp-port firewall ports-firewall save-firewall; do
        fixture "failure-$phase"
        failure="$phase"
        expect_failure Install_ocserv
        ! grep -Fx 'systemctl start ocserv' "$trace" >/dev/null ||
            fail "$installer: install continued past failed $phase"
        [[ -d "$conf_file/.install-state" ]] ||
            fail "$installer: failed install lost resume state"
    done

    fixture resume-after-publish
    failure=partial-download
    expect_failure Install_ocserv
    [[ -x "$file" ]] || fail "$installer: partial publication fixture did not run"
    failure=""
    expect_status 0 Install_ocserv
    [[ "$(grep -Fxc download "$trace")" == 2 ]] ||
        fail "$installer: partial binary publication blocked rebuilding"

    fixture resume-after-account
    failure=udp-port
    expect_failure Install_ocserv
    before="$(sha256sum "$CA_CERT" "$CA_KEY" "$passwd_file" "$USERS_DIR/test-user/test-user.p12")"
    failure=""
    expect_status 0 Install_ocserv
    [[ "$before" == "$(sha256sum "$CA_CERT" "$CA_KEY" "$passwd_file" "$USERS_DIR/test-user/test-user.p12")" ]] ||
        fail "$installer: retry changed CA or account material"
    [[ "$(grep -Fxc ssl "$trace")" == 1 && "$(grep -Fxc account "$trace")" == 1 ]] ||
        fail "$installer: retry repeated credential generation"

    fixture resume-after-pki
    failure=crl
    expect_failure Install_ocserv
    before="$(sha256sum "$CA_CERT" "$CA_KEY")"
    failure=""
    expect_status 0 Install_ocserv
    [[ "$before" == "$(sha256sum "$CA_CERT" "$CA_KEY")" ]] ||
        fail "$installer: later failure caused CA replacement"

    fixture resume-partial-pki-publication
    failure=publish-server-cert
    expect_failure Install_ocserv
    [[ -s "$CA_CERT" && -s "$CA_KEY" && ! -e "$SSL_DIR/server-cert.pem" ]] ||
        fail "$installer: partial certificate publication fixture did not run"
    before="$(sha256sum "$CA_CERT" "$CA_KEY")"
    failure=""
    expect_status 0 Install_ocserv
    [[ "$before" == "$(sha256sum "$CA_CERT" "$CA_KEY")" && "$(grep -Fxc ssl "$trace")" == 1 ]] ||
        fail "$installer: partial publication retry generated a different CA"

    fixture start-failure
    failure='systemctl start ocserv'
    expect_status 73 Install_ocserv
    ! grep -Fx view "$trace" >/dev/null || fail "$installer: failed start printed success"
    before="$(sha256sum "$CA_CERT" "$passwd_file")"
    failure=""
    expect_status 0 Install_ocserv
    [[ "$before" == "$(sha256sum "$CA_CERT" "$passwd_file")" ]] ||
        fail "$installer: retry after failed startup replaced credentials"

    fixture existing
    write_config
    printf 'existing binary\n' > "$file"
    mkdir -p "$SSL_DIR"
    printf 'existing CA\n' > "$CA_CERT"
    printf 'existing account\n' > "$passwd_file"
    before="$(sha256sum "$file" "$conf" "$CA_CERT" "$passwd_file")"
    expect_failure Install_ocserv
    [[ ! -s "$trace" && "$before" == "$(sha256sum "$file" "$conf" "$CA_CERT" "$passwd_file")" ]] ||
        fail "$installer: existing installation was modified"

    for phase in 'systemctl daemon-reload' 'systemctl enable ocserv'; do
        fixture "service-${phase// /-}"
        failure="$phase"
        expect_failure Install_ocserv
        ! grep -Fx ssl "$trace" >/dev/null || fail "$installer: service setup failure was ignored"
    done
    for phase in Service_ocserv Firewall_Service_ocserv; do
        fixture "unit-write-$phase"
        write_config
        printf 'original unit\n' > "$SYSTEMD_UNIT_DIR/ocserv.service"
        printf 'original firewall unit\n' > "$SYSTEMD_UNIT_DIR/ocserv-firewall.service"
        before="$(sha256sum "$SYSTEMD_UNIT_DIR/"*.service)"
        fail_unit_write=1
        expect_failure "$phase"
        [[ "$before" == "$(sha256sum "$SYSTEMD_UNIT_DIR/"*.service)" && ! -s "$trace" ]] ||
            fail "$installer: failed unit write replaced a unit or called systemctl"
    done
    fixture firewall-service-failure
    write_config
    failure='systemctl daemon-reload'
    expect_status 73 Firewall_Service_ocserv
    failure='systemctl enable ocserv-firewall'
    expect_status 73 Firewall_Service_ocserv

    fixture service-command-failures
    write_config
    printf '#!/bin/sh\nexit 0\n' > "$file"
    chmod +x "$file"
    failure='systemctl start ocserv'
    expect_status 73 Start_ocserv
    failure='systemctl restart ocserv'
    expect_status 73 Restart_ocserv
    failure='systemctl stop ocserv'
    expect_status 73 Stop_ocserv
    failure=""
    expect_status 0 Stop_ocserv
    [[ ! -e "$running" ]] || fail "$installer: successful stop left the daemon marked running"

    # The direct-daemon branch must propagate its executable's actual failure too.
    fixture daemon-command-failure
    write_config
    printf '#!/bin/sh\nexit 61\n' > "$file"
    chmod +x "$file"
    have_systemd() { return 1; }
    expect_status 61 Start_ocserv
    expect_status 61 Restart_ocserv
    printf '%s: installer sequencing, recovery and service failures passed\n' "$installer"
)

run_download_cases() (
    local installer="$1" original_dir
    # shellcheck disable=SC1090
    source "$repo_dir/$installer"
    wget() {
        [[ "$1" == -O ]] || return 91
        case "$3" in
            */ocserv.conf)
                record config-download || return $?
                printf 'tcp-port = 443\n' > "$2"
                ;;
            */ocserv-*.tar.xz)
                record source-download || return $?
                printf 'test source archive\n' > "$2"
                ;;
            *) return 92 ;;
        esac
    }
    tar() {
        record unpack || return $?
        mkdir -p "$4/ocserv-$ocserv_ver"
    }
    meson() { record configure-build; }
    ninja() {
        if [[ "${3:-}" == install ]]; then
            record publish-binary || return $?
            printf '#!/bin/sh\nexit 0\n' > "$file"
            chmod +x "$file"
        else
            record compile
        fi
    }
    fixture download-config-failure
    failure=config-download
    expect_failure Download_ocserv
    [[ ! -e "$file" ]] && ! grep -Fx publish-binary "$trace" >/dev/null ||
        fail "$installer: published binary before obtaining configuration"

    fixture download-success
    original_dir="$PWD"
    expect_status 0 Download_ocserv
    [[ "$PWD" == "$original_dir" && -x "$file" && -s "$conf" ]] ||
        fail "$installer: source installer failed or changed caller directory"
    [[ "$(head -n 1 "$trace")" == config-download ]] ||
        fail "$installer: configuration was not fetched first"
    printf '# preserve on retry\n' >> "$conf"
    expect_status 0 Download_ocserv
    grep -Fx '# preserve on retry' "$conf" >/dev/null ||
        fail "$installer: source retry replaced existing configuration"
    printf '%s: download publication order and configuration preservation passed\n' "$installer"
)

run_pid_cases() (
    local installer="$1" live_child="" other_child="" actual
    # shellcheck disable=SC1090
    source "$repo_dir/$installer"
    fixture pid-lookup
    write_config
    [[ "$(Configured_PID_File)" == "$case_dir/custom.pid" ]] ||
        fail "$installer: configured PID path was ignored"
    printf '1\n2\n' > "$case_dir/custom.pid"
    expect_status 2 Get_Ocserv_PID
    : > "$case_dir/custom.pid"
    expect_status 2 Get_Ocserv_PID
    printf '2147483647\n' > "$case_dir/custom.pid"
    expect_status 1 Get_Ocserv_PID
    expect_status 0 check_pid
    [[ -z "$PID" ]] || fail "$installer: stale PID remained set"
    rm "$case_dir/custom.pid"
    expect_status 1 Get_Ocserv_PID
    mkdir "$case_dir/custom.pid"
    expect_status 2 Get_Ocserv_PID
    rmdir "$case_dir/custom.pid"
    printf 'pid-file = relative.pid\n' > "$conf"
    expect_status 2 Get_Ocserv_PID
    printf 'tcp-port = 443\n' > "$conf"
    [[ "$(Configured_PID_File)" == "$PID_FILE" ]] || fail "$installer: default PID fallback failed"
    rm "$conf"
    expect_status 2 Get_Ocserv_PID
    write_config
    # Some remote executors expose a host /proc to a different PID namespace.
    # CI must always exercise the real process identity checks below.
    if ! readlink "/proc/$BASHPID/exe" >/dev/null 2>&1; then
        [[ "${CI:-}" != true ]] || fail "$installer: CI cannot inspect its own process namespace"
        printf '%s: PID configuration/error checks passed; live identity checks unavailable in this local /proc namespace\n' "$installer"
        return 0
    fi
    # Temporary child executables test identity matching without running a VPN or signaling host services.
    cp "$(command -v sleep)" "$file"
    "$file" 300 &
    live_child=$!
    sleep 300 &
    other_child=$!
    trap 'kill "$live_child" "$other_child" 2>/dev/null || true; wait "$live_child" "$other_child" 2>/dev/null || true' EXIT
    printf '%s\n' "$other_child" > "$PID_FILE"
    printf '%s\n' "$live_child" > "$case_dir/custom.pid"
    actual="$(Get_Ocserv_PID)" || fail "$installer: configured PID lookup failed"
    [[ "$actual" == "$live_child" ]] || fail "$installer: default PID overrode configured PID"
    check_pid || fail "$installer: valid PID failed check_pid"
    [[ "$PID" == "$live_child" ]] || fail "$installer: check_pid returned the wrong process"

    printf '%s\n' "$other_child" > "$case_dir/custom.pid"
    expect_status 2 Get_Ocserv_PID
    printf 'tcp-port = 443\n' > "$conf"
    printf '%s\n' "$live_child" > "$PID_FILE"
    [[ "$(Get_Ocserv_PID)" == "$live_child" ]] || fail "$installer: default PID fallback failed"
    printf '%s: configured, stale, invalid and unrelated PID checks passed\n' "$installer"
)

for installer in ocserv.sh ocserv-en.sh; do
    run_installer_cases "$installer"
    run_download_cases "$installer"
    run_pid_cases "$installer"
done
printf 'Installer regression checks passed for both languages.\n'
