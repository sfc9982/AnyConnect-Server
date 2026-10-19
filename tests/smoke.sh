#!/usr/bin/env bash
set -euo pipefail

expected_pm="${1:?Usage: bash tests/smoke.sh <expected-package-manager>}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

# Load only the helpers under test, without executing the interactive installer.
# Both name(){ and name() { occur in the production scripts.
load_function() {
    local script="$1" name="$2" target="$3"
    if ! awk -v name="$name" '
        $0 ~ "^" name "[[:space:]]*\\(\\)[[:space:]]*\\{" { found = 1 }
        found { print }
        found && /^}/ { exit }
        END { if (!found) exit 1 }
    ' "$script" > "$target"; then
        echo "$script: could not extract $name" >&2
        return 1
    fi
    # shellcheck disable=SC1090
    source "$target"
    declare -F "$name" > /dev/null
}

check_script() (
    local script="$1" menu_text="$2"
    local work_dir="$test_dir/$script"
    mkdir -p "$work_dir"
    echo "::group::$script"

    bash -n "$script"
    for name in check_sys Set_Conf_Value sanitize_username; do
        load_function "$script" "$name" "$work_dir/$name.sh"
    done

    check_sys
    echo "detected release=${release} pm=${pm} (expect $expected_pm)"
    test -n "$release"
    test "$pm" = "$expected_pm"

    conf="$work_dir/ocserv.conf"
    printf 'tcp-port = 443\ndns = 8.8.8.8\n' > "$conf"
    Set_Conf_Value tcp-port 8443
    Set_Conf_Value udp-port 8443
    Set_Conf_Value crl /etc/ocserv/ssl/crl.pem
    grep -Fxq 'tcp-port = 8443' "$conf"
    grep -Fxq 'udp-port = 8443' "$conf"
    grep -Fxq 'dns = 8.8.8.8' "$conf"
    grep -Fxq 'crl = /etc/ocserv/ssl/crl.pem' "$conf"

    sanitize_username alice-1
    sanitize_username alice_1
    for username in 'a/b' '.' '..' ''; do
        if sanitize_username "$username"; then
            echo "$script: accepted invalid username '$username'" >&2
            exit 1
        fi
    done

    # Blank input exercises the menu without selecting an installation action.
    # Preserve the exit status: printing a banner must not hide a crash or timeout.
    if printf '\n' | timeout 15 bash "$script" > "$work_dir/menu.out" 2>&1; then
        if ! grep -Fq "$menu_text" "$work_dir/menu.out"; then
            cat "$work_dir/menu.out"
            echo "$script: expected menu text was not printed" >&2
            exit 1
        fi
    else
        status=$?
        cat "$work_dir/menu.out"
        echo "$script: menu exited with status $status" >&2
        exit "$status"
    fi

    echo "$script: syntax, distro detection, config helpers, and menu passed"
    echo "::endgroup::"
)

check_script ocserv.sh '一键安装管理脚本'
check_script ocserv-en.sh 'install and conf script'
