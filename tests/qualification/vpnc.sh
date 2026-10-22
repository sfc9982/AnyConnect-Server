#!/usr/bin/env bash
set -euo pipefail
: "${VPNC_REAL_SCRIPT:?}" "${VPNC_STATE_DIR:?}"
(
    set +e +u
    set +o pipefail
    # shellcheck disable=SC1090
    source "$VPNC_REAL_SCRIPT"
) >&2
case "${reason:-}" in
    connect|reconnect)
        printf '%s\n' "${INTERNAL_IP4_ADDRESS:-}" > "$VPNC_STATE_DIR/ipv4"
        printf '%s\n' "${INTERNAL_IP6_ADDRESS:-}" > "$VPNC_STATE_DIR/ipv6"
        printf '%s\n' "${INTERNAL_IP6_DNS:-}" > "$VPNC_STATE_DIR/dns6"
        touch "$VPNC_STATE_DIR/connected"
        ;;
    disconnect) rm -f "$VPNC_STATE_DIR/connected" ;;
esac
