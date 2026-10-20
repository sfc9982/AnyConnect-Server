#!/usr/bin/env bash
# Observe negotiated settings, then let the distro's real vpnc-script apply them.
set -euo pipefail

: "${VPNC_REAL_SCRIPT:?}" "${VPNC_STATE_DIR:?}"
"$VPNC_REAL_SCRIPT"
case "${reason:-}" in
    connect|reconnect)
        printf '%s\n' "${INTERNAL_IP4_ADDRESS:-}" > "$VPNC_STATE_DIR/address"
        printf '%s\n' "${INTERNAL_IP4_DNS:-}" > "$VPNC_STATE_DIR/dns"
        printf '%s\n' "${TUNDEV:-}" > "$VPNC_STATE_DIR/device"
        touch "$VPNC_STATE_DIR/connected"
        ;;
    disconnect)
        rm -f "$VPNC_STATE_DIR/connected"
        ;;
esac
