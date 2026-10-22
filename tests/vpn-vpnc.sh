#!/usr/bin/env bash
# Observe negotiated settings, then let the distro's real vpnc-script apply them.
set -euo pipefail

: "${VPNC_REAL_SCRIPT:?}" "${VPNC_STATE_DIR:?}"
# Keep OpenConnect's private cookie stdout separate from routing diagnostics.
# Older distro scripts key saved routes by PPID. Sourcing in a subshell preserves
# OpenConnect as that parent across callbacks, while containing the script's exit
# and shell state. Match the stock script's normal non-strict shell options.
(
    set +e
    set +u
    set +o pipefail
    # shellcheck disable=SC1090
    source "$VPNC_REAL_SCRIPT"
) >&2
case "${reason:-}" in
    connect|reconnect)
        printf '%s\n' "${INTERNAL_IP4_ADDRESS:-}" > "$VPNC_STATE_DIR/address"
        printf '%s\n' "${INTERNAL_IP4_DNS:-}" > "$VPNC_STATE_DIR/dns"
        printf '%s\n' "${TUNDEV:-}" > "$VPNC_STATE_DIR/device"
        printf '%s\n' "${INTERNAL_IP6_ADDRESS:-}" > "$VPNC_STATE_DIR/address6"
        printf '%s\n' "${INTERNAL_IP6_DNS:-}" > "$VPNC_STATE_DIR/dns6"
        # Allowlisted routing evidence only; never dump the full environment,
        # CSTP options, session cookie or credentials into diagnostic artifacts.
        {
            printf 'Routing callback: %s\n' "$reason"
            for key in ${!CISCO_IPV6_SPLIT_@}; do
                printf '%s=%s\n' "$key" "${!key}"
            done
            ip -6 route show
        } >&2
        touch "$VPNC_STATE_DIR/connected"
        ;;
    disconnect)
        rm -f "$VPNC_STATE_DIR/connected"
        ;;
esac
