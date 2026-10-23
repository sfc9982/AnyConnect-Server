#!/usr/bin/env bash
# Sourced by network.sh: keep client negotiation and failure evidence together.
# shellcheck disable=SC2034,SC2154
connect() {
    local n=$1 outer=$2 transport=$3 label=$4 ns address i
    probe_transport=$transport
    ns=q-c$n-$$
    address=198.18.0.2; [[ "$outer" != 6 ]] || address=2001:db8:1::2
    printf '%s vpn-qualification.test\n' "$address" > "/etc/netns/$ns/hosts"
    mkdir -p "$state/client-$n"
    rm -f "$state/client-$n/connected"
    local -a args=(--verbose --protocol=anyconnect --non-inter --no-proxy --no-system-trust
        --cafile /etc/ocserv/ssl/ca-cert.pem --user "qual-$n" --passwd-on-stdin
        --interface vpntest --reconnect-timeout 5
        --script "exec bash $repo/tests/qualification/vpnc.sh")
    [[ "$transport" != tls ]] || args+=(--no-dtls)
    # Parse the actual argument vector without connecting. Unsupported client
    # options are setup errors, never an expected policy/authentication failure.
    # --passwd-on-stdin is processed during option parsing, before --version.
    # Supply a dummy line for that parse-only run, never the account password.
    openconnect "${args[@]}" --version <<< qualification-argument-check > /dev/null 2> "$state/$label-cli.log" ||
        fail "$label unsupported OpenConnect arguments"
    # Without --printcookie, OpenConnect writes INFO (including DTLS success)
    # to stdout and errors to stderr. Capture both in the private log.
    ip netns exec "$ns" env VPNC_STATE_DIR="$state/client-$n" openconnect "${args[@]}" \
        https://vpn-qualification.test:4443/ < "$state/password-$n" > "$state/$label-$n.log" 2>&1 &
    client_pids+=("$!")
    for ((i=0;i<200;i++)); do
        [[ -f "$state/client-$n/connected" ]] && break
        kill -0 "${client_pids[-1]}" || fail "$label client exited"
        sleep .1
    done
    [[ -f "$state/client-$n/connected" ]] || fail "$label tunnel timed out"
    ip -n "$ns" route get 198.51.100.2 | grep -q 'dev vpntest' || fail 'IPv4 bypass'
    ip -n "$ns" -6 route get 2001:db8:2::2 | grep -q 'dev vpntest' || fail 'IPv6 bypass'
    ip -n "$ns" -6 addr show dev vpntest | grep -q 'fd42:7:' || fail 'missing IPv6 lease'
    if [[ "$transport" == dtls ]]; then
        for ((i=0;i<100;i++)); do grep -q 'Established DTLS connection' "$state/$label-$n.log" && break; sleep .1; done
        grep -q 'Established DTLS connection' "$state/$label-$n.log" ||
            fail "$label: DTLS not established before deadline"
    fi
}
