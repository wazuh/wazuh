#!/bin/bash
# Runs every check the load-balancer spike needs and reports PASS/FAIL against the documented
# expected outcome. One command, so a regression is obvious.
#
# Each group maps to a requirement from the spike issue, named in the group header.
#
# Prerequisites (see README.md section 5):
#   * node 1 on the host with wazuh-db + analysisd + remoted, port 1517, lab certificate installed
#   * node 2 built with ./add_second_manager.sh, port 1518 (remoted only -> answers 503)
#   * ./generate_test_certificates.sh already run
#
# Usage: ./run_issue_checks.sh [--python /path/to/python3]

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/send_signed_request.py"
CERTS="$HERE/certs"
PYTHON=python3
NODE1=https://127.0.0.1:1517
NODE2=https://127.0.0.1:1518
TERM=https://127.0.0.1:8443       # termination, layer 7
PASS_URL=https://127.0.0.1:8444   # passthrough, layer 4

[[ "${1:-}" == "--python" ]] && { PYTHON="$2"; shift 2; }

PASSED=0
FAILED=0
SKIPPED=0
FAILURES=()

# --------------------------------------------------------------------------------- helpers

# Prints the status code(s) of a probe run, comma-separated. TLS-level failures print TLS_ERROR.
status() {
    "$PYTHON" "$PROBE" --json "$@" 2>/dev/null | "$PYTHON" -c '
import json, sys
codes = []
for line in sys.stdin:
    line = line.strip()
    if line:
        value = json.loads(line)["status"]
        codes.append(str(value) if value is not None else "TLS_ERROR")
print(",".join(codes) if codes else "NO_OUTPUT")
'
}

# Prints a count summary of a repeated run, e.g. "3x202 3x503", sorted so it is comparable.
summary() {
    status "$@" | "$PYTHON" -c '
import sys
from collections import Counter
codes = sys.stdin.read().strip().split(",")
print(" ".join(f"{n}x{c}" for c, n in sorted(Counter(codes).items())))
'
}

check() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        printf '  \033[32mPASS\033[0m  %-52s %s\n' "$label" "$actual"
        PASSED=$((PASSED + 1))
    else
        printf '  \033[31mFAIL\033[0m  %-52s got %s, expected %s\n' "$label" "$actual" "$expected"
        FAILED=$((FAILED + 1))
        FAILURES+=("$label (got $actual, expected $expected)")
    fi
}

note() { printf '  \033[33mNOTE\033[0m  %s\n' "$1"; SKIPPED=$((SKIPPED + 1)); }

# A check that is EXPECTED to fail because of a known bug. Reported loudly, but it does not make
# the suite red -- otherwise the suite would never be green and people would stop reading it.
# If it ever starts passing, that is reported too: it means the bug got fixed.
XFAILED=0
UNEXPECTED_PASS=()
xfail() {
    local label="$1" broken="$2" actual="$3" would_be="$4"
    if [[ "$actual" == "$broken" ]]; then
        printf '  \033[35mXFAIL\033[0m %-52s %s  (known bug)\n' "$label" "$actual"
        XFAILED=$((XFAILED + 1))
    else
        printf '  \033[36mFIXED?\033[0m %-52s got %s -- expected the bug (%s)\n' \
               "$label" "$actual" "$broken"
        UNEXPECTED_PASS+=("$label now returns $actual; the known bug may be fixed")
    fi
}
group() { printf '\n\033[1m%s\033[0m\n' "$1"; }

use_config() { "$HERE/start_load_balancer.sh" "$1" "${2:-8443}" >/dev/null 2>&1; }
use_mode()   { "$HERE/set_manager_verification_mode.sh" "$1" >/dev/null 2>&1; }

# Waits until a node actually answers a signed request, not merely until its port is open.
# remoted needs about 15 s after start (it retries wazuh-db first), and NGINX marks a backend down
# for 10 s after a single failure, so starting the two-node checks too early yields a spurious 502
# and a lopsided split.
wait_for_node() {
    local url="$1" label="$2"
    for _ in $(seq 1 40); do
        case "$(status --url "$url")" in
            202|503) return 0 ;;
        esac
        sleep 2
    done
    echo "!! $label never became ready at $url"
    return 1
}

require() {
    local url="$1" what="$2"
    if [[ "$(status --url "$url")" == "NO_OUTPUT" ]] || [[ "$(status --url "$url")" == "TLS_ERROR" ]]; then
        echo "!! $what is not reachable at $url -- see README.md section 5"
        exit 1
    fi
}

# --------------------------------------------------------------------------------- preflight

echo "=== preflight ==="
[[ -f "$CERTS/agent.crt" ]] || { echo "!! no certificates: run ./generate_test_certificates.sh"; exit 1; }
# Without this, a missing module surfaces as three baffling NO_OUTPUT failures much later.
"$PYTHON" -c 'import cryptography, zstandard' 2>/dev/null || {
    echo "!! $PYTHON lacks the cryptography/zstandard modules."
    echo "   pip install -r requirements.txt, or pass --python /path/to/venv/bin/python3"
    exit 1
}
use_mode none
use_config both_topologies
require "$NODE1" "manager node 1"
wait_for_node "$NODE2" "manager node 2" || exit 1
echo "  node 1 (full, with engine)   $NODE1  -> answers 202"
echo "  node 2 (remoted only)        $NODE2  -> answers 503 when the signature is accepted"
echo "  load balancer                $TERM (L7) / $PASS_URL (L4)"

# ============================================================ issue: scenarios 1, 2 and 3
group "Scenario 1 (direct), 2 (passthrough) and 3 (termination) -- the signature must survive"
check "direct: valid request"                       "202" "$(status --url "$NODE1")"
check "direct: tampered body rejected"              "401" "$(status --url "$NODE1" --tamper)"
check "passthrough: valid request"                  "202" "$(status --url "$PASS_URL")"
check "passthrough: tampered body rejected"         "401" "$(status --url "$PASS_URL" --tamper)"
check "termination: valid request"                  "202" "$(status --url "$TERM")"
check "termination: tampered body rejected"         "401" "$(status --url "$TERM" --tamper)"

group "Which certificate the agent validates (issue: where validation happens, which identity)"
subject_at() {
    openssl s_client -connect "$1" </dev/null 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//'
}
direct_subject=$(subject_at 127.0.0.1:1517)
check "passthrough presents remoted's certificate"  "$direct_subject" "$(subject_at 127.0.0.1:8444)"
check "termination presents the balancer's"         "wazuh-lb.test"   "$(subject_at 127.0.0.1:8443)"

# ============================================================ issue: scenario 4
group "Scenario 4 (termination, plaintext backend) -- issue asks whether to support it"
if grep -q "tls_traits_t" "$HERE/../../src/http_server/RestinioHttpServer.cpp" 2>/dev/null; then
    note "NOT IMPLEMENTABLE: the listener is TLS-only (restinio::tls_traits_t, no plaintext variant)."
    note "Termination therefore always means re-encryption. Nothing to test; this is a design answer."
else
    note "could not verify the TLS-only listener from source; check manually"
fi

# ============================================================ issue: health checks (AWS section)
group "Health checks (issue: AWS health checks) -- GET / is an unauthenticated liveness probe"
check "direct: GET / with no Authorization"         "200" "$(status --url "$NODE1" --no-auth --method GET --target / --body '')"
check "termination: GET /"                          "200" "$(status --url "$TERM" --no-auth --method GET --target / --body '')"
check "passthrough: GET /"                          "200" "$(status --url "$PASS_URL" --no-auth --method GET --target / --body '')"
check "node 2 (no engine): GET / still answers"     "200" "$(status --url "$NODE2" --no-auth --method GET --target / --body '')"
check "control: unsigned POST /stateless rejected"  "401" "$(status --url "$NODE1" --no-auth)"
note "GET / (registered in remotedModuleFacade.hpp) is what an LB health check must target: 200,"
note "no auth, no body, exempt from the in-flight byte budget. AWS target group: path /, matcher"
note "200. A plain TCP health check (the NLB default) also works: the port only opens once ready."
note "CAVEAT: this is LIVENESS, not pipeline health -- node 2 answers 200 while every event gets"
note "503 (no engine). A balancer health-checking GET / keeps routing traffic to such a node."

# ============================================================ issue: request transformations
group "Request transformations that could break the signature (issue: full checklist)"
check "query string preserved verbatim"             "202" "$(status --url "$TERM" --target '/stateless?foo=bar&x=1')"
check "extra headers are harmless (not signed)"     "202" "$(status --url "$TERM" --header 'X-Test: 1' --header 'X-Other: 2')"
check "zstd body traverses the proxy"               "202" "$(status --url "$TERM" --zstd)"
check "connection reuse (keep-alive) works"         "6x202" "$(summary --url "$TERM" --repeat 6 --keepalive)"

use_config breaks_signature_path_rewrite
check "path rewriting BREAKS the signature"         "401" "$(status --url "$TERM" --target /wazuh/stateless)"

use_config safe_merge_slashes_on
check "merge_slashes on does NOT break it (//)"     "404" "$(status --url "$TERM" --target '//stateless')"
check "merge_slashes on does NOT break it (..)"     "404" "$(status --url "$TERM" --target '/foo/../stateless')"
note "404 rather than 401 is the proof: the target arrived verbatim, so the signature still matched."

use_config both_topologies
group "Unsigned field: Content-Encoding (issue: are additional signed fields needed?)"
check "control: zstd body with its header"          "202" "$(status --url "$TERM" --zstd)"
check "header removed after signing -> 400 not 401" "400" "$(status --url "$TERM" --zstd --strip-content-encoding)"
check "header added after signing   -> 400 not 401" "400" "$(status --url "$TERM" --add-content-encoding zstd)"
note "400 means the signature validated and the event was silently dropped: the field is unsigned."

# ============================================================ issue: connection handling / AWS
group "PROXY protocol towards remoted (issue: connection handling, source address forwarding)"
check "control: passthrough works without it"       "202" "$(status --url "$PASS_URL")"
use_config breaks_handshake_proxy_protocol 8444
check "proxy_protocol on BREAKS the TLS handshake" "TLS_ERROR" "$(status --url "$PASS_URL")"
note "The PROXY line lands where remoted expects the ClientHello, so EVERY agent's handshake dies"
note "at once. Same failure mode as 'proxy_protocol_v2' on an AWS NLB target group. Never enable"
note "it: until remoted parses it, passthrough deployments simply do not see the agent's IP."
use_config both_topologies

# ============================================================ issue: AWS HTTP transformations
group "HTTP/2 towards the agent (issue: an ALB speaks h2 to clients, HTTP/1.1 to targets)"
if command -v curl >/dev/null; then
    use_config termination_http2
    H2_BODY=$'H {"wazuh":{"agent":{"id":"1001"}}}\nE 1:/var/log/syslog:http2 check event'
    h2_curl() {
        curl -sk "$1" -o /dev/null -w '%{http_version}:%{http_code}' --max-time 15 \
             -H "protocol-version: 1" \
             -H "Authorization: $("$PYTHON" "$PROBE" --print-auth --body "$H2_BODY")" \
             --data-binary "$H2_BODY" https://127.0.0.1:8443/stateless
    }
    check "h2 client: signature survives h2 -> h1.1"  "2:202" "$(h2_curl --http2)"
    check "control: same request over HTTP/1.1"     "1.1:202" "$(h2_curl --http1.1)"
    check "HTTP/1.1-only client (the probe) works"      "202" "$(status --url "$TERM")"
    note "ALPN decides per client on one port: h2 when offered, HTTP/1.1 when not. The conversion"
    note "cannot break the signature: the canonical string (method, target, agent id, timestamp,"
    note "body) exists identically in both versions, and framing is not signed."
    use_config both_topologies
else
    note "curl not found -- HTTP/2 checks skipped (the probe itself only speaks HTTP/1.1)"
fi

group "Idle timeout on keep-alive connections (issue: timeout and connection limits)"
use_config termination_idle_timeout
check "requests spaced inside the timeout"        "2x202" "$(summary --url "$TERM" --repeat 2 --keepalive --interval 1)"
check "idle beyond it: next send finds it closed" "1x202 1xTLS_ERROR" "$(summary --url "$TERM" --repeat 2 --keepalive --interval 5)"
note "Emulates the ALB's 60 s idle timeout with 3 s -- same mechanism, smaller number. The failure"
note "is transport-level and immediate: the request never left the client, nothing was consumed,"
note "so reconnect-and-resend is safe and duplicates nothing. Agents must already handle this."
use_config both_topologies

# ============================================================ issue: verification modes
group "verification_mode = none (issue: all three modes, per topology)"
use_mode none
check "direct"                                      "202" "$(status --url "$NODE1")"
check "termination"                                 "202" "$(status --url "$TERM")"

group "verification_mode = certificate"
use_mode certificate
check "direct, no client certificate"          "TLS_ERROR" "$(status --url "$NODE1")"
check "direct, with the agent certificate"          "202" "$(status --url "$NODE1" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
check "passthrough, no client certificate"     "TLS_ERROR" "$(status --url "$PASS_URL")"
check "passthrough, with the agent certificate"     "202" "$(status --url "$PASS_URL" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
check "termination, NO client certificate"          "202" "$(status --url "$TERM")"
check "termination, with the agent certificate"     "202" "$(status --url "$TERM" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
note "FINDING: under termination remoted answers 202 to a client that presented NO certificate."
note "It verified the proxy's certificate, not the agent's. Agent mTLS does not work there."

use_config termination_without_client_cert
check "termination, proxy presents none: no cert"   "502" "$(status --url "$TERM")"
check "termination, proxy presents none: with cert" "502" "$(status --url "$TERM" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
note "Either way the agent's certificate makes no difference. That is the finding."
use_config both_topologies

# ============================================================ issue: verification_mode=full
# 'full' adds one requirement to 'certificate': the client certificate must carry the address
# the connection CAME FROM, as a subjectAltName. The certificates come from
# generate_test_certificates.sh: agent.crt has IP:127.0.0.1, agent_wrong_ip.crt is identical
# except its SAN says 10.99.99.99. Everything in this lab connects from 127.0.0.1, so that
# second certificate is what makes a passing check mean anything.
group "verification_mode=full, direct connection (issue: verification modes)"
use_mode full
check "cert carrying the peer address"              "202" "$(status --url "$NODE1" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
check "cert carrying a different address"           "403" "$(status --url "$NODE1" --client-cert "$CERTS/agent_wrong_ip.crt" --client-key "$CERTS/agent_wrong_ip.key")"
check "no client certificate at all"          "TLS_ERROR" "$(status --url "$NODE1")"
# The health route is unauthenticated, which is exactly why it has to be covered: a check that
# only guarded the signed routes would leave the one route anybody can reach wide open.
check "health route, cert carrying the address"     "200" "$(status --url "$NODE1" --target / --method GET --no-auth --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
check "health route, cert with another address"     "403" "$(status --url "$NODE1" --target / --method GET --no-auth --client-cert "$CERTS/agent_wrong_ip.crt" --client-key "$CERTS/agent_wrong_ip.key")"
note "403 on every route, health check included -- the rejection is per CONNECTION, not per route."

group "verification_mode=full behind each topology"
check "passthrough, agent cert with the address"    "202" "$(status --url "$PASS_URL" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
check "passthrough, agent cert with another one"    "403" "$(status --url "$PASS_URL" --client-cert "$CERTS/agent_wrong_ip.crt" --client-key "$CERTS/agent_wrong_ip.key")"
note "Passthrough: the agent's own connection reaches remoted, so 'full' judges THE AGENT."
check "termination, agent cert with the address"    "202" "$(status --url "$TERM" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
check "termination, agent cert with another one"    "202" "$(status --url "$TERM" --client-cert "$CERTS/agent_wrong_ip.crt" --client-key "$CERTS/agent_wrong_ip.key")"
check "termination, agent with NO certificate"      "202" "$(status --url "$TERM")"
note "FINDING: under termination all three are 202, including an agent with no certificate."
note "remoted judged the PROXY's certificate (SAN IP:127.0.0.1, which is where NGINX connects"
note "from). 'full' constrains the balancer there, not the agents."

# The other half: the proxy's certificate no longer carries the address it connects from, which
# is what a real deployment hits when the balancer's egress address changes (a second node, an
# autoscaling group, a NAT address).
use_config breaks_full_mode_proxy_cert_ip
check "proxy cert missing its own address"          "403" "$(status --url "$TERM" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
note "403 for a flawless agent certificate: the certificate remoted judged was never the agent's."
use_config both_topologies
use_mode none

# ============================================================ issue: TLS session resumption
# Found while measuring the group above, and it was NOT specific to 'full': whenever remoted
# requested a client certificate, a connection RESUMING a previous TLS session failed the
# handshake with 'internal error' (alert 80), while verification_mode=none resumed fine.
#
# It matters here because proxies resume by default (nginx's proxy_ssl_session_reuse), so a
# terminating proxy with mTLS to the backend got intermittent 502s -- intermittent because a
# pooled keep-alive connection needs no new handshake, and only the connections opened
# afterwards hit it.
#
# Cause: OpenSSL refuses to resume a session on a server that requests client certificates unless
# SSL_CTX_set_session_id_context() has been called. createTlsContext() in RestinioHttpServer.cpp
# now calls it; these checks are what keeps it called.
group "TLS session resumption with mTLS (found by this lab)"
use_mode none
check "verification_mode=none, 3 resumed connections" "202,202,202" "$(status --url "$NODE1" --repeat 3 --resume-session)"
use_mode certificate
check "verification_mode=certificate, resumed"      "202,202,202" "$(status --url "$NODE1" --repeat 3 --resume-session --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
use_mode full
check "verification_mode=full, resumed"             "202,202,202" "$(status --url "$NODE1" --repeat 3 --resume-session --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
note "Both modes were affected identically before the fix: the defect was in the TLS context,"
note "not in the peer-address check that 'full' adds."
use_mode none

# remoted supports three modes: none, certificate and full. Anything else is not a mode -- it is
# an invalid value, ignored with a warning, leaving verification_mode unset. This group checks
# that an unsupported value cannot take the listener down.
group "an unsupported verification_mode is ignored, not fatal"
use_mode unsupported_value
# set_manager_verification_mode.sh also writes <ca>, and remoted's documented special case is that
# a configured <ca> with no usable <verification_mode> infers 'certificate'. So the listener does
# keep serving -- it just asks for a client certificate, which is the whole point of the inference.
check "without a client certificate: mTLS demanded"  "TLS_ERROR" "$(status --url "$NODE1")"
check "with the agent certificate: still serving"     "202" "$(status --url "$NODE1" --client-cert "$CERTS/agent.crt" --client-key "$CERTS/agent.key")"
if grep -q "9001.*verification_mode" /var/wazuh-manager/logs/wazuh-manager.log 2>/dev/null; then
    note "The manager warned about the value instead of accepting it:"
    grep "9001.*verification_mode" /var/wazuh-manager/logs/wazuh-manager.log | tail -1 | sed 's/^/        /'
else
    note "NOTE: no (9001) warning naming verification_mode found in wazuh-manager.log."
fi
use_mode none

# ============================================================ issue: replay protection
group "Replay within the accepted timestamp window (issue: replay protection)"
check "same signature replayed 10 times"         "10x202" "$(summary --url "$TERM" --repeat 10 --interval 0.1)"
note "No replay protection beyond the timestamp window. Already true on a single node."
# Offsets kept a few seconds clear of the exact boundary on purpose: the server evaluates its own
# clock about a second after the probe stamps the request, so -301 and +31 sit right on the edge
# and flip between 202 and 401 from run to run. The window itself is exactly -300 / +30; these
# checks confirm which side of it each request lands on, without being flaky.
check "timestamp -290 s (inside the window)"        "202" "$(status --url "$NODE1" --timestamp-offset -290)"
check "timestamp -320 s (expired)"                  "401" "$(status --url "$NODE1" --timestamp-offset -320)"
check "timestamp +20 s (inside the window)"         "202" "$(status --url "$NODE1" --timestamp-offset 20)"
check "timestamp +45 s (too far ahead)"             "401" "$(status --url "$NODE1" --timestamp-offset 45)"
note "Effective replay window: 330 s (auth_max_request_age 300 back, auth_max_future_skew 30 ahead)."

group "Duplicate delivery across manager nodes (issue: shared replay state in clusters?)"
FIXED_TS=$("$PYTHON" -c 'import time; print(int(time.time()))')
check "node 1 accepts and ingests"                  "202" "$(status --url "$NODE1" --timestamp "$FIXED_TS")"
check "node 2 accepts THE SAME BYTES"               "503" "$(status --url "$NODE2" --timestamp "$FIXED_TS")"
check "control: node 2 rejects a tampered body"     "401" "$(status --url "$NODE2" --timestamp "$FIXED_TS" --tamper)"
check "control: node 2 rejects an expired stamp"    "401" "$(status --url "$NODE2" --timestamp-offset -400)"
note "The 503 means node 2 authenticated a request already consumed by node 1: the request is not"
note "bound to any node. A per-node replay cache would therefore be useless behind a balancer."

# ============================================================ issue: load-balanced deployments
group "Load-balanced deployment: per-connection vs per-request balancing"
wait_for_node "$NODE2" "manager node 2" || exit 1
use_config two_nodes_no_retry
l7=$(summary --url "$TERM" --repeat 6 --keepalive)
l4=$(summary --url "$PASS_URL" --repeat 6 --keepalive)
check "termination spreads requests over nodes"  "3x202 3x503" "$l7"
check "passthrough sends them all to one node"       "6x202" "$l4"
note "One connection, six requests. L4 decides once when the connection opens; L7 decides per request."

# A DEAD node and a node that ANSWERS an error are two different cases, and conflating them is
# easy: with the node down, NGINX logs node_status=502 for the failed attempt, which looks like a
# response but is NGINX's own synthesised status for a refused connection. Nothing was delivered
# there, so retrying it cannot duplicate. Both cases are measured separately below.
group "Failover with the node DOWN (nothing was delivered, so a retry is safe)"
pkill -f '/var/wazuh-manager-2/bin/[w]azuh-manager-remoted' 2>/dev/null || true
sleep 3
check "no retry: one request is lost (502)"      "5x202 1x502" "$(summary --url "$TERM" --repeat 6 --interval 0.2)"
use_config two_nodes_with_retry
check "with retry: nothing lost"                     "6x202" "$(summary --url "$TERM" --repeat 6 --interval 0.2)"
note "The retried request never reached the dead node, so this is failover, not duplication."
echo
echo "  restarting node 2..."
/var/wazuh-manager-2/bin/wazuh-manager-remoted >/dev/null 2>&1
wait_for_node "$NODE2" "manager node 2" && echo "  node 2 answering again"

# Now the case that CAN duplicate: node 2 is alive and answers 503 (it has no engine), so the
# request WAS delivered and consumed before the error came back.
group "Retrying an ANSWERED error is what duplicates -- and it is opt-in on both proxies"
# Asserted as "did any 503 reach the client" rather than an exact split: a 503 also marks node 2
# as failed for fail_timeout, so how many requests it still gets is timing-dependent. The property
# under test is only whether the 503 was passed through instead of retried away.
has_503() { case "$(summary "$@")" in *x503*) echo yes ;; *) echo no ;; esac; }
check "default: a 503 from a live node is NOT retried"  "yes" "$(has_503 --url "$TERM" --repeat 6 --interval 0.3)"
note "NGINX refuses to pass a POST to another server once it has been sent, whatever"
note "proxy_next_upstream lists: retrying non-idempotent methods needs the 'non_idempotent' value."
use_config duplicates_non_idempotent
check "with 'non_idempotent': nothing lost..."        "6x202" "$(summary --url "$TERM" --repeat 6 --interval 0.3)"
if docker logs remoted-lb 2>&1 | grep -q "node_status=503, 202"; then
    note "...but THIS is real duplicate delivery: node_status=503, 202 means node 2 received and"
    note "answered the request, and then node 1 received the very same one:"
    docker logs remoted-lb 2>&1 | grep "node_status=503, 202" | tail -1 | sed 's/^/        /'
fi
note "HAProxy behaves the same way for the same reason: its default 'retry-on conn-failure' only"
note "retries what was never delivered; 'retry-on 503' opts into the duplicate. See"
note "haproxy/duplicates_retry_on_503.cfg, and README.md section 11."
note "So the at-least-once trade-off is a CHOICE, not a default: out of the box neither proxy"
note "duplicates. What stays true is that a legitimate retry and a malicious replay are"
note "byte-identical, so whatever protection is added must answer idempotently rather than reject."
echo
use_config both_topologies

# ============================================================ not covered
group "Not covered by this run"
note "AWS ALB / NLB: needs an account. NGINX reproduces both models (stream=NLB, http=ALB), and the"
note "  h2, idle-timeout and PROXY-protocol behaviours are now measured locally; three AWS-specific"
note "  items remain (ALB backend TLS policy, NLB client-IP preservation, X-Amzn-Mtls-* headers)."
note "Double INGESTION: duplicate delivery is proved above, but measuring double ingestion needs an"
note "  engine on both nodes. See README.md section 8."
note "HAProxy: covered, but not by THIS run -- these checks drive NGINX. Run the same scenarios"
note "  under HAProxy with ./start_haproxy.sh <scenario>; the comparison is in README.md section 11."
note "IPv6/dual-stack, invalid-certificate cases, latency overhead: see README.md section 8."

# --------------------------------------------------------------------------------- summary
printf '\n\033[1m=== summary ===\033[0m\n'
printf '  passed: %d   failed: %d   known bugs reproduced: %d   notes: %d\n' \
       "$PASSED" "$FAILED" "$XFAILED" "$SKIPPED"
if [[ ${#UNEXPECTED_PASS[@]} -gt 0 ]]; then
    echo
    echo "  a known bug no longer reproduces -- check whether it was fixed:"
    for item in "${UNEXPECTED_PASS[@]}"; do echo "    - $item"; done
fi
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo
    echo "  failures:"
    for failure in "${FAILURES[@]}"; do echo "    - $failure"; done
    echo
    echo "  A failure here means either a regression or a lab that is not set up as section 5 expects."
    exit 1
fi
echo
echo "  Every documented outcome reproduced."
exit 0
