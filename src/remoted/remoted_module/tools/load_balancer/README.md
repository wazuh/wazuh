# Load balancer lab: a real cluster, real agents, non-sticky balancing

One master and two workers with real `wazuh-clusterd`, behind HAProxy **and** NGINX, each
serving TLS passthrough and TLS termination at the same time, with real 4.x and 5.x agents and
a single-node indexer.

It exists to reproduce what a production deployment actually does and what no existing test
environment does: **spread one agent's requests across different cluster nodes**.

## Why the balancing is round robin

This is the single decision that makes the lab useful. `api/test/integration/env/` already
provisions master + two workers + HAProxy + mixed agents, and it is a better starting point
than nothing, but it is configured in a way that **hides** everything this lab looks for:

| There | Here | Why it matters |
|---|---|---|
| `balance source`, consistent hash | `roundrobin` | Source hashing pins each agent to one node. The cross-node `/download` 403 never appears |
| `mode tcp` only | passthrough **and** termination | Only termination balances per request; TCP balances per connection |
| `1517` not published | published | — |
| Keys pre-seeded, enrollment off | real enrollment with `authd.pass` | Without enrolling there is no propagation to measure |
| One certificate shared by three nodes | one leaf per node | `cluster.json` does not replicate `etc/certs/` |
| `verification_mode none` on agents | full CA validation | Otherwise SANs are never checked |

## Layout

```
setup_lab.sh            bring everything up, packages included
run_issue_checks.sh     every assertion as PASS/FAIL
generate_certs.sh       the PKI: one leaf per node, plus deliberately broken ones
cert_drill.sh           install a broken certificate on one node and measure every front end
build_wpk.sh            a WPK signed by the lab CA, for a real end-to-end upgrade
base/                   one image per role: manager, agent5, agent4, indexer, probe, proxies
probe/                  scripts that drive scenarios an agent does not perform on demand
scenarios/              per-node configuration overrides for failure injection
migrate/                a 5.x agent booted with a 4.x configuration, for the in-place upgrade path
```

The probe container mounts the repository's **own** agent tools from the parent directory
(`wire_jwt.py`, `send_*.py`) instead of carrying copies, so the wire format can never drift
between the lab and the tools it is testing.

## Requirements

Docker with compose, and three packages the lab does not carry:

```
wazuh-manager_*.deb   wazuh-agent_*.deb   wazuh-indexer_*.deb
```

**Always confirm the package carries what you intend to measure.** A build older than the
feature under test answers as if the defect did not exist, which is worse than failing loudly.
`setup_lab.sh` refuses to continue unless both of these hold:

```bash
strings /var/wazuh-manager/lib/libremoted_module.so | grep -c expectedSelectorFor   # /download authz
grep -c '"ca_certificate"' /var/wazuh-manager/etc/wazuh-manager.schema.json
```

## Bring it up

```bash
# The PKI is issued by the installation assistant's tool, built once:
git clone https://github.com/wazuh/wazuh-installation-assistant
(cd wazuh-installation-assistant && bash builder.sh -c)

export CERTS_TOOL=$PWD/wazuh-installation-assistant/wazuh-certs-tool.sh
./setup_lab.sh --packages /path/to/debs
./run_issue_checks.sh
```

`CERTS_TOOL` is only read when the PKI does not exist yet, or with `--regenerate`. A version
supporting `--agent-san` and the `load_balancer:` section is required -- see [Certificates](#certificates).

`--regenerate` issues a fresh CA, which invalidates every certificate already installed. The
setup always reinstalls from the current PKI so that cannot happen halfway.

## Ports

| Host | Target | Model |
|---|---|---|
| 21517 | HAProxy | TLS passthrough (L4), balances **connections** |
| 21518 | HAProxy | TLS termination + re-encryption (L7), balances **requests** |
| 21519 | HAProxy | Termination with a leaf from a **different CA**, to model a public edge |
| 31517 / 31518 | NGINX | Passthrough / termination |
| 21514 / 21515 | HAProxy | Legacy: `1514` to every node, `1515` to the master only |
| 41517 / 41518 / 41519 | master / worker1 / worker2 | Direct, bypassing the balancer |
| 28404 | HAProxy | Statistics, `/stats` |
| 49200 | Indexer | OpenSearch, client certificate required |

Under termination HAProxy sets `X-Lab-Node` on every response, which is how a scenario records
**which node served which request**. Passthrough cannot report it: the balancer never opens the
response. That is a lab affordance, not something a production front end should leak.

## Certificates

`generate_certs.sh` issues the whole PKI in one invocation. It needs the installation
assistant's tool:

```bash
git clone https://github.com/wazuh/wazuh-installation-assistant
cd wazuh-installation-assistant && bash builder.sh -c
CERTS_TOOL=$PWD/wazuh-certs-tool.sh /path/to/generate_certs.sh
```

The agent-facing address belongs to no node, so the tool takes it separately, once per TLS model:

* **`--agent-san <address>`** adds it to the listener certificate of **every** manager node. That
  is what passthrough needs: the agent dials the balancer but completes the handshake against
  whichever backend answers.
* **a `load_balancer:` section** in `config.yml` issues the proxy its own leaf from the same CA.
  That is what termination needs.

The lab exercises both models at once, so it asks for both. The same SAN requirement gates
enrollment tokens: `POST /agents/enrollment-tokens` validates that `address` is a name in a
listener certificate, so without it no token can point at the balancer.

It also issues material for the failure drills: a leaf whose SAN names nothing the agent dials,
an expired leaf signed by the real CA, and a leaf from a foreign CA.

## Scenarios

### The whole route matrix, with node attribution

```bash
docker exec lab-probe python3 /probe/route_matrix.py \
  --agent-id <id> --key <key> --password labpassword
```

All ten routes through all four front ends. `/control` is one route: `startup`, `notify` and
`shutdown` are values of the body's `type`, and they return **different fields** — the hashes
appear only on `notify`.

### Cluster propagation windows

```bash
docker exec lab-probe python3 /probe/measure_propagation.py \
  --enroll-url https://wazuh-lb-haproxy:1518 \
  --node master=https://wazuh-master:1517 \
  --node worker1=https://wazuh-worker1:1517 \
  --node worker2=https://wazuh-worker2:1517 \
  --password labpassword --json-out /results/propagation.json
```

Enrolls, then asks every node every 250 ms until it accepts the key. `POST /stateless` is the
oracle: `401` means the node does not have the key yet, anything else means it does.

### The cross-node `/download` 403, and whether it converges

```bash
docker exec lab-probe python3 /probe/cross_node_download.py \
  --agent-id <id> --key <key> --control-on worker1 \
  --node master=https://wazuh-master:1517 \
  --node worker1=https://wazuh-worker1:1517 \
  --node worker2=https://wazuh-worker2:1517

docker exec lab-probe python3 /probe/download_convergence.py --password labpassword
```

The first sends `/control` to one node and then the same download to all three. The second
measures whether the denial closes on its own, and how many notify rounds it takes — which is
the part that scales with cluster size.

### Enrollment credential modes

```bash
docker exec wazuh-master cat /var/wazuh-manager/etc/enrollment_tokens.json > probe/store.json
docker exec lab-probe python3 /probe/enroll_modes.py --password labpassword
```

No credential, shared password, enrollment token, an unknown token id, and re-enrollment.

### What still works while nodes are down

```bash
docker stop wazuh-worker2      # or wazuh-master
docker exec lab-probe python3 /probe/availability.py \
  --agent-id <id> --key <key> --password labpassword --label "worker2 down"
```

Reports four capabilities separately — liveness, reporting, control and enrollment — because
the question is not "is it up" but "what stops and what continues".

### Body size limits across every path

```bash
docker exec lab-probe python3 /probe/body_limits.py --agent-id <id> --key <key>
```

The same batch at 1, 9, 11 and 21 MiB, direct and through all four front ends. Above the
transport cap the three paths answer differently, and only one of those answers is actionable
by the agent.

### Certificate failure drills

```bash
./cert_drill.sh "expired leaf"  certs-bad/expired.pem       certs-bad/expired-key.pem
./cert_drill.sh "wrong CA"      certs-bad/rogue.pem         certs-bad/rogue-key.pem
./cert_drill.sh "SAN mismatch"  certs/wazuh-badsan/node.pem certs/wazuh-badsan/node-key.pem
./cert_drill.sh restore
```

Installs the certificate on worker2, restarts it, measures twelve requests from all five paths,
and reads the node's two TLS metrics. Of the three failures, only two move a metric.

`certs-bad/` is built with `openssl ca` and explicit dates, because OpenSSL 3.0 has no
`-not_before`/`-not_after` on `openssl x509`.

### A real upgrade end to end

```bash
./build_wpk.sh --install
# then create the task through the API and watch the agent
docker logs -f wazuh-agent5-term
```

Signs a WPK with the lab CA and repoints the agent's `wpk_root.pem` at it, so task delivery,
download through the balancer, signature verification, unpacking and installer execution all
run for real. It does not exercise the Wazuh release signing key.

The installer must sit at the **root** of the package. Nested under a directory, the agent fails
with `(8134) Could not chmod 'var/upgrade/upgrade.sh'`, which does not name the real cause.

### The 4.x to 5.x in-place transition

```bash
docker exec wazuh-agent4-a cat /var/ossec/etc/client.keys > migrate/legacy.keys
docker stop wazuh-agent4-a
docker compose up -d migrated-agent
```

Boots the 5.x binaries with the `ossec.conf` and `client.keys` a 4.x agent had, which is what a
migrated host looks like: an upgrade never rewrites `ossec.conf`. The agent keeps its id, does
not re-enroll, and moves to `1517` on its own.

### Failure injection

`scenarios/` holds per-node configuration overrides, applied by the manager entrypoint from
`/lab-overrides`. `break-indexer-ca.sh` points the indexer connector at a missing file, which
is enough to keep the whole node from opening its agent listener.

## Indexer

Certificates come from the **same CA** as the managers, so one `root-ca.pem` is the anchor for
the entire lab. `base/indexer/entrypoint.sh` performs the same post-install steps a supported
single-host deployment performs by hand, because the package alone does not start usefully:

| Step | Why |
|---|---|
| Append `-Djava.security.policy=all.policy` and `-Dpermission.java.io.FilePermission=/sys/fs/cgroup/-,read` to `jvm.options` | Without them the node starts and then fails on the cgroup file it reads for memory accounting |
| Set the heap to **4g** (`INDEXER_HEAP` overrides) | The shipped default is `1g`. At `1g` the node answers, then returns `429` under the Wazuh templates and data streams, which reads as an auth or connectivity failure from the manager side |
| Install the certificates `640`, owned by `wazuh-indexer` | The node runs as that user and cannot read them otherwise |
| Rewrite `plugins.security.nodes_dn` to the DN the node certificate actually carries | See below |
| Run `indexer-security-init.sh` **after** the node answers, not before | It writes the security index through the running node |

Two DN facts cost time if you do not know them:

* `opensearch.yml` pins `CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US` as `admin_dn`, and
  `wazuh-certs-tool` issues exactly that, so the manager's client-certificate login works
  untouched.
* `nodes_dn` ships as the **placeholder** `CN=node-1`, while the tool names the node
  certificate after the node (`CN=wazuh-indexer` here). Left alone, the node rejects its own
  transport certificate at bootstrap:

  ```
  Node presenting certificate with SSL Principal {CN=wazuh-indexer,...}
  could not securely connect to the cluster
  ```

  A single node survives it, because nothing else ever joins over the transport layer — which
  is exactly what makes it easy to ship broken and only discover it when a second node is
  added. The step-by-step deployment guides tell you to replace that placeholder with your real
  node names; the entrypoint does the same, deriving the DN from the certificate.

The node's SAN must also include `wazuh-indexer`, the name the managers dial.

The configuration directory is selected by `OPENSEARCH_PATH_CONF`, not by `-Epath.conf`, which
was removed and stops the node from starting.

The managers reach it over `https://wazuh-indexer:9200` with `admin.pem`. A single-host install
points `<indexer><ssl>` straight at `/etc/wazuh-indexer/certs/`; here the two are separate
containers, so the same three files are copied into each manager's own `etc/certs`.

The vulnerability feed does not load here. The manager reads it from the indexer's CTI
catalogue, which nothing populates: the `wazuh-engine` binary shipped inside the indexer package
does not start, because it `dlopen`s `libwazuhshared.so`, which that package does not contain.

## What this lab does not cover

The single-node lab it replaces exercised behaviours this one does not, and they are worth
porting rather than losing:

* `verification_mode` in all three modes, across every topology, including the `403` and the
  startup SAN warning.
* TLS session resumption under mTLS, which is how the intermittent `502` with
  `proxy_ssl_session_reuse` was found and fixed.
* `zstd` request bodies. The transport-versus-auth cap ordering *is* covered here, by
  `probe/body_limits.py` -- see [Body size limits across every path](#body-size-limits-across-every-path).
* Proxy path handling: `merge_slashes`, `..` segments, query-string preservation.
* PROXY protocol being rejected.

Also not covered here: Windows agents, the release WPK signature path, and `vd_feed_offset`
divergence between nodes, which needs feeds loading at different rates.

## Clean up

```bash
docker compose down
docker rm -f lab-probe
```
