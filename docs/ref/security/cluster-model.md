# Manager Cluster Security Model

This document describes the security model of the Wazuh Manager Cluster. It is
intended as a reference for developers, security researchers, and operators
evaluating the cluster surface.

## Overview

The Manager Cluster uses a dedicated transport protocol (DAPI) over TCP port
1516. This protocol is an **internal control plane** between manager nodes, not
a user-facing API. It is distinct from the RESTful API (port 55000), which is
the user-facing entry point and the place where user authentication and
authorization are enforced.

Communication on the cluster protocol is encrypted and authenticated with
per-connection keys derived from a shared cluster key, and every message is
bound to its connection, its position in that connection and its header (see
[Transport Protection](#transport-protection)). Possession of the cluster key is
what defines membership in the cluster.

> **Note:** The `<cluster>` XML section (where the key and other cluster
> settings are configured) is validated against the manager configuration
> schema like every other section of `wazuh-manager.conf`. `key` is a
> **required** field there — a missing or malformed `<key>` (it must match
> `^[A-Za-z0-9]{32}$`) fails configuration validation outright rather than
> falling back to a hardcoded or shared value; see
> [Cluster Configuration](../modules/cluster/configuration.md).

## Trust Boundary

The cluster operates within a single **authority context** shared by all
manager nodes that hold the cluster key. Within this context:

- Nodes are **privileged peers by design**, not clients of one another.
- Any node may invoke operations on any other node through the DAPI, subject
  only to the explicit restrictions described below.
- The authority of a node over another node is equivalent to the authority it
  holds over its own system.

A node joining the cluster is therefore equivalent, in terms of authority, to
an administrator of every other node in the cluster. This is intentional and
is the basis of the cluster's distributed operation.

## Transport Protection

This section specifies how a TCP connection on port 1516 is protected. It
applies to every connection between nodes. The local
`queue/sockets/cluster-internal.sock` socket is created with no key; it stays
plaintext and is protected by its file permissions alone.

### Threat addressed

Earlier versions encrypted each payload as a Fernet token under the static
cluster key and sent a 20-byte header (`!2I12s`: counter, length, command)
**outside** the token. Nothing in a token tied it to a connection, a position
or a header, and the decrypt applied no TTL. An attacker with only a capture of
cluster traffic, and no key, could therefore:

- **Replay a session**: open a new connection and resend a worker's captured
  `hello` (accepted whenever that worker is not connected at the time), then
  its `dapi` and `sendsync` frames. The master re-executes API operations that
  RBAC authorized once.
- **Replay or reorder within a connection**: inject a copy of a captured frame
  into a live connection.
- **Relabel**: send a valid token under a different command or counter in the
  header.
- **Reflect**: send a master's frame back to the master, because both
  directions shared one key.

Each of these is "executing operations on the cluster protocol without
possession of the key", which this model classifies as a vulnerability.

### Handshake

Each side writes a 37-byte plaintext **preamble** as soon as the connection is
established, before any frame:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `WZCP` |
| 4 | 1 | version | `1` |
| 5 | 32 | nonce | `os.urandom(32)`, fresh per connection |

The acceptor (the master's server handler) sends its preamble from
`connection_made`. The connector (the worker's client) also sends its preamble
from `connection_made`, but sends `hello` only once it has received the
acceptor's preamble. Both preambles travel in parallel, so the handshake adds
one half round trip before `hello`. Each side reads exactly 37 bytes before it
parses any frame; anything that follows them in the same read belongs to the
first frame. A wrong magic or version closes the connection with error 3063.
That is what a peer running an older protocol sees, in either direction, instead
of a decryption error. A peer that never sends a preamble is closed by the
existing pre-handshake deadline (`PRE_AUTH_PAYLOAD_TIMEOUT`).

### Key schedule

Each direction has its own key:

```text
salt   = nonce_connector || nonce_acceptor                     (64 bytes)
k_c2s  = HKDF-SHA256(ikm = cluster key, salt, info = "wazuh-cluster/1 c2s", L = 32)
k_s2c  = HKDF-SHA256(ikm = cluster key, salt, info = "wazuh-cluster/1 s2c", L = 32)
```

`ikm` is the 32-character `<cluster><key>`, encoded as ASCII. Each 32-byte output
is a Fernet key (16 bytes for HMAC-SHA256, 16 bytes for AES-128-CBC), passed to
`Fernet` base64url-encoded. A side encrypts with its sending key and decrypts
with its receiving key. The keys live only in the handler object and are
discarded with the connection; every reconnect derives new ones.

### Message format

The outer header is unchanged (`!2I12s`, 20 bytes), and so are message
division into `request_chunk` pieces and the `d` flag. What changes is the
plaintext that each Fernet token encrypts:

```text
token = Fernet(k_send).encrypt( pack("!QI11s", seq, counter, command) || payload )
```

- `seq` is a 64-bit per-direction message number. It starts at 0 for each
  connection and increments by one for each **logical** message, so all chunks
  of a divided message share one `seq`. It is never written to the outer
  header: the receiver expects it. The sender consumes a number only once all
  of a message's frames are built, so a build that fails (the `MemoryError`
  path of `send_request`) leaves no gap.
- `counter` is the outer header's counter, which stays the request/response
  matching ID.
- `command` is the command name as the receiver parses it from the outer
  header: the 12-byte field up to its first space, without the padding and the
  division flag. It is NUL-padded to 11 bytes, the longest command allowed.

On receipt the message is decrypted once, after reassembly as today, with
`k_recv`. It is accepted only if all three inner fields match: `seq` equals the
expected number, `counter` equals the outer counter, and `command` equals the
command parsed from the header of the message's last frame. Then the expected
number is incremented. A token that fails to decrypt raises 3025. A token that
decrypts but fails a match raises 3064. Either way the frame is not dispatched,
no response is sent, and the connection is closed with an error in
`cluster.log`. A keyed handler that is asked to build a frame before its
handshake completes refuses with 3063 rather than send it unbound
(`send_request` reports it wrapped in 3018).

Requiring an exact `seq` is sound because TCP delivers in order and a message's
frames are always written together: `msg_build` and `push` run in one
synchronous step in both `send_request` and `dispatch`, with no `await` between
them, so frames of different messages never interleave.

### Design decisions

1. **Session binding, not a TTL.** The decrypt keeps `ttl=None`. A replay from
   another connection fails because the keys differ, so a TTL adds no replay
   protection. It would add a dependency on clock synchronization between nodes,
   and would also risk rejecting a large synchronization message that is still
   in transit when its timestamp expires.
2. **A separate sequence number, not a monotonic header counter.** The outer
   counter cannot be checked for monotonicity: each side seeds it at random, and
   a response reuses its request's counter. It stays the matching ID, and order
   is enforced by the implicit `seq`.
3. **Fernet stays the cipher.** Only its key changes. This keeps the change
   local to `Handler` and leaves the framing, the chunking and their size limits
   as they are.
4. **Per-direction keys.** These defeat reflection without needing a direction
   bit in the plaintext.
5. **No compatibility shim.** A worker must already run the master's exact
   version (error 3031), so mixed-protocol clusters cannot form. The preamble's
   magic and version turn a mismatch into a clear 3063 instead of a 3025.

### What this does not provide

- **Forward secrecy.** The nonces travel in clear, so anyone who holds the
  cluster key and a capture can derive the session keys. Ephemeral key
  agreement and TLS are out of scope (see the closed #4517). Key compromise
  remains the event described in
  [Cluster Key Compromise](#cluster-key-compromise).
- **Protection against an on-path attacker who drops or resets connections.**
  The nodes detect the break and reconnect, but cannot prevent it.

## Authorization Model

User-level authorization (RBAC) is enforced at the **RESTful API entry point**
(port 55000). Once a request has passed RBAC at the API, the resulting
operations may be dispatched to other nodes through the DAPI. The receiving
node does not re-evaluate the original caller's RBAC permissions; it assumes
that authorization has already been performed upstream.

In practical terms:

- RBAC lives at the API boundary.
- The DAPI is the mechanism by which authorized operations are executed across
  nodes.
- The DAPI is not, and is not intended to be, an authorization boundary
  between nodes.

## Explicit Restrictions Enforced by the DAPI

Independently of the trust model, the DAPI does enforce a small set of
restrictions on operations between nodes:

- **Local configuration**: a node will not accept remote modifications to its
  local  `wazuh-manager.conf` (previously `ossec.conf`).
- **Authority context boundary**: operations outside the scope of the Wazuh
  product (i.e. outside the Wazuh authority context) are not executed through
  the DAPI.

These restrictions are explicit limits of the cluster protocol and are part
of the security model. Crossing them is considered a vulnerability (see
below).

## Deployment Assumptions

The cluster protocol is designed **exclusively for operation within an isolated
network segment**.

**Supported deployment**: Port 1516 is isolated to a dedicated management
network accessible only to cluster nodes. This is enforced through network-level
segmentation (dedicated subnet, VLAN, security group, firewall rules, etc.).

**Unsupported deployment**: Port 1516 exposed to untrusted networks, the
Internet, agent networks, or user networks.

Vulnerabilities reported in unsupported deployment configurations are **out of
scope** for security evaluation, as they require violating documented
operational requirements that define the product's security boundary.

An attacker capable of reaching port 1516 has, by definition of a supported
deployment, already crossed a network boundary that the operator is required
to enforce.

## CVSS Considerations

When evaluating vulnerabilities affecting the cluster protocol, the appropriate
CVSS attack vector metric is **AV:A (Adjacent Network)**, not AV:N (Network).

**Rationale**: The DAPI operates within a **limited administrative domain** as
defined by CVSS 3.1. In a supported deployment, port 1516 is restricted to a
dedicated management network segment accessible only to cluster nodes. An
attacker cannot reach port 1516 from arbitrary network locations without first
breaching the network segmentation that defines the cluster's administrative
boundary.

The protocol is not designed for Internet-accessible or untrusted network
deployments. Such configurations are unsupported and out of scope for
vulnerability evaluation.

This is analogous to:

- Kubernetes etcd (port 2379/2380) and kubelet APIs, which require access to
  the control plane network (AV:A)
- Elasticsearch transport protocol (port 9300), which operates within the
  cluster's private network (AV:A)
- Database replication protocols within a private VLAN or secure VPN (AV:A)

Access to port 1516 requires positioning within the **secure administrative
domain** of the cluster management network—equivalent to access within a
management VLAN, secure VPN, or MPLS network as described in CVSS 3.1 AV:A
definition.

## Common Threat Scenarios

### Unauthorized Network Access to Port 1516

**Attack path**: An external attacker attempts to connect directly to port 1516
from outside the isolated cluster network.

**Mitigations**:
- Network segmentation prevents access from untrusted networks (operator
  responsibility, deployment assumption)
- Even if network access is gained, the cluster key is required to authenticate
- The attacker must breach network isolation **and** obtain the cluster key

**CVSS vector**: AV:A, as it requires breaching the adjacent network boundary
first.

### Cluster Key Compromise

**Attack path**: An attacker obtains the cluster key (e.g., via file
read vulnerability, backup exposure, or insider access).

**Impact**: The key alone is insufficient for cluster compromise. The attacker
also requires network access to port 1516, which is prevented by network
segmentation in a supported deployment.

**Mitigations**:
- Store keys in secrets management systems
- Restrict file permissions on key storage
- Regular key rotation
- Network segmentation (key + network access both required)

**Note**: Compromise of the cluster key is a critical security event and should
trigger an incident response (key rotation, access investigation, etc.), but
the key alone does not constitute full cluster compromise without the adjacent
network access.

### Node Compromise

**Attack path**: An attacker fully compromises a single cluster node (e.g.,
via remote code execution, stolen credentials, or physical access).

**Impact**: By design, compromise of any cluster node implies compromise of the
entire cluster. The attacker now possesses the cluster key and has network
access to port 1516 from within the trusted network segment.

**Mitigations**:
- Node hardening (OS security controls, patching, access restrictions)
- Monitoring and intrusion detection on cluster nodes
- Network segmentation to limit lateral movement beyond the cluster

**Key insight**: This is analogous to root access on a server in a traditional
architecture. The cluster's mutual trust model means there is no security
boundary between authenticated cluster members. This is intentional and
enables the cluster's distributed operation.

## What Constitutes a Cluster Vulnerability

Within this model, the following are considered vulnerabilities in the
cluster surface:

- Disclosure of the cluster key to a principal that is not a cluster
  administrator.
- Joining the cluster, or executing operations on the cluster protocol,
  without possession of the cluster key — including by replaying, reordering,
  reflecting or relabelling captured cluster traffic.
- Bypassing the explicit restrictions listed above (writing local
  `wazuh-manager.conf` remotely, or executing operations outside the Wazuh authority
  context through the DAPI).
- Any vector that allows a principal outside the cluster authority context to
  cross into it.

The following are **not** considered vulnerabilities in the cluster surface,
as they describe the documented behavior of the trust model:

- A node performing privileged operations on another node, given that both
  nodes are legitimate members of the cluster.
- The absence of per-operation RBAC re-evaluation on the receiving node of a
  DAPI call.
- The ability of a cluster administrator to act with administrator-level
  authority across the cluster.

Reports describing the latter category will be evaluated against this model.
Reports describing the former are in scope and will be handled through the
normal coordinated disclosure process.
