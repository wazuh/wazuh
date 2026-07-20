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

Communication on the cluster protocol is encrypted and authenticated using a
shared Fernet key. Possession of this key is what defines membership in the
cluster.

## Trust Boundary

The cluster operates within a single **authority context** shared by all
manager nodes that hold the Fernet key. Within this context:

- Nodes are **privileged peers by design**, not clients of one another.
- Any node may invoke operations on any other node through the DAPI, subject
  only to the explicit restrictions described below.
- The authority of a node over another node is equivalent to the authority it
  holds over its own system.

A node joining the cluster is therefore equivalent, in terms of authority, to
an administrator of every other node in the cluster. This is intentional and
is the basis of the cluster's distributed operation.

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
- Even if network access is gained, the Fernet key is required to authenticate
- The attacker must breach network isolation **and** obtain the cluster key

**CVSS vector**: AV:A, as it requires breaching the adjacent network boundary
first.

### Cluster Key Compromise

**Attack path**: An attacker obtains the Fernet cluster key (e.g., via file
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

- Disclosure of the Fernet key to a principal that is not a cluster
  administrator.
- Joining the cluster, or executing operations on the cluster protocol,
  without possession of the Fernet key.
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
