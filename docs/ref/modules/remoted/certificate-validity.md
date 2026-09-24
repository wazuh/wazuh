# Certificate validity

remoted reports the validity of the TLS material it serves to agents as one JSON document per
node: the certificate its HTTPS listener presents, and the CA bundle it hands out on
`GET /cacerts`. Two ways to read it:

| Where | Route | Who |
|---|---|---|
| Admin socket on the node | `GET /tls` on `queue/sockets/remote-admin-http.sock` | an operator with a shell, `curl --unix-socket` |
| Server API | `GET /cluster/{node_id}/daemons/remoted/tls` | the Dashboard, automation; action `cluster:read` on `node:id` |

The document carries **dates and identities, no verdicts**: there is no `warning` or `critical`
field and no threshold. What "expiring soon" means is the consumer's decision (the Dashboard's, a
runbook's). The daily log line remoted writes about its certificate (see
[Metrics](metrics.md#tls-listener-certificate--remotedservertls)) is unchanged and separate.

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/tls | jq
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:55000/cluster/master-node/daemons/remoted/tls?pretty=true
```

## The document

```json
{
  "evaluated_at": "2026-09-15T10:00:00Z", "evaluated_at_ts": 1789466400,
  "listener": {
    "subject": "CN=manager-01", "issuer": "CN=Corp Root CA",
    "sans": ["manager-01.example.com", "10.0.0.5"],
    "not_before": "2026-01-01T00:00:00Z", "not_before_ts": 1767225600,
    "not_after": "2027-01-01T00:00:00Z", "not_after_ts": 1798761600,
    "seconds_until_expiry": 9295200,
    "fingerprint": "x509-sha256:3f9c…", "serial": "0x1a2b…",
    "path": "etc/certs/remoted.pem",
    "loaded_at": "2026-09-14T08:12:31Z", "loaded_at_ts": 1789373551
  },
  "ca_bundle": {
    "path": "etc/certs/root-ca.pem",
    "publication": 0, "publication_vouched": false,
    "content_sha256": "b7e1…",
    "certificates_count": 2, "certificates_limit": 6,
    "serialized_bytes": 2428, "serialized_bytes_limit": 8191,
    "matches_active_leaf": true, "chain_valid": true,
    "certificates": [
      { "subject": "CN=Corp Root CA", "issuer": "CN=Corp Root CA",
        "not_before": "…", "not_before_ts": 0, "not_after": "…", "not_after_ts": 0,
        "seconds_until_expiry": 0, "fingerprint": "x509-sha256:…", "serial": "0x…",
        "signs_active_leaf": true },
      { "…": "…", "signs_active_leaf": false }
    ]
  }
}
```

Every timestamp comes in two spellings: RFC 3339 UTC, and `_ts` as epoch seconds.

| Field | Meaning |
|---|---|
| `evaluated_at` | When remoted built the document: the request time. |
| `listener.subject`, `issuer` | RFC 2253 one-line names of the certificate the HTTPS listener serves ([`https.certificate`](configuration.md#httpscertificate)). |
| `listener.sans` | Its subjectAltName DNS names and IP addresses, bare, in certificate order. What an agent can dial with verification on. |
| `listener.not_before`, `not_after` | Validity window. |
| `listener.seconds_until_expiry` | `not_after_ts − evaluated_at_ts`. **Signed: negative once expired.** |
| `listener.fingerprint` | The certificate's identity, see [Identities](#identities). |
| `listener.serial` | Serial number, `0x` + lowercase hex. |
| `listener.path` | The configured path, relative to the installation directory. |
| `listener.loaded_at` | When remoted loaded this certificate: its last start. See [Freshness](#freshness). |
| `ca_bundle.path` | [`https.ca_certificate`](configuration.md#httpsca_certificate), the file `GET /cacerts` serves from. |
| `ca_bundle.publication`, `publication_vouched` | The publication `wazuh-manager-certs` stamped in the bundle's `##` block, the same value the manager advertises to agents as `ca_generation`: `null` when there is no servable bundle, `0` when a bundle is served but no guard vouches for it, else the vouched Unix timestamp. `publication_vouched` is that guard's verdict (block present, hash matches, the leaf chains to a CA of the bundle, count and size within the agent limits), judged against the clock on every request: a CA that expires with the file untouched reads `0` / `false` on the next one. See the [CA rotation runbook](ca-rotation.md). |
| `ca_bundle.content_sha256` | The bundle's identity: SHA-256 (bare hex) over the DER encoding of every certificate, sorted and concatenated, so it does not depend on the order the files were concatenated in. |
| `ca_bundle.certificates_count`, `certificates_limit` | Certificates in the bundle, and the most a bundle may carry and still reach every agent (6). |
| `ca_bundle.serialized_bytes`, `serialized_bytes_limit` | Size of the PEM `GET /cacerts` sends, and the largest bundle an agent accepts (8191 bytes). Whichever limit binds first is the room left before adding a CA. Nothing here enforces them: the rotation tool refuses to publish past them. |
| `ca_bundle.matches_active_leaf` | Whether the listener certificate chains to some CA of this bundle: the `503 ca_mismatch` decision of `GET /cacerts`, see [Three different questions](#three-different-questions). Judged against the clock on every request. `null` when there is nothing to check against. |
| `ca_bundle.chain_valid`, `chain_error` | Whether the listener certificate validates with this bundle as its **only** trust store; see [Three different questions](#three-different-questions). `null` when there is nothing to validate against; `chain_error` present only when `false`. |
| `ca_bundle.certificates[]` | One entry per certificate, same fields as the listener minus `sans`, `path` and `loaded_at`, plus `signs_active_leaf`. |
| `ca_bundle.last_read_failure` | Present only while the bundle file cannot be read; see [When the bundle cannot be read](#when-the-bundle-cannot-be-read). |

## Freshness

The two halves age differently, and the document says so.

- **The CA half is never older than the request.** Each request reads the bundle from the same
  place `GET /cacerts` answers from, so the two routes can never disagree about whether the CA
  signs the served certificate, and a bundle replaced on disk shows in the very next request: no
  restart, no wait for the daily evaluation. Replace it atomically (write a sibling file, `mv` it
  over the path): a file caught half-written reads as empty or as refused whole.
- **The listener certificate is the one loaded when remoted started**, dated by
  `listener.loaded_at`. Replacing `remoted.pem` on disk changes nothing until remoted restarts, and
  the document keeps describing the certificate agents actually get. There is no "force refresh"
  parameter on purpose: it could only refresh half the resource.

## Three different questions

`signs_active_leaf` (per CA), `matches_active_leaf` and `chain_valid` (per bundle) are all about "does
this bundle let an agent trust the listener", and each answers a different part of it.

- **`signs_active_leaf`** is a plain signature check: did this CA's key sign the served certificate.
  No dates, no constraints. It is the same fact `wazuh-manager-certs inspect` prints per certificate.
- **`matches_active_leaf`** is what `GET /cacerts` decides its `503 ca_mismatch` from: does the
  listener certificate CHAIN to some CA of the bundle, with OpenSSL's default rules (validity dates
  and `CA:TRUE` checked, only a self-signed certificate is an anchor). It is the same value the metric
  `remoted.server.tls.ca_matches_leaf` exposes.
- **`chain_valid`** is what a verifying agent would conclude with this bundle as its only trust
  store: path building, validity dates, `basicConstraints`/`keyUsage` of every CA on the path,
  TLS-server purpose.

They disagree on purpose in the cases an operator most needs to see: a CA that signed the listener
but has expired, or that lacks `CA:TRUE`, reads `signs_active_leaf: true` while `matches_active_leaf`
and `chain_valid` are both `false`, `chain_error` saying why (`certificate has expired`, `invalid CA certificate`). During a
rotation the new CA typically reads `signs_active_leaf: false` until the listener is reissued under
it: that is the expected intermediate state, not a fault. All three are evaluated at request time,
from the certificates already parsed: a CA that expires while the file stays untouched reads
`matches_active_leaf: false`, `chain_valid: false` and `publication: 0` on the next request -- the
same moment `GET /cacerts` starts answering `503` -- and the log says so once, in the request that
noticed it. Only the parse is cached by the file's content hash, never a verdict with a date term.

## When the bundle cannot be read

A read that fails is a window, not a decision: remoted keeps serving the last bundle it read
successfully, and this document keeps describing it. While that lasts, `ca_bundle` carries
`last_read_failure` with the `cause` (for example `cannot be opened (No such file or directory)`,
`cannot be read (Is a directory)`, `is larger than the 1 MiB cap`), the `errno`, and how many reads
in a row have failed (`consecutive`). The certificate list, sizes and hash next to it are those of
the **last good read**, and `chain_valid` is still judged as of now against that bundle. A bundle that
never read successfully shows `certificates_count: 0` **and** the failure, so an empty list can never be
mistaken for "no certificates to worry about".

## Identities

`fingerprint` is `x509-sha256:` followed by the SHA-256 of the certificate's DER encoding as 64
lowercase hex digits, no separators. It identifies that exact certificate: a reissue with the same
key is a different certificate and reads as one. It is **not** a public-key (SPKI) pin. To compare
with what OpenSSL prints (uppercase, colon-separated):

```bash
openssl x509 -in /var/wazuh-manager/etc/certs/remoted.pem -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
```

`ca_bundle.content_sha256` identifies the bundle as a whole (see the table above). Both are the
strings the rotation tool takes and prints, so a value copied from this document can be pasted
into it.

## Server API

`GET /cluster/{node_id}/daemons/remoted/tls` returns the document of that node, with `node` added,
under `cluster:read` over `node:id:{node_id}` (the same permission as
`GET /cluster/{node_id}/daemons/stats`; no new RBAC action). It is per node on purpose: certificate
material is node specific, and nodes legitimately differ while a rotation is in progress.

`data.affected_items` always holds exactly one item, and it always carries `node`:

- when remoted answered: `{"node": "worker-01", "available": true, ...the document...}`;
- when it could not: `{"node": "worker-01", "available": false, "reason": "..."}`.

The second form is the node's answer, not an error of the request, so it never appears in
`failed_items` and the HTTP status stays `200`. A consumer should render it as **unknown**, never as
healthy (there is no certificate list to be reassured by) and never as failed. Reasons:

| `reason` | What it means |
|---|---|
| `remoted not running` | The daemon is down on that node (PID check). |
| `admin socket unreachable` | remoted runs, but its local admin socket never came up (it is optional: remoted keeps serving agents without it). |
| `listener not started` | remoted runs, the admin socket answers, but the HTTPS listener is not accepting yet (remoted answered `503`). |
| `timeout`, `invalid response`, `unexpected response`, `request failed`, `admin client unavailable` | The admin socket did not answer usefully. |

Requests for a node the cluster does not have answer `404` with error `1730`, and a caller without
the permission gets `403`, as for every other per-node cluster resource.
