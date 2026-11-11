# VirusTotal migration from Wazuh 4.x to 5.x

Integratord, which managed external notifications in 4.x, was removed in Wazuh 5.0 (the manager ships no `wazuh-manager-integratord`), and with it every VirusTotal integration method. If you also had other third-party notifications configured (Slack, PagerDuty, etc.), see the [integratord migration guide](integratord-notifications.md).

In 4.x, VirusTotal and Maltiverse worked as a bi-directional callback loop: integratord sent the alert to the external service, received an enriched response, and re-injected it into Wazuh as a new alert. There is no direct equivalent mechanism in 5.x for live third-party lookups. Enrichment is now handled inline by the Engine during event processing, before events reach the indexer, through two built-in enrichments: Geo/ASN and IOC.

> [!NOTE]
> As the [release notes](../../ref/release-notes.md) put it, real-time VirusTotal lookups have no direct replacement: what 5.0 provides is the Engine's IOC enrichment — a general-purpose threat indicator matching system backed by Wazuh's CTI feed — not live VirusTotal API lookups. See [Section 4](#4-migration-gap) for the functional gap.

## 1. Configuration changes

### 1.1. Do not carry the integration block over

A 5.0 manager is a fresh installation, and its `wazuh-manager.conf` replaces the 4.x `ossec.conf` (see the [manager configuration migration guide](manager-configuration-migration.md)). Leave every 4.x `<integration>` block with `<name>virustotal</name>` behind, whatever filters (`<level>`, `<group>`, `<rule_id>`, `<event_location>`) it contains: `wazuh-manager.conf` has no `<integration>` section, so the manager refuses to start with one (`(1244): Invalid configuration at '/integration': unknown option ...`). The 4.x block looked like this:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

Your VirusTotal API key is no longer used and can be removed from any secrets store tied to this integration.

### 1.2. Do not carry `upload_configuration.integrations` into `api.yaml`

The 4.x `upload_configuration.integrations.virustotal` block of `api.yaml` was removed in 5.0. 5.0 validates `api.yaml` against a closed schema, so a leftover block makes `wazuh-manager-apid` refuse the file (error `2000`) and the API does not start. See [`api.yaml`](manager-configuration-migration.md#apiyaml) in the manager configuration migration guide for this and the other `api.yaml` options removed in 5.0.

## 2. What replaced VirusTotal in 5.0

The Engine has two built-in enrichments, Geo/ASN and IOC, applied to events when the policy enables them; neither
can be extended with a third-party service. Which event fields each one observes is fixed at installation, when the Engine generates its
observed-fields definitions from the Wazuh Common Schema. How both work is described in
[Security enrichment process](../../ref/modules/engine/README.md#security-enrichment-process); what matters for a
VirusTotal migration is the IOC enrichment.

The IOC enrichment looks up the observed values in local IOC databases, one per indicator type: connections
(`ip:port`, built from an IP field and its sibling port field), full URLs, URL domains, and file hashes (MD5, SHA-1
and SHA-256). Each match appends an entry to `wazuh.threat.enrichments` on the event itself (one per matching indicator
document, when several feeds share the value), holding the matched indicator as stored in the database and, in `matched.field`, the event field(s) it came from. For a connection
indicator both field names are written, comma-separated (the `indicator` content shown is illustrative):

```json
{
  "wazuh": {
    "threat": {
      "enrichments": [
        {
          "indicator": {
            "type": "connection",
            "name": "203.0.113.10:4444"
          },
          "matched": {
            "field": "destination.ip, destination.port"
          }
        }
      ]
    }
  }
}
```

The IOC databases are populated from Wazuh's Cyber Threat Intelligence (CTI) feed into the Wazuh Indexer
(`wazuh-threatintel-enrichments`), from which the Engine synchronizes them automatically. They cannot be extended
with custom indicators or connected to third-party feeds such as VirusTotal.

## 3. Migration comparison

In 4.x, the VirusTotal integration acted only on FIM (syscheck) alerts and looked up the file's MD5 hash (`syscheck.md5_after`) live against the VirusTotal API. The table below summarizes the key differences with the 5.x IOC enrichment:

| | Wazuh 4.x (VirusTotal) | Wazuh 5.x (IOC enrichment) |
|---|---|---|
| Trigger | FIM alert (syscheck file event) | Any event with a field matching an IOC observed-fields definition |
| Lookup | VirusTotal API (live, at alert time) | Wazuh CTI database (periodic sync, offline matching) |
| Indicators covered | File MD5 hash | File hashes (MD5, SHA-1, SHA-256), connections (`ip:port`), URLs, URL domains — via Wazuh CTI |
| Indicator source | VirusTotal's database | Wazuh CTI only; custom indicators not supported |
| Result injected as new alert | Yes | No — enrichment is added inline to the originating event |
| API key required | Yes | No |

## 4. Migration gap

> [!WARNING]
> VirusTotal performed live file hash lookups against the VirusTotal API at alert time. The IOC enrichment plugin has no equivalent — it only matches against the Wazuh CTI database, which is synchronized periodically and does not perform real-time external queries. If your use case depended on real-time VirusTotal lookups for on-demand file reputation checks, there is no direct replacement in 5.x.
