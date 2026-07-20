# VirusTotal migration from Wazuh 4.x to 5.x

Integratord, which managed external notifications, has been deprecated in Wazuh 5.0, and with it all VirusTotal integration methods. If you also had other third-party notifications configured (Slack, PagerDuty, etc.), see the [integratord migration guide](integratord-notifications.md).

In 4.x, VirusTotal and Maltiverse worked as a bi-directional callback loop: integratord sent the alert to the external service, received an enriched response, and re-injected it into Wazuh as a new alert. There is no direct equivalent mechanism in 5.x for live third-party lookups. Enrichment is now handled inline by the Engine during event processing, before events reach the indexer, through exactly two built-in plugins: Geo/ASN and IOC.

> [!NOTE]
> The Wazuh 5.0 release notes state that "VirusTotal functionality is now built-in." This refers to the Engine's native IOC enrichment capability — a general-purpose threat indicator matching system backed by Wazuh's CTI feed — not a replacement for live VirusTotal API lookups. See [Section 4](#4-migration-gap) for the functional gap.

## 1. Configuration changes

### 1.1. Remove the integration block from `ossec.conf`

Remove all `<integration>` blocks with `<name>virustotal</name>` from your 4.x `ossec.conf` (renamed to `wazuh-manager.conf` in 5.0 — see the [manager configuration migration guide](manager-configuration-migration.md)). The entire block must be deleted regardless of which optional parameters (`<level>`, `<group>`, `<rule_id>`, `<alert_level>`) it contains:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

Your VirusTotal API key is no longer used and can be removed from any secrets store tied to this integration.

### 1.2. Remove the `upload_configuration` entry from `api.yaml`

The `upload_configuration.integrations.virustotal` block was removed in 5.0 and must be deleted from `api.yaml`:

```yaml
# Remove this block:
upload_configuration:
  integrations:
    virustotal:
      public_key:
        allow: yes
        minimum_quota: 240
```

See the [manager configuration migration guide](manager-configuration-migration.md#simplified-upload_configuration) for the full list of `upload_configuration` entries removed in 5.0.

## 2. What replaced VirusTotal in 5.0

The Engine provides two built-in enrichment plugins, Geo/ASN and IOC, which cannot be extended with third-party services. During installation, the Engine generates enrichment source definition files for both.

### 2.1. Geo/ASN enrichment

Geo enrichment evaluates the event fields defined for geo/ASN observation and, when applicable, adds location and autonomous system context to the event.

The fields observed for this enrichment are determined from the generated geo enrichment definitions based on the Wazuh Common Schema (WCS). These typically include fields that may contain IP addresses relevant for enrichment.

When a valid source value is found, geo enrichment may add information such as:

- Geographic location data
- Country or city data
- ASN number
- ASN organization

```json
{
  "source": {
    "ip": "8.8.8.8",
    "geo": {
      "country_name": "United States",
      "location": {
        "lat": 37.751,
        "lon": -97.822
      }
    },
    "as": {
      "number": 15169,
      "organization": {
        "name": "Google LLC"
      }
    }
  }
}
```

### 2.2. IOC enrichment

IOC enrichment evaluates the event fields defined for IOC observation and checks whether their values match known indicators of compromise.

The observed fields are determined from the generated IOC enrichment definitions based on the Wazuh Common Schema (WCS) and the predefined observation rules.

Depending on the observed field and the configured IOC types, this enrichment may evaluate values such as:

- Connection-based indicators represented as ip:port
- Domains
- URLs
- Hashes
- Other supported indicator values

In particular, network IOC matching is not limited to plain IP values. For connection-based enrichment, the observed value is built from the relevant event fields as a connection key, typically combining IP address and port.

If a match is found, the event is enriched with threat-related context associated with the matched indicator. For connection-based IOC matching, the Engine builds a `ip:port` key from the relevant event fields and writes both field names in `matched.field`:

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

The IOC database is populated from Wazuh's Cyber Threat Intelligence (CTI) feed and synchronized automatically by the Wazuh Indexer. It is not user-configurable and cannot be extended with custom indicators or connected to third-party feeds such as VirusTotal directly.

## 3. Migration comparison

In 4.x, the VirusTotal integration was triggered exclusively by FIM (syscheck) alerts and performed live file hash lookups against the VirusTotal API. The table below summarizes the key differences with the 5.x IOC enrichment:

| | Wazuh 4.x (VirusTotal) | Wazuh 5.x (IOC enrichment) |
|---|---|---|
| Trigger | FIM alert (syscheck file event) | Any event with a field matching an IOC observed-fields definition |
| Lookup | VirusTotal API (live, at alert time) | Wazuh CTI database (periodic sync, offline matching) |
| Indicators covered | File hashes (MD5/SHA-256) | Hashes, connection indicators (IP:port), domains, URLs — via Wazuh CTI |
| Custom indicators | Backed by VirusTotal's database | Not supported |
| Result injected as new alert | Yes | No — enrichment is added inline to the originating event |
| API key required | Yes | No |

## 4. Migration gap

> [!WARNING]
> VirusTotal performed live file hash lookups against the VirusTotal API at alert time. The IOC enrichment plugin has no equivalent — it only matches against the Wazuh CTI database, which is synchronized periodically and does not perform real-time external queries. If your use case depended on real-time VirusTotal lookups for on-demand file reputation checks, there is no direct replacement in 5.x.
