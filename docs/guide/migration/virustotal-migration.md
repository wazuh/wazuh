# VirusTotal migration from Wazuh 4.x to 5.x

Integratord, which managed external notifications, has been deprecated in Wazuh 5.0, and with it all VirusTotal integration methods.

In 4.x, VirusTotal and Maltiverse worked as a bi-directional callback loop: integratord sent the alert to the external service, received an enriched response, and re-injected it into Wazuh as a new alert. There is no equivalent mechanism in 5.x, so these integrations cannot be migrated. Enrichment is now handled inline by the Engine during event processing, before events reach the indexer, through exactly two built-in plugins: Geo/ASN and IOC.

## 1. Configuration changes

Make sure to remove this block from your manager configuration file (`wazuh-manager.conf`):

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

## 2. What replaced VirusTotal in 5.0

The Engine provides two built-in enrichment plugins, Geo/ASN and IOC, which cannot be extended with third-party services. During installation, the Engine generates enrichment source definition files for both.

### 2.1. Geo/ASN enrichment

Geo enrichment evaluates the event fields defined for geo/ASN observation and, when applicable, adds location and autonomous system context to the event.

The fields observed for this enrichment are determined from the generated geo enrichment definitions based on the WCS. These typically include fields that may contain IP addresses relevant for enrichment.

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

The observed fields are determined from the generated IOC enrichment definitions based on the WCS and the predefined observation rules.

Depending on the observed field and the configured IOC types, this enrichment may evaluate values such as:

- Connection-based indicators represented as ip:port
- Domains
- URLs
- Hashes
- Other supported indicator values

In particular, network IOC matching is not limited to plain IP values. For connection-based enrichment, the observed value is built from the relevant event fields as a connection key, typically combining IP address and port.

If a match is found, the event is enriched with threat-related context associated with the matched indicator.

```json
{
  "wazuh": {
    "threat": {
      "indicator": {
        "type": "ipv4-addr",
        "ip": "203.0.113.10"
      },
      "enrichments": [
        {
          "matched": {
            "field": "destination.ip"
          }
        }
      ]
    }
  }
}
```

## 3. Migration gap

> [!WARNING]
> VirusTotal performed live hash and IP lookups against the VirusTotal API at alert time. The IOC enrichment plugin has no equivalent — it only matches against the Wazuh IOC database populated via the indexer. If your use case depended on real-time VirusTotal lookups, there is no direct replacement in 5.x.
