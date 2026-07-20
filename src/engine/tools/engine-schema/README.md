# Engine Schema Tool

Standalone tool for generating engine schema and associated configuration files from Wazuh Common Schema (WCS).

## Installation

```bash
pip install -e .
```

It can also be used directly without the installation:

```bash
python3 engine_schema.py generate --output-dir /engine_schema_test --wcs-path "ecs_flat_1.yaml , ecs_flat_2.yaml" --decoder-template /path/to/wazuh-decoders.template.json
```

## Usage

```bash
# Using a single YAML file
engine-schema generate --wcs-path /path/to/wcs_flat.yml --output-dir ./output --decoder-template /path/to/wazuh-decoders.template.json

# Using a directory with multiple YAML files (they will be merged)
engine-schema generate --wcs-path /path/to/wcs_directory/ --output-dir ./output --decoder-template /path/to/wazuh-decoders.template.json

# Using a list of YAML files (they will be merged)
engine-schema generate --wcs-path "/path/to/wcs_directory/file_1.yaml , /path/to/wcs_directory/file_2.yaml" --output-dir ./output --decoder-template /path/to/wazuh-decoders.template.json
```

## Arguments

- `--wcs-path`: Path to the Wazuh Common Schema YAML file, directory containing YAML files or list of files separated by comma. If a directory is provided, all .yml and .yaml files will be merged into a single schema without duplicated keys
- `--output-dir`: Root directory to store generated files (default: current directory)
- `--decoder-template`: Path to wazuh-decoders.json template file for fields injection
- `--types-output`: Optional path to write the list of ECS field types
- `--exclude-geo-ip`: Optional comma-separated list of IP fields to exclude from geo enrichment (e.g., "observer.ip,client.nat.ip")
- `--ioc-enrichment-cfg`: Optional path to a JSON file that defines IOC enrichment configuration (which fields to check for IOCs)

## Generated Files

The tool generates the following files:
- `wazuh-decoders.json`: Unified decoder schema with all fields injected into the template
- `wazuh-logpar-overrides.json`: Logpar configuration overrides
- `engine-schema.json`: Engine schema definition
- `enrichment-geo.json`: Geo/AS enrichment configuration mapping
- `enrichment-ioc.json`: IOC enrichment source fields configuration

## Enrichment Configuration

### Geo/AS Enrichment

The tool automatically generates a geo enrichment mapping (`enrichment-geo.json`) that specifies which IP fields should be enriched with geographic and AS (Autonomous System) information.

**How it works:**
- Scans all IP-type fields in the WCS schema
- For each IP field, identifies sibling geo and AS/ASN containers
- Creates a mapping between the IP field and its enrichment targets

**Example output:**
```json
{
  "source.ip": {
    "geo_field": "source.geo",
    "as_field": "source.as"
  },
  "destination.ip": {
    "geo_field": "destination.geo",
    "as_field": "destination.as"
  }
}
```

**Exclude IP fields from geo enrichment:**
You can exclude specific IP fields using the `--exclude-geo-ip` argument:
```bash
engine-schema generate --wcs-path /path/to/wcs.yml --output-dir ./output \
  --exclude-geo-ip "observer.ip,cloud.instance.id"
```

### IOC Enrichment

The tool generates an IOC enrichment configuration (`enrichment-ioc.json`) that defines which event fields should be checked against IOC (Indicator of Compromise) databases.

#### Configuration File Structure

The IOC enrichment is controlled by a JSON configuration file (typically `ioc-enrichment-cfg.json`) that you pass via the `--ioc-enrichment-cfg` argument.

**Global Section:**
```json
{
  "global": {
    "exclude_trees": [
      "threat.indicator",
      "threat.enrichments"
    ]
  }
}
```
- `exclude_trees`: List of field prefixes to globally exclude from ALL IOC types. Any field starting with these prefixes will never be checked for IOCs.

**Types Section:**

The `types` section defines configuration for each IOC type. Each type can be independently enabled/disabled and has its own inclusion/exclusion rules.

##### 1. Connection Type

Detects malicious IP:port pairs. It looks for sibling fields where an IP and port exist under the same parent.

```json
"connection": {
  "enabled": true,
  "include": {
    "sibling_pair_rule": {
      "ip_field_names": ["ip"],
      "port_field_names": ["port"]
    }
  },
  "exclude": {
    "exclude_trees": []
  }
}
```

- `enabled`: Set to `true` to activate connection IOC checking
- `sibling_pair_rule`: Defines which leaf field names to look for
  - `ip_field_names`: Array of IP field leaf names (e.g., "ip", "address")
  - `port_field_names`: Array of port field leaf names (e.g., "port")
- `exclude.exclude_trees`: Additional field prefixes to exclude (on top of global exclusions)

**How it works:** The tool scans for fields like `source.ip` + `source.port` or `destination.ip` + `destination.port` and creates pairs.

**Generated output:**
```json
"connection": {
  "sources": [
    {"ip_field": "source.ip", "port_field": "source.port"},
    {"ip_field": "destination.ip", "port_field": "destination.port"}
  ]
}
```

##### 2. URL Full Type

Checks complete URLs against IOC databases.

```json
"url_full": {
  "enabled": true,
  "include": {
    "explicit_fields": [
      "url.full",
      "url.original"
    ]
  },
  "exclude": {
    "exclude_trees": []
  }
}
```

- `enabled`: Set to `true` to activate URL full matching
- `explicit_fields`: Exact field paths to check for full URLs
- `exclude.exclude_trees`: Field prefixes to exclude

**Generated output:**
```json
"url_full": {
  "sources": ["url.full", "url.original"]
}
```

##### 3. URL Domain Type

Checks domain names, subdomains, and hostnames against IOC databases.

```json
"url_domain": {
  "enabled": true,
  "include": {
    "by_field_contains": [
      "domain",
      "registered_domain",
      "subdomain"
    ],
    "explicit_fields": [
      "host.name",
      "host.hostname"
    ],
    "by_description_exact": {
      "enabled": true,
      "values": [
        "Name of the directory the user is a member of.",
        "Name of the directory the group is a member of."
      ]
    }
  },
  "exclude": {
    "exclude_trees": []
  }
}
```

- `enabled`: Set to `true` to activate domain IOC checking
- `by_field_contains`: Array of tokens to search in field names. Any field containing these tokens will be included (e.g., "dns.question.domain", "url.registered_domain")
- `explicit_fields`: Specific field paths to always include
- `by_description_exact`: **Exclusion filter** based on field descriptions in WCS
  - `enabled`: Set to `true` to activate this filter
  - `values`: Array of exact description strings. Fields with these descriptions will be EXCLUDED (useful to filter out fields like "user.domain" which refers to Active Directory, not internet domains)
- `exclude.exclude_trees`: Additional field prefixes to exclude

**Generated output:**
```json
"url_domain": {
  "sources": [
    "dns.question.name",
    "host.name",
    "url.domain",
    "url.registered_domain"
  ]
}
```

##### 4. Hash Type

Checks file hashes against IOC databases. Supports multiple hash algorithms.

```json
"hash": {
  "enabled": true,
  "algorithms": {
    "md5": {
      "enabled": true,
      "include": {
        "by_field_contains": ["hash.md5"]
      },
      "exclude": {
        "exclude_trees": []
      }
    },
    "sha1": {
      "enabled": true,
      "include": {
        "by_field_contains": ["hash.sha1"]
      },
      "exclude": {
        "exclude_trees": []
      }
    },
    "sha256": {
      "enabled": true,
      "include": {
        "by_field_contains": ["hash.sha256"]
      },
      "exclude": {
        "exclude_trees": []
      }
    }
  }
}
```

- `enabled`: Set to `true` to activate hash IOC checking globally
- `algorithms`: Object containing configuration for each hash algorithm
  - Each algorithm (md5, sha1, sha256, sha384, sha512, tlsh, ssdeep, cdhash) can be independently enabled
  - `by_field_contains`: Array of tokens to search in field names
  - `exclude.exclude_trees`: Field prefixes to exclude for this specific algorithm

**Exclusion hierarchy for hash:**
1. Global `exclude_trees`
2. Hash-level `exclude.exclude_trees` (coming from hash configuration)
3. Algorithm-level `exclude.exclude_trees`

All three levels are merged (union) when filtering fields.

**Generated output:**
```json
"hash_md5": {
  "sources": ["file.hash.md5", "process.hash.md5", "dll.hash.md5"]
},
"hash_sha256": {
  "sources": ["file.hash.sha256", "process.hash.sha256"]
}
```

#### Complete Example Configuration

```json
{
  "global": {
    "exclude_trees": [
      "threat.indicator",
      "threat.enrichments"
    ]
  },
  "types": {
    "connection": {
      "enabled": true,
      "include": {
        "sibling_pair_rule": {
          "ip_field_names": ["ip"],
          "port_field_names": ["port"]
        }
      },
      "exclude": {
        "exclude_trees": ["observer"]
      }
    },
    "url_full": {
      "enabled": true,
      "include": {
        "explicit_fields": ["url.full", "url.original"]
      },
      "exclude": {
        "exclude_trees": []
      }
    },
    "url_domain": {
      "enabled": true,
      "include": {
        "by_field_contains": ["domain", "subdomain"],
        "explicit_fields": ["host.name"]
      },
      "exclude": {
        "exclude_trees": []
      }
    },
    "hash": {
      "enabled": true,
      "exclude": {
        "exclude_trees": []
      },
      "algorithms": {
        "md5": {
          "enabled": true,
          "include": {
            "by_field_contains": ["hash.md5"]
          }
        },
        "sha256": {
          "enabled": true,
          "include": {
            "by_field_contains": ["hash.sha256"]
          }
        }
      }
    }
  }
}
```

#### Usage Example

```bash
# Generate enrichment configurations with IOC support
engine-schema generate \
  --wcs-path /path/to/wcs.yml \
  --output-dir ./output \
  --decoder-template /path/to/wazuh-decoders.template.json \
  --ioc-enrichment-cfg /path/to/ioc-enrichment-cfg.json

# This will generate enrichment-ioc.json containing all source fields to check
```

#### Tips and Best Practices

1. **Exclude false positives**: Use `exclude_trees` to avoid checking fields that aren't relevant (e.g., observer IPs, internal metadata)

2. **Domain filtering**: The `by_description_exact` filter for `url_domain` is crucial to exclude Active Directory domain fields (like `user.domain`) which aren't internet domains

3. **Performance**: Only enable the hash algorithms you need. Checking every hash field against all algorithms can impact performance

4. **Field discovery**: Use `by_field_contains` to automatically discover relevant fields. For example, `"by_field_contains": ["hash.md5"]` will find all fields like `file.hash.md5`, `process.hash.md5`, `dll.hash.md5`, etc.

5. **Testing**: After generating `enrichment-ioc.json`, review the output to ensure only relevant fields are included
