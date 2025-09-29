# API Reference

The Inventory Sync module indexes inventory state data into dedicated indices within the Wazuh-indexer (OpenSearch). The indexed data can be retrieved using the [OpenSearch API](https://opensearch.org/docs/latest/api-reference/).

For querying synchronized inventory data, use the **GET /wazuh-states-*/_search** endpoint pattern.

## Indexed Inventory Data

Below are examples of indexed inventory data following the [ECS](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) and Wazuh Common Schema standards.

### FIM

```json
{
  "_index": "wazuh-states-fim-files",
  "_id": "cluster_002_d9c5f609a163521eb09b8bce743db9459da8aa83",
  "_score": 1,
  "_source": {
    "agent": {
      "id": "002",
      "name": "Agent5",
      "version": "v5.0.0"
    },
    "wazuh": {
      "cluster": {
        "name": "cluster"
      }
    },
    "file": {
      "size": 8,
      "permissions": ["rw-r--r--"],
      "uid": "0",
      "owner": "root",
      "gid": "0",
      "group": "root",
      "inode": "27295851",
      "device": 66306,
      "mtime": 1758047355,
      "hash": {
        "md5": "ab05286b2ef828c7b73718820dd54059",
        "sha1": "c488e254383fe062674f85ba1792a74edb4e734b",
        "sha256": "550ad22979db6d54d9955ba4821600c3275b4bdab8000a16794a7a0f6682b980"
      },
      "path": "/etc/hostname"
    },
    "checksum": {
      "hash": {
        "sha1": "dc0885868e771736de8a2ae00197084ab5f35fe8"
      }
    },
    "state": {
      "modified_at": "2025-09-16T18:29:21.705Z"
    }
  }
}
```

### Packages

```json
{
  "_index": "wazuh-states-inventory-packages",
  "_id": "cluster_001_35e3099e76d12e2184b731541cf7feb7e9868708",
  "_score": 1.0,
  "_source": {
    "agent": { "id": "001", "name": "WIN-K9C7QDERVJB", "version": "v5.0.0" },
    "checksum": {
      "hash": { "sha1": "dc36e29d44215be742b174dc451c74dc02721821" }
    },
    "wazuh": {
      "cluster": {
        "name": "cluster"
      }
    },
    "package": {
      "architecture": null,
      "category": null,
      "description": null,
      "installed": null,
      "multiarch": null,
      "name": "Microsoft Clipchamp",
      "path": "C:\\Program Files\\WindowsApps\\Clipchamp.Clipchamp_4.3.10120.0_arm64__yxz26nhyzhsrt",
      "priority": null,
      "size": 0,
      "source": null,
      "type": "win",
      "vendor": "Microsoft Corp.",
      "version": "4.3.10120.0"
    },
    "state": { "modified_at": "2025-09-02T19:36:06.207Z" }
  }
}
```

### Network interfaces

```json
{
  "_index": "wazuh-states-inventory-interfaces",
  "_id": "cluster_002_a1c9127e81cd0d8bbb724f8a39f722d20e0d7f13",
  "_score": 1,
  "_source": {
    "agent": {
      "id": "002",
      "name": "Agent5",
      "version": "v5.0.0"
    },
    "wazuh": {
      "cluster": {
        "name": "cluster"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "1e2f3d846f7ea394368a16de07371922eefc7891"
      }
    },
    "host": {
      "mac": ["02:42:ac:11:00:02"],
      "network": {
        "egress": {
          "bytes": 3519214,
          "drops": 0,
          "errors": 0,
          "packets": 24620
        },
        "ingress": {
          "bytes": 62143044,
          "drops": 0,
          "errors": 0,
          "packets": 29517
        }
      }
    },
    "interface": {
      "alias": null,
      "mtu": 1500,
      "name": "eth0",
      "state": "up",
      "type": "ethernet"
    },
    "state": {
      "modified_at": "2025-09-16T19:13:26.061Z"
    }
  }
}
```

### Users

```json
{
  "_index": "wazuh-states-inventory-users",
  "_id": "cluster_002_dc76e9f0c0006e8f919e0c515c66dbba3982f785",
  "_score": 1,
  "_source": {
    "agent": {
      "id": "002",
      "name": "Agent5",
      "version": "v5.0.0"
    },
    "wazuh": {
      "cluster": {
        "name": "cluster"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "113445addd4361184d6175fcd52e678679b43ce6"
      }
    },
    "host": {
      "ip": null
    },
    "login": {
      "status": false,
      "tty": null,
      "type": null
    },
    "process": {
      "pid": 0
    },
    "state": {
      "modified_at": "2025-09-16T19:13:26.087Z"
    },
    "user": {
      "auth_failures": {
        "count": 0,
        "timestamp": 0
      },
      "created": 0,
      "full_name": "root",
      "group": {
        "id": 0,
        "id_signed": 0
      },
      "groups": ["root"],
      "home": "/root",
      "id": 0,
      "is_hidden": false,
      "is_remote": true,
      "last_login": 0,
      "name": "root",
      "password": {
        "expiration_date": -1,
        "hash_algorithm": null,
        "inactive_days": -1,
        "last_change": 1748563200,
        "max_days_between_changes": 99999,
        "min_days_between_changes": 0,
        "status": "locked",
        "warning_days_before_expiration": 7
      },
      "roles": null,
      "shell": "/bin/bash",
      "type": null,
      "uid_signed": 0,
      "uuid": null
    }
  }
}
```

### Groups

```json
{
  "_index": "wazuh-states-inventory-groups",
  "_id": "cluster_002_42ef63e7836ef622d9185c1a456051edf16095cc",
  "_score": 1,
  "_source": {
    "agent": {
      "id": "002",
      "name": "Agent5",
      "version": "v5.0.0"
    },
    "wazuh": {
      "cluster": {
        "name": "cluster"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "65ced8f9f749ef06b776a250fb50defd7d22cb78"
      }
    },
    "group": {
      "description": null,
      "id": 4,
      "id_signed": 4,
      "is_hidden": false,
      "name": "adm",
      "users": null,
      "uuid": null
    },
    "state": {
      "modified_at": "2025-09-16T19:13:26.083Z"
    }
  }
}
```

### System

```json
{
  "_index": "wazuh-states-inventory-system-batman",
  "_id": "001_a1c366cacdc2e4f2ca5e9f514afccf66ad1dfa3e",
  "_score": 1,
  "_source": {
    "agent": {
      "id": "001",
      "name": "Agent5",
      "version": "v5.0.0"
    },
    "wazuh": {
      "cluster": {
        "name": "batman"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "2e212691188e6a538ef445bfa41b4168b8f89276"
      }
    },
    "host": {
      "architecture": "x86_64",
      "hostname": "Agent5",
      "os": {
        "build": null,
        "codename": "jammy",
        "distribution": {
          "release": null
        },
        "full": null,
        "kernel": {
          "name": "Linux",
          "release": "6.12.38+kali-amd64",
          "version": "#1 SMP PREEMPT_DYNAMIC Kali 6.12.38-1kali1 (2025-08-12)"
        },
        "major": "22",
        "minor": "04",
        "name": "Ubuntu",
        "patch": "5",
        "platform": "ubuntu",
        "version": "22.04.5 LTS (Jammy Jellyfish)"
      }
    },
    "state": {
      "modified_at": "2025-09-15T18:51:57.806Z"
    }
  }
}
```

### Networks

```json
{
  "_index": "wazuh-states-inventory-networks-batman",
  "_id": "001_5aeb83e81e61130c0ade1f91e33119ff0441dddc",
  "_score": 1,
  "_source": {
    "agent": {
      "id": "001",
      "name": "Agent5",
      "version": "v5.0.0"
    },
    "wazuh": {
      "cluster": {
        "name": "batman"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "8a1dca4dbd45c6a66f13b5e253fe3ba9485ed8fc"
      }
    },
    "interface": {
      "name": "eth0"
    },
    "network": {
      "broadcast": "172.17.255.255",
      "ip": "172.17.0.2",
      "netmask": "255.255.0.0",
      "type": 0
    },
    "state": {
      "modified_at": "2025-09-15T18:51:57.809Z"
    }
  }
}
```
