# Description

The following sections present representative examples of the supported modules in the WCS schema.

## FIM

## Inventory

### Ports

This is an example of the indexed ports format:

```json
{
    "agent": {
        "id": "002",
        "name": "b593602240f5",
        "version": "v4.11.1",
        "ip": "any"
    },
    "destination": {
        "ip": "0.0.0.0",
        "port": 0
    },
    "file": {
        "inode": "15526675"
    },
    "host": {
        "network": {
            "egress": {
                "queue": 0
            },
            "ingress": {
                "queue": 0
            }
        }
    },
    "interface": {
        "state": "listening"
    },
    "network": {
        "transport": "tcp"
    },
    "process": {
        "name": "python3",
        "pid": 6124
    },
    "source": {
        "ip": "0.0.0.0",
        "port": 8000
    }
```

### Hardware

This is an example of the indexed hardware format:

```json
{
  "agent": {
    "id": "002",
    "ip": "any",
    "name": "b593602240f5",
    "version": "v4.11.1"
  },
  "host": {
    "cpu": {
      "cores": 12,
      "name": "Intel(R) Core(TM) i5-10500H CPU @ 2.50GHz",
      "speed": 2501
    },
    "memory": {
      "free": 5289812,
      "total": 16286860,
      "used": 68286860
    },
    "observer": {
      "serial_number": "PF3JXBEZ"
    }
  }
}
```

### Hotfixes

Here is an example of the indexed hotfixes format. The event ID consists of the agent ID and the hotfix ID.

```json
{
  "id": "001_KB12345",
  "operation": "INSERTED",
  "data": {
    "package": {
      "hotfix": {
        "name": "KB12345"
      }
    },
    "agent": {
      "id": "001",
      "name": "agentName",
      "ip": "agentIp",
      "version": "agentVersion"
    }
  }
}
```
