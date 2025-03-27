# Description

The following sections present representative examples of the supported modules in the WCS schema.

## FIM

## Inventory

### Network Protocol

Here is an example of the indexed Network Protocol format. The event ID consists of the agent ID and network interface ID.

```json
{
  "id": "001_92245c06b5120c62174799e7f531d4df81619672",
  "operation": "INSERTED",
  "data": {
    "agent": {
      "ip": "any",
      "id": "001",
      "name": "agent-10",
      "version": "5.4.0"
    },
    "network": {
      "dhcp": "enabled",
      "gateway": "192.168.1.1",
      "metric": "10",
      "type": "ethernet"
    },
    "observer": {
      "ingress": {
        "interface": {
          "name": "eth0"
        }
      }
    }
  }
}
```