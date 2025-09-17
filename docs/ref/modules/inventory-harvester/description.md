# Description

The following sections present representative examples of the supported modules in the WCS schema.


## Inventory

### System

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "host": {
    "architecture": "x86_64",
    "hostname": "VAGRANT",
    "os": {
      "name": "Microsoft Windows Server 2019 Datacenter Evaluation",
      "platform": "windows",
      "version": "10.0.17763.7136"
    }
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "host": {
    "architecture": "x86_64",
    "hostname": "centos9",
    "os": {
      "kernel": {
        "name": "Linux",
        "release": "5.14.0-391.el9.x86_64",
        "version": "#1 SMP PREEMPT_DYNAMIC Tue Nov 28 20:35:49 UTC 2023"
      },
      "name": "CentOS Stream",
      "platform": "centos",
      "version": "9"
    }
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Packages

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "package": {
    "architecture": "x86_64",
    "description": " ",
    "name": "Microsoft Office Shared 64-bit MUI (English) 2016",
    "path": "C:\\Program Files (x86)\\Microsoft Office\\",
    "size": 0,
    "type": "win",
    "vendor": "Microsoft Corporation",
    "version": "16.0.4849.1000"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "package": {
    "architecture": "x86_64",
    "description": "pkgconf is a program which helps to configure compiler and linker flags\nfor development frameworks. It is similar to pkg-config from freedesktop.org\nand handles .pc files in a similar manner as pkg-config.",
    "installed": "2024-01-01T10:59:44.000Z",
    "name": "pkgconf",
    "path": " ",
    "size": 77890,
    "type": "rpm",
    "vendor": "CentOS",
    "version": "1.7.3-10.el9"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Processes

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "process": {
    "args_count": 0,
    "command_line": "C:/Program Files (x86)/ossec-agent/wazuh-agent.exe",
    "name": "wazuh-agent.exe",
    "parent": {
      "pid": 656
    },
    "pid": 7360,
    "start": "2025-04-15T16:01:12.000Z"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "process": {
    "args_count": 0,
    "command_line": "/var/ossec/bin/wazuh-modulesd",
    "name": "wazuh-modulesd",
    "parent": {
      "pid": 1
    },
    "pid": 6310,
    "start": "2025-04-15T16:01:02.000Z"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Ports

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "destination": {
    "ip": "::",
    "port": 0
  },
  "file": {
    "inode": "0"
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
    "transport": "tcp6"
  },
  "process": {
    "name": "svchost.exe",
    "pid": 2544
  },
  "source": {
    "ip": "::",
    "port": 49667
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "destination": {
    "ip": "10.0.2.2",
    "port": 67
  },
  "file": {
    "inode": "25109"
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
  "network": {
    "transport": "udp"
  },
  "process": {
    "name": "NetworkManager",
    "pid": 2586
  },
  "source": {
    "ip": "10.0.2.15",
    "port": 68
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Hardware

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "host": {
    "cpu": {
      "cores": 4,
      "name": "Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz",
      "speed": 2592
    },
    "memory": {
      "free": 1048576,
      "total": 2097152,
      "used": 1048576
    }
  },
  "observer": {
    "serial_number": "0"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "host": {
    "cpu": {
      "cores": 10,
      "name": "Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz",
      "speed": 2593
    },
    "memory": {
      "free": 1048576,
      "total": 2097152,
      "used": 1048576
    }
  },
  "observer": {
    "serial_number": "0"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Hotfixes

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "package": {
    "hotfix": {
      "name": "KB5055519"
    }
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Network Protocol

- Windows
```json
{
  "id": "001_92245c06b5120c62174799e7f531d4df81619672",
  "operation": "INSERTED",
  "data": {
    "agent": {
      "id": "001",
      "name": "vagrant",
      "version": "v4.8.2"
    },
    "network": {
      "dhcp": true,
      "gateway": "192.168.1.1",
      "metric": 10,
      "type": "ethernet"
    },
    "observer": {
      "ingress": {
        "interface": {
          "name": "Ethernet 2"
        }
      }
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "network": {
    "dhcp": false,
    "gateway": "10.0.2.2",
    "metric": 100,
    "type": "ipv4"
  },
  "observer": {
    "ingress": {
      "interface": {
        "name": "eth0"
      }
    }
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Network address

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "network": {
    "broadcast": "192.168.56.255",
    "ip": "192.168.56.234",
    "name": "Ethernet 2",
    "netmask": "255.255.255.0",
    "protocol": "IPv4"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "network": {
    "broadcast": "192.168.33.255",
    "ip": "192.168.33.65",
    "name": "eth1",
    "netmask": "255.255.255.0",
    "protocol": "IPv4"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Network interfaces

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "host": {
    "mac": "08:00:27:78:f6:3b",
    "network": {
      "egress": {
        "bytes": 85881,
        "drops": 0,
        "errors": 0,
        "packets": 895
      },
      "ingress": {
        "bytes": 97108,
        "drops": 0,
        "errors": 0,
        "packets": 477
      }
    }
  },
  "observer": {
    "ingress": {
      "interface": {
        "alias": "Intel(R) PRO/1000 MT Desktop Adapter #2",
        "mtu": 1500,
        "name": "Ethernet 2",
        "state": "up",
        "type": "ethernet"
      }
    }
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Linux
```json
{
  "agent": {
    "id": "002",
    "name": "centos9",
    "version": "v4.10.1"
  },
  "host": {
    "mac": "08:00:27:b7:39:4d",
    "network": {
      "egress": {
        "bytes": 3449046,
        "drops": 0,
        "errors": 0,
        "packets": 8806
      },
      "ingress": {
        "bytes": 1183041,
        "drops": 0,
        "errors": 0,
        "packets": 8363
      }
    }
  },
  "observer": {
    "ingress": {
      "interface": {
        "mtu": 1500,
        "name": "eth1",
        "state": "up",
        "type": "ethernet"
      }
    }
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```
