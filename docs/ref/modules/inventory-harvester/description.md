# Description

The following sections present representative examples of the supported modules in the WCS schema.

## FIM

### Files

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "file": {
    "hash": {
      "md5": "9d7684f978ebd77e6a3ea7ef1330b946",
      "sha1": "3fa2d2963cbf47ffd5f7f5a9b4576f34ed42e552",
      "sha256": "6c96e976dc47e0c99b77814e560e0dc63161c463c75fa15b7a7ca83c11720e82"
    },
    "mtime": "2018-09-15T07:12:04.000Z",
    "owner": "TrustedInstaller",
    "path": "c:/windows/system32/winrm.vbs",
    "size": 204105,
    "uid": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
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
  "file": {
    "gid": "0",
    "group": "root",
    "hash": {
      "md5": "74467d237f18967c3e3bea1b3fd73d18",
      "sha1": "f6b8fa759e262a7550e321fc8e88a16dfed695c1",
      "sha256": "073c86e28fe5d5bf445aaa19a329dc4e464ab1a30c3b2ab997db8427b01917d3"
    },
    "mtime": "2023-08-24T20:37:40.000Z",
    "owner": "root",
    "path": "/usr/sbin/zramctl",
    "size": 57208,
    "uid": "0"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Registries

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.8.2"
  },
  "registry": {
    "data": {
      "hash": {
        "md5": "1819b148c3a26615f44690ea435b47fd",
        "sha1": "601c0c5d46a40ac2438acb307006640777b2e116",
        "sha256": "0dc8eaaf5819b9e20891b4b3dbcfa53091165df88f869bdc018ac0799c19af7e"
      },
      "type": "REG_SZ"
    },
    "hive": "HKLM",
    "key": "System/CurrentControlSet/Services/Processor",
    "path": "HKLM/System/CurrentControlSet/Services/Processor/DisplayName",
    "value": "DisplayName"
  },
  "wazuh": {
    "schema": {
      "version": "1.0"
    }
  }
}
```

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

### Groups

- Linux
```json
{
  "agent": {
    "id": "001",
    "name": "c9cc11ad8298",
    "version": "v4.14.0"
  },
  "group": {
    "id": 1000,
    "id_signed": 1000,
    "is_hidden": false,
    "name": "docker",
    "users": [
      "wazuh_user1"
    ]
  },
  "wazuh": {
    "cluster": {
      "name": "jammy"
    },
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.14.0"
  },
  "group": {
    "id": 1005,
    "id_signed": 1005,
    "is_hidden": false,
    "name": "devteam",
    "users": [
      "miguel"
    ],
    "uuid": "S-1-5-21-1333024871-3948894769-956662955-1005"
  },
  "wazuh": {
    "cluster": {
      "name": "jammy"
    },
    "schema": {
      "version": "1.0"
    }
  }
}
```

### Users

- Linux
```json
{
  "agent": {
    "id": "001",
    "name": "c9cc11ad8298",
    "version": "v4.14.0"
  },
  "login": {
    "status": false
  },
  "process": {
    "pid": 0
  },
  "user": {
    "auth_failures": {
      "count": 0
    },
    "group": {
      "id": 0,
      "id_signed": 0
    },
    "groups": [
      "root",
      "docker"
    ],
    "home": "/home/wazuh_user1",
    "id": "1000",
    "is_hidden": false,
    "is_remote": true,
    "name": "wazuh_user1",
    "password": {
      "last_change": 20270,
      "max_days_between_changes": 99999,
      "min_days_between_changes": 0,
      "status": "not_set",
      "warning_days_before_expiration": 7
    },
    "shell": "/bin/bash",
    "uid_signed": 1000
  },
  "wazuh": {
    "cluster": {
      "name": "jammy"
    },
    "schema": {
      "version": "1.0"
    }
  }
}
```

- Windows
```json
{
  "agent": {
    "id": "001",
    "name": "vagrant",
    "version": "v4.14.0"
  },
  "login": {
    "status": false
  },
  "process": {
    "pid": 0
  },
  "user": {
    "auth_failures": {
      "count": 0
    },
    "full_name": "Test user",
    "group": {
      "id": 1001,
      "id_signed": 1001
    },
    "groups": [
      "devteam"
    ],
    "id": "1006",
    "is_hidden": false,
    "is_remote": false,
    "name": "miguel",
    "password": {
      "inactive_days": 0,
      "last_change": 0,
      "max_days_between_changes": 0,
      "min_days_between_changes": 0,
      "warning_days_before_expiration": 0
    },
    "shell": "C:\\Windows\\system32\\cmd.exe",
    "type": "local",
    "uid_signed": 1006,
    "uuid": "S-1-5-21-1333024871-3948894769-956662955-1006"
  },
  "wazuh": {
    "cluster": {
      "name": "jammy"
    },
    "schema": {
      "version": "1.0"
    }
  }
}
```
