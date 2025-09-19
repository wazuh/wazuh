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

### Browser extensions

```json
{
  "agent": {
      "id": "002",
      "name": "centos9",
      "version": "v4.14.0"
  },
  "browser": {
      "name": "chrome",
      "profile": {
          "name": "Default",
          "path": "C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
          "referenced": true
      }
  },
  "file": {
      "hash": {
          "sha256": "a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234"
      }
  },
  "package": {
      "autoupdate": true,
      "build_version": "1.52.2",
      "description": "Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.",
      "enabled": true,
      "from_webstore": true,
      "id": "cjpalhdlnbpafiamejdnhcphjbkeiagm",
      "installed": "2024-03-15T08:03:41.000Z",
      "name": "UBlock Origin",
      "path": "C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0",
      "permissions": "[\\\"activeTab\\\",\\\"storage\\\",\\\"tabs\\\",\\\"webNavigation\\\"]",
      "persistent": true,
      "reference": "https://clients2.google.com/service/update2/crx",
      "type": "extension",
      "vendor": "Raymond Hill",
      "version": "1.52.2"
  },
  "user": {
      "id": "S-1-5-21-1234567890-987654321-1122334455-1001"
  },
  "wazuh": {
      "cluster": {
          "name": "cluster01"
      },
      "schema": {
          "version": "1.0"
      }
  }
}
```

### Services

```json
{
  "agent": {
    "id": "001",
    "name": "centos9",
    "version": "v4.14.0"
  },
  "file": {
    "path": "/usr/sbin/sshd"
  },
  "process": {
    "executable": "/usr/sbin/sshd",
    "pid": 1234
  },
  "service": {
    "description": "OpenSSH server daemon",
    "enabled": "enabled",
    "exit_code": 0,
    "id": "sshd",
    "name": "OpenSSH Daemon",
    "start_type": "enabled",
    "state": "running",
    "sub_state": "running",
    "type": "simple"
  },
  "user": {
    "name": "root"
  },
  "wazuh": {
    "cluster": {
      "name": "cluster01"
    },
    "schema": {
      "version": "1.0"
    }
  }
}
```
