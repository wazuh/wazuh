# Data Provider Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-use-the-tool)

## Purpose
The Data Provider Testing Tool was created to test and validate the data obtained by the module's execution. This tool works as a black box where an user will be able execute it and analyze the output data as desired.

## Compile Wazuh
In order compile the solution on a specific wazuh target, the project needs to be built either in os_kernel_release or debug mode.
```
make TARGET=server|agent <DEBUG=1>
```

## How to use the tool
```
Usage: sysinfo_test_tool [options]
```

The information output will vary based on the Operating System the tool is being executed.
A brief example could be similar to the following one:

```
{"users":[{"host_ip":null,"login_status":null,"login_tty":null,"login_type":null,"process_pid":null,"user_auth_failed_count":null,"user_auth_failed_timestamp":null,"user_created":null,"user_full_name":"","user_group_id":999,"user_group_id_signed":999,"user_groups":null,"user_home":"/var/ossec","user_id":998,"user_is_hidden":null,"user_is_remote":1,"user_last_login":null,"user_name":"wazuh","user_password_expiration_date":-1,"user_password_hash_algorithm":null,"user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":-1,"user_password_min_days_between_changes":-1,"user_password_status":"locked","user_password_warning_days_before_expiration":-1,"user_roles_sudo":0,"user_shell":"/sbin/nologin","user_type":null,"user_uid_signed":998,"user_uuid":null}]}
[{"hotfix_name":"KB12345678"},{"hotfix_name":"KB87654321"}]
{"serial_number":" ","cpu_cores":6,"cpu_speed":801.0,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","memory_free":4659652,"memory_total":32746472,"memory_used":86}
[{"architecture":"amd64","description":"query and manipulate user account information\n The AccountService project provides a set of D-Bus\n interfaces for querying and manipulating user account\n information and an implementation of these interfaces,\n based on the useradd, usermod and userdel commands.","type":"deb","category":"admin","multiarch":" ","name":"accountsservice","priority":"optional","size":"452","source":" ","vendor":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","version_":"0.6.55-0ubuntu12~20.04.4"}],
[{"args":"splash","args_count":1,"command_line":"/sbin/init","name":"systemd","pid":"1","parent_pid":0,"start":23,"state":"S","stime":11365,"utime":1005},{"args":"","args_count":0,"command_line":"","name":"kthreadd","pid":"2","parent_pid":0,"start":23,"state":"S","stime":7,"utime":0}],
{"iface":[{"interface_alias":" ","network_gateway":" ","host_mac":"d4:5d:64:51:07:5d","interface_mtu":"1500","interface_name":"enp4s0","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_state":"down","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"interface_type":"ethernet"},{"interface_alias":" ","network_gateway":" ","host_mac":"0a:00:27:00:00:00","interface_mtu":"1500","interface_name":"vboxnet0","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_state":"down","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"interface_type":"ethernet"},{"IPv4":{"network_ip":"192.168.92.1","network_broadcast":"192.168.92.255","network_dhcp":"unknown","network_metric":"0","network_netmask":"255.255.255.0"},"IPv6":{"network_ip":"fe80::250:56ff:fec0:1","network_broadcast":"","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}}]},
{"architecture":"x86_64","host_name":"martin-PC","os_codename":"focal","os_major":"20","os_minor":"04","os_name":"Ubuntu","os_patch":"2","os_platform":"ubuntu","os_version":"20.04.2 LTS (Focal Fossa)","os_kernel_release":"5.4.0-65-generic","os_kernel_name":"Linux","os_kernel_version":"#73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021"},
{"architecture":"x86_64","host_name":"martin-PC","os_codename":"focal","os_major":"20","os_minor":"04","os_name":"Ubuntu","os_patch":"2","os_platform":"ubuntu","os_version":"20.04.2 LTS (Focal Fossa)","os_kernel_release":"5.4.0-65-generic","os_kernel_name":"Linux","os_kernel_version":"#73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021"}
```

### Optional arguments:

|Argument|Description|
|---|---|
| `--hardware`     			| Prints the current Operating System hardware information only. Example: `sysinfo_test_tool --hardware`                               |
| `--networks`     			| Prints the current Operating System networks information only. Example: `sysinfo_test_tool --networks`                               |
| `--packages`     			| Prints the current Operating System packages information only. Example: `sysinfo_test_tool --packages`                               |
| `--processes`    			| Prints the current Operating System processes information only. Example: `sysinfo_test_tool --processes`                             |
| `--packages-cb`  			| Prints the current Operating System packages information only with callbacks mechanism. Example: `sysinfo_test_tool --packages-cb`   |
| `--processes-cb` 			| Prints the current Operating System processes information only with callbacks mechanism. Example: `sysinfo_test_tool --processes-cb` |
| `--ports`        			| Prints the current Operating System ports information only. Example: `sysinfo_test_tool --ports`                                     |
| `--os`           			| Prints the current Operating System information only. Example: `sysinfo_test_tool --os`                                              |
| `--hotfixes`     			| Prints the current Operating System hotfixes information only. Example: `sysinfo_test_tool --hotfixes`                               |
| `--groups`       			| Prints the current Operating System groups information only. Example: `sysinfo_test_tool --groups`                                   |
| `--users`        			| Prints the current Operating System users information only. Example: `sysinfo_test_tool --users`                                     |
| `--services`     			| Prints the current Operating System services information only. Example: `sysinfo_test_tool --services`                               |

| `--browser-extensions`    | Prints the current Operating System browser extensions information only. Example: `sysinfo_test_tool --browser-extensions`                                     |
