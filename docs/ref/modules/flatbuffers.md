# Flatbuffers

Various modules, such as the Vulnerability Detector and Inventory Harvester, use FlatBuffers for efficient data serialization and deserialization. FlatBuffers is a data serialization library that enables high-performance serialization and deserialization.

Although the synchronization events received by Remoted are in JSON format, they require augmentation (adding agent context) within this module. As a result, deserializing and re-serializing the data becomes unavoidable. Given this requirement, the augmented synchronization events—processed through dbsync and rsync—are converted to FlatBuffers.

Another key use of FlatBuffers in the Vulnerability Detector module is for processing vulnerability feeds, specifically those following the CVE5 schema. In this case, FlatBuffers are used to avoid the deserialization overhead during scanning.

Due to the nature of FlatBuffers, the deserialization cost is significantly lower compared to JSON, regardless of the JSON library used. This makes FlatBuffers particularly well-suited for scanning operations, where deserialization performance is a critical factor.

For the inventory harvester the data is converted into FlatBuffers and send it to wazuh-modulesd through the router module(IPC).

## FlatBuffers schemas for FIM Delta events
| Table        | Field          | Type       | Description |
|-------------|--------------|------------|-------------|
| **AgentInfo** | agent_id     | string     | Unique identifier of the agent, e.g., "001". |
|             | agent_ip     | string     | IP address of the agent. |
|             | agent_name   | string     | Name assigned to the agent. |
|             | agent_version | string     | Version of the agent software, e.g., "v4.10.2". |
| **Attributes** | type        | string     | Type of monitored entity, e.g., "registry_value", "registry_key", "file". |
|             | uid          | string     | User ID associated with the entity. |
|             | user_name    | string     | Name of the owner of the entity (user). |
|             | gid          | string     | Group ID associated with the entity. |
|             | group_name   | string     | Name of the group that owns the entity. |
|             | inode        | ulong      | Inode number (only applicable for file events). |
|             | mtime        | ulong      | Last modified timestamp of the entity. |
|             | size         | ulong      | Size of the file or registry value (in bytes). |
|             | value_type   | string     | Type of the registry value, e.g., "REG_SZ", "REG_DWORD". |
|             | value_name   | string     | Name of the registry value. |
|             | hash_md5     | string     | MD5 hash of the file or registry value content. |
|             | hash_sha1    | string     | SHA-1 hash of the file or registry value content. |
|             | hash_sha256  | string     | SHA-256 hash of the file or registry value content. |
| **Data**    | attributes   | Attributes | Detailed attributes of the event. |
|             | path        | string     | Absolute file path or full registry key path. |
|             | mode        | string     | Monitoring mode, either "Scheduled" or "Realtime". |
|             | type        | string     | Type of change detected, e.g., "added", "modified", "deleted". |
|             | arch        | string     | Registry architecture type, e.g., "[x86]", "[x64]". |
|             | timestamp   | ulong      | Timestamp when the event was generated. |
| **Delta**   | agent_info  | AgentInfo  | Metadata about the agent generating the event. |
|             | data_type   | string     | Nature of the event, e.g., "event". |
|             | data        | Data       | Detailed data about the detected change. |


## FlatBuffers schemas for Inventory Delta events
| Table                        | Field              | Type     | Description |
|------------------------------|--------------------|----------|-------------|
| **dbsync_hotfixes**          | hotfix            | string   | Name or identifier of the applied hotfix. |
| **dbsync_hwinfo**            | board_serial      | string   | Serial number of the motherboard. |
|                              | cpu_name          | string   | Name/model of the CPU. |
|                              | cpu_cores         | int      | Number of CPU cores. |
|                              | cpu_mhz           | double   | CPU clock speed in MHz. |
|                              | ram_total         | int      | Total RAM available in the system (MB). |
|                              | ram_free          | int      | Free RAM available in the system (MB). |
|                              | ram_usage         | int      | RAM usage in percentage. |
| **dbsync_network_address**   | iface             | string   | Network interface name. |
|                              | proto             | int      | Protocol type (e.g., IPv4, IPv6). |
|                              | address           | string   | Assigned IP address. |
|                              | netmask           | string   | Subnet mask of the interface. |
|                              | broadcast         | string   | Broadcast address. |
|                              | item_id           | string   | Unique identifier for the network address entry. |
|                              | metric            | string   | Interface metric for routing decisions. |
|                              | dhcp              | string   | Indicates whether DHCP is enabled (yes/no). |
| **dbsync_network_iface**     | name              | string   | Interface name. |
|                              | adapter           | string   | Adapter type (e.g., Ethernet, WiFi). |
|                              | type              | string   | Network interface type. |
|                              | state             | string   | Current state (e.g., up, down). |
|                              | mtu               | long     | Maximum Transmission Unit (MTU). |
|                              | mac               | string   | MAC address of the interface. |
|                              | tx_packets        | long     | Number of transmitted packets. |
|                              | rx_packets        | long     | Number of received packets. |
|                              | tx_bytes          | long     | Number of bytes transmitted. |
|                              | rx_bytes          | long     | Number of bytes received. |
|                              | tx_errors         | long     | Number of transmission errors. |
|                              | rx_errors         | long     | Number of reception errors. |
|                              | tx_dropped        | long     | Number of dropped outgoing packets. |
|                              | rx_dropped        | long     | Number of dropped incoming packets. |
|                              | item_id           | string   | Unique identifier for the interface entry. |
| **dbsync_network_protocol**  | iface             | string   | Interface name. |
|                              | type              | string   | Protocol type (e.g., static, dynamic). |
|                              | gateway           | string   | Default gateway address. |
|                              | dhcp              | string   | Indicates if DHCP is used (yes/no). |
|                              | metric            | string   | Routing metric value. |
|                              | item_id           | string   | Unique identifier for the protocol entry. |
| **dbsync_osinfo**            | hostname          | string   | System hostname. |
|                              | architecture      | string   | CPU architecture (e.g., x86_64, ARM). |
|                              | os_name           | string   | Operating system name. |
|                              | os_version        | string   | Full OS version. |
|                              | os_codename       | string   | OS codename (if applicable). |
|                              | os_major          | string   | Major version number. |
|                              | os_minor          | string   | Minor version number. |
|                              | os_patch          | string   | Patch level of the OS. |
|                              | os_build          | string   | Build number of the OS. |
|                              | os_platform       | string   | Platform name (e.g., Debian, RedHat). |
|                              | sysname           | string   | System kernel name. |
|                              | release           | string   | Kernel release version. |
|                              | version           | string   | Kernel version. |
|                              | os_release        | string   | Distribution-specific release information. |
|                              | os_display_version | string  | Human-readable OS version. |
| **dbsync_ports**             | protocol          | string   | Transport protocol (TCP/UDP). |
|                              | local_ip          | string   | Local IP address. |
|                              | local_port        | long     | Local port number. |
|                              | remote_ip         | string   | Remote IP address. |
|                              | remote_port       | long     | Remote port number. |
|                              | tx_queue          | long     | Transmit queue length. |
|                              | rx_queue          | long     | Receive queue length. |
|                              | inode             | long     | Inode associated with the connection. |
|                              | state             | string   | Connection state (e.g., LISTEN, ESTABLISHED). |
|                              | pid               | long     | Process ID using the port. |
|                              | process           | string   | Name of the process using the port. |
|                              | item_id           | string   | Unique identifier for the port entry. |
| **dbsync_processes**         | pid               | string   | Process ID. |
|                              | name              | string   | Process name. |
|                              | state             | string   | Current process state. |
|                              | ppid              | long     | Parent process ID. |
|                              | utime             | long     | User mode CPU time used. |
|                              | stime             | long     | System mode CPU time used. |
|                              | cmd               | string   | Command executed by the process. |
|                              | argvs             | string   | Arguments passed to the process. |
| **dbsync_packages**          | name              | string   | Package name. |
|                              | version           | string   | Package version. |
|                              | vendor            | string   | Vendor or maintainer of the package. |
|                              | install_time      | string   | Installation timestamp. |
|                              | location          | string   | Path where the package is installed. |
|                              | architecture      | string   | Package architecture. |
|                              | groups            | string   | Package category or group. |
|                              | description       | string   | Description of the package. |
| **AgentInfo**                | agent_id          | string   | Unique ID of the agent. |
|                              | agent_ip          | string   | IP address of the agent. |
|                              | agent_name        | string   | Name of the agent. |
|                              | agent_version     | string   | Agent version. |
| **Delta**                    | agent_info        | AgentInfo | Information about the agent. |
|                              | data              | Provider  | Data changes in the agent. |
|                              | operation         | string   | Type of operation performed (e.g., INSERTED, MODIFIED, DELETED). |


## FlatBuffers schemas for Synchronization
| Table                          | Field              | Type       | Description |
|--------------------------------|--------------------|-----------|-------------|
| **AgentInfo**                  | agent_id          | string    | Unique identifier of the agent. |
|                                | agent_ip          | string    | IP address of the agent. |
|                                | agent_name        | string    | Name assigned to the agent. |
|                                | agent_version     | string    | Version of the agent software. |
| **syscollector_hotfixes**       | hotfix           | string    | Name or identifier of the applied hotfix. |
| **syscollector_hwinfo**         | board_serial     | string    | Serial number of the motherboard. |
|                                | cpu_cores        | int       | Number of CPU cores. |
|                                | cpu_mhz          | double    | CPU clock speed in MHz. |
|                                | cpu_name         | string    | Name/model of the CPU. |
|                                | ram_free         | int       | Available RAM (MB). |
|                                | ram_total        | int       | Total system RAM (MB). |
|                                | ram_usage        | int       | RAM usage percentage. |
| **syscollector_network_address**| address          | string    | IP address assigned to the interface. |
|                                | broadcast        | string    | Broadcast address of the interface. |
|                                | iface            | string    | Network interface name. |
|                                | item_id          | string    | Unique identifier for the network address entry. |
|                                | netmask          | string    | Subnet mask of the interface. |
|                                | proto            | int       | Network protocol (e.g., IPv4, IPv6). |
| **syscollector_network_iface**  | adapter         | string    | Type of network adapter (e.g., Ethernet, WiFi). |
|                                | item_id         | string    | Unique identifier for the network interface entry. |
|                                | mac             | string    | MAC address of the interface. |
|                                | mtu             | long      | Maximum Transmission Unit (MTU). |
|                                | name            | string    | Interface name. |
|                                | rx_bytes        | long      | Number of received bytes. |
|                                | rx_dropped      | long      | Number of dropped incoming packets. |
|                                | rx_errors       | long      | Number of receive errors. |
|                                | rx_packets      | long      | Number of received packets. |
|                                | state           | string    | Current interface state (e.g., up, down). |
|                                | tx_bytes        | long      | Number of transmitted bytes. |
|                                | tx_dropped      | long      | Number of dropped outgoing packets. |
|                                | tx_errors       | long      | Number of transmission errors. |
|                                | tx_packets      | long      | Number of transmitted packets. |
|                                | type            | string    | Interface type (e.g., wireless, wired). |
| **syscollector_network_protocol** | dhcp          | string    | Indicates if DHCP is used (yes/no). |
|                                | gateway        | string    | Default gateway address. |
|                                | iface          | string    | Network interface name. |
|                                | item_id        | string    | Unique identifier for the protocol entry. |
|                                | metric         | string    | Routing metric value. |
|                                | type           | string    | Protocol type (e.g., static, dynamic). |
| **syscollector_osinfo**         | architecture    | string    | System architecture (e.g., x86_64, ARM). |
|                                | hostname       | string    | System hostname. |
|                                | os_build       | string    | OS build version. |
|                                | os_codename    | string    | OS codename. |
|                                | os_display_version | string | Human-readable Windows OS version. |
|                                | os_major       | string    | Major OS version. |
|                                | os_minor       | string    | Minor OS version. |
|                                | os_name        | string    | Operating system name. |
|                                | os_patch       | string    | OS patch version. |
|                                | os_platform    | string    | Platform name (e.g., Debian, RedHat). |
|                                | os_release     | string    | OS release information. |
|                                | os_version     | string    | Full OS version. |
|                                | release        | string    | Kernel release version. |
|                                | sysname        | string    | Kernel name. |
|                                | version        | string    | Kernel version. |
| **syscollector_packages**       | architecture   | string    | Package architecture (e.g., x86_64, arm64). |
|                                | description    | string    | Description of the package. |
|                                | format         | string    | Package format (e.g., rpm, deb). |
|                                | groups         | string    | Package category or group. |
|                                | install_time   | string    | Installation timestamp. |
|                                | item_id        | string    | Unique identifier of the package. |
|                                | location       | string    | Path where the package is installed. |
|                                | multiarch      | string    | Multiarch compatibility flag. |
|                                | name           | string    | Package name. |
|                                | priority       | string    | Package priority (e.g., optional, required). |
|                                | size           | int       | Package size in bytes. |
|                                | source         | string    | Source package name. |
|                                | vendor         | string    | Vendor or maintainer of the package. |
|                                | version        | string    | Package version. |
| **syscollector_ports**          | inode          | long      | Inode associated with the connection. |
|                                | item_id        | string    | Unique identifier for the port entry. |
|                                | local_ip       | string    | Local IP address. |
|                                | local_port     | long      | Local port number. |
|                                | pid            | long      | Process ID using the port. |
|                                | process        | string    | Name of the process using the port. |
|                                | protocol       | string    | Transport protocol (TCP/UDP). |
|                                | remote_ip      | string    | Remote IP address. |
|                                | remote_port    | long      | Remote port number. |
|                                | rx_queue       | long      | Receive queue length. |
|                                | state          | string    | Connection state (e.g., LISTEN, ESTABLISHED). |
|                                | tx_queue       | long      | Transmit queue length. |
| **fim_file**                   | gid            | string    | Group ID associated with the file. |
|                                | group_name     | string    | Name of the group that owns the file. |
|                                | hash_md5       | string    | MD5 hash of the file content. |
|                                | hash_sha1      | string    | SHA-1 hash of the file content. |
|                                | hash_sha256    | string    | SHA-256 hash of the file content. |
|                                | inode          | ulong     | Inode number of the file. |
|                                | mtime          | ulong     | Last modified timestamp. |
|                                | size           | ulong     | File size in bytes. |
|                                | type           | string    | File type (e.g., directory, file, symlink). |
|                                | uid            | string    | User ID associated with the file. |
|                                | user_name      | string    | Name of the file owner. |
| **state**                      | attributes     | AttributesUnion | Aggregated attributes of the entity. |
|                                | index          | string    | Index of the entity. |
|                                | path           | string    | Absolute path of the file or registry entry. |
|                                | value_name     | string    | Name of the registry value. |
|                                | arch           | string    | System architecture (x86, x64). |
| **SyncMsg**                    | agent_info     | AgentInfo | Information about the agent. |
|                                | data           | DataUnion | Data related to synchronization. |
