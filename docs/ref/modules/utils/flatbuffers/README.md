# Flatbuffers

Various modules, such as the Vulnerability Detector and Inventory Harvester, use FlatBuffers. FlatBuffers is a library that enables high-performance data serialization and deserialization without the need of unpacking or parsing, providing direct access to the required information.

Although the synchronization events received by Remoted are in JSON format, they require to augmentate the event data with additional **agent context** within this module. As a result, deserializing and re-serializing the data becomes unavoidable. Given this requirement, the augmented synchronization events—processed through dbsync and rsync—are converted to FlatBuffers.

Another key use of FlatBuffers in the Vulnerability Detector module is for processing vulnerability feeds, specifically those following the CVE5 schema. In this case, FlatBuffers are used to avoid the deserialization overhead during scanning.

Due to the nature of FlatBuffers, the deserialization cost is significantly lower compared to JSON, regardless of the JSON library used. This makes FlatBuffers particularly well-suited for scanning operations, where deserialization performance is a critical factor.

For the inventory harvester the data is converted into FlatBuffers and send it to wazuh-modulesd through the router module(IPC).

## Flatbuffer schemas

### Common AgentInfo table
- Common agent information for FIM Delta, Inventory Delta and Synchronization events.

| Table         | Field          | Type       | Description |
|---------------|----------------|------------|-------------|
| **AgentInfo** | agent_id       | string     | Unique identifier of the agent, e.g., "001". |
|               | agent_ip       | string     | IP address of the agent. |
|               | agent_name     | string     | Name assigned to the agent. |
|               | agent_version  | string     | Version of the agent software, e.g., "v4.10.2". |


### FIM Delta table
- Main table in flatbuffer schema for FIM Delta events.

| Table        | Field          | Type       | Description |
|--------------|----------------|------------|-------------|
| **Delta**    | agent_info     | AgentInfo  | Metadata about the agent generating the event. |
|              | data_type      | string     | Nature of the event, e.g., "event". |
|              | data           | Data       | Detailed data about the detected change. |


### FIM Data table
- Data table for FIM delta events.

| Table        | Field          | Type       | Description |
|--------------|----------------|------------|-------------|
| **Data**     | attributes     | Attributes | Detailed attributes of the event. |
|              | path           | string     | Absolute file path or full registry key path. |
|              | index          | string     | Index of the entity. |
|              | mode           | string     | Monitoring mode, either "Scheduled" or "Realtime". |
|              | type           | string     | Type of change detected, e.g., "added", "modified", "deleted". |
|              | arch           | string     | Registry architecture type, e.g., "[x86]", "[x64]". |
|              | timestamp      | long       | Timestamp when the event was generated. |
|              | value_name     | string     | Name of the registry value. |


### FIM Attributes table
- Attributes table for FIM delta events.

| Table          | Field        | Type       | Description |
|----------------|--------------|------------|-------------|
| **Attributes** | type         | string     | Type of monitored entity, e.g., "registry_value", "registry_key", "file". |
|                | uid          | string     | User ID associated with the entity. |
|                | user_name    | string     | Name of the owner of the entity (user). |
|                | gid          | string     | Group ID associated with the entity. |
|                | group_name   | string     | Name of the group that owns the entity. |
|                | inode        | long       | Inode number (only applicable for file events). |
|                | mtime        | long       | Last modified timestamp of the entity. |
|                | size         | long       | Size of the file or registry value (in bytes). |
|                | value_type   | string     | Type of the registry value, e.g., "REG_SZ", "REG_DWORD". |
|                | value_name   | string     | Name of the registry value. |
|                | hash_md5     | string     | MD5 hash of the file or registry value content. |
|                | hash_sha1    | string     | SHA-1 hash of the file or registry value content. |
|                | hash_sha256  | string     | SHA-256 hash of the file or registry value content. |


### Inventory Delta table
- Main table in flatbuffer schema for inventory Delta events.

| Table                        | Field              | Type      | Description |
|------------------------------|--------------------|-----------|-------------|
| **Delta**                    | agent_info         | AgentInfo | Information about the agent. |
|                              | data               | Provider  | Data changes in the agent. |
|                              | operation          | string    | Type of operation performed (e.g., INSERTED, MODIFIED, DELETED). |


### Inventory Provider union table
- Provider union table for inventory delta events.

| Table                        | Type                    | Description |
|------------------------------|-------------------------|-------------|
| **Provider** (Union)         | dbsync_network_iface    | Network interfaces description. |
|                              | dbsync_network_protocol | Network protocol configuration for detected interfaces. |
|                              | dbsync_network_address  | Network address information for detected interfaces. |
|                              | dbsync_osinfo           | Host operating system. |
|                              | dbsync_hwinfo           | Hardware information. |
|                              | dbsync_ports            | Listening ports. |
|                              | dbsync_packages         | Installed packages. |
|                              | dbsync_hotfixes         | Installed hotfixes. |
|                              | dbsync_processes        | Running processes. |


### Inventory providers
- Provider tables for inventory delta events.

| Table                        | Field              | Type      | Description |
|------------------------------|--------------------|-----------|-------------|
| **dbsync_hotfixes**          | hotfix             | string    | Name or identifier of the applied hotfix. |
| **dbsync_hwinfo**            | board_serial       | string    | Serial number of the motherboard. |
|                              | cpu_name           | string    | Name/model of the CPU. |
|                              | cpu_cores          | long      | Number of CPU cores. |
|                              | cpu_mhz            | double    | CPU clock speed in MHz. |
|                              | ram_total          | long      | Total RAM available in the system (MB). |
|                              | ram_free           | long      | Free RAM available in the system (MB). |
|                              | ram_usage          | long      | RAM usage in percentage. |
| **dbsync_network_address**   | iface              | string    | Network interface name. |
|                              | proto              | long      | Protocol type (e.g., IPv4, IPv6). |
|                              | address            | string    | Assigned IP address. |
|                              | netmask            | string    | Subnet mask of the interface. |
|                              | broadcast          | string    | Broadcast address. |
|                              | item_id            | string    | Unique identifier for the network address entry. |
|                              | metric             | string    | Interface metric for routing decisions. |
|                              | dhcp               | string    | Indicates whether DHCP is enabled (yes/no). |
| **dbsync_network_iface**     | name               | string    | Interface name. |
|                              | adapter            | string    | Adapter type (e.g., Ethernet, WiFi). |
|                              | type               | string    | Network interface type. |
|                              | state              | string    | Current state (e.g., up, down). |
|                              | mtu                | long      | Maximum Transmission Unit (MTU). |
|                              | mac                | string    | MAC address of the interface. |
|                              | tx_packets         | long      | Number of transmitted packets. |
|                              | rx_packets         | long      | Number of received packets. |
|                              | tx_bytes           | long      | Number of bytes transmitted. |
|                              | rx_bytes           | long      | Number of bytes received. |
|                              | tx_errors          | long      | Number of transmission errors. |
|                              | rx_errors          | long      | Number of reception errors. |
|                              | tx_dropped         | long      | Number of dropped outgoing packets. |
|                              | rx_dropped         | long      | Number of dropped incoming packets. |
|                              | item_id            | string    | Unique identifier for the interface entry. |
| **dbsync_network_protocol**  | iface              | string    | Interface name. |
|                              | type               | string    | Protocol type (e.g., static, dynamic). |
|                              | gateway            | string    | Default gateway address. |
|                              | dhcp               | string    | Indicates if DHCP is used (yes/no). |
|                              | metric             | string    | Routing metric value. |
|                              | item_id            | string    | Unique identifier for the protocol entry. |
| **dbsync_osinfo**            | hostname           | string    | System hostname. |
|                              | architecture       | string    | CPU architecture (e.g., x86_64, ARM). |
|                              | os_name            | string    | Operating system name. |
|                              | os_version         | string    | Full OS version. |
|                              | os_codename        | string    | OS codename (if applicable). |
|                              | os_major           | string    | Major version number. |
|                              | os_minor           | string    | Minor version number. |
|                              | os_patch           | string    | Patch level of the OS. |
|                              | os_build           | string    | Build number of the OS. |
|                              | os_platform        | string    | Platform name (e.g., Debian, RedHat). |
|                              | sysname            | string    | System kernel name. |
|                              | release            | string    | Kernel release version. |
|                              | version            | string    | Kernel version. |
|                              | os_release         | string    | Distribution-specific release information. |
|                              | os_display_version | string    |  Human-readable OS version. |
| **dbsync_ports**             | protocol           | string    | Transport protocol (TCP/UDP). |
|                              | local_ip           | string    | Local IP address. |
|                              | local_port         | long      | Local port number. |
|                              | remote_ip          | string    | Remote IP address. |
|                              | remote_port        | long      | Remote port number. |
|                              | tx_queue           | long      | Transmit queue length. |
|                              | rx_queue           | long      | Receive queue length. |
|                              | inode              | long      | Inode associated with the connection. |
|                              | state              | string    | Connection state (e.g., LISTEN, ESTABLISHED). |
|                              | pid                | long      | Process ID using the port. |
|                              | process            | string    | Name of the process using the port. |
|                              | item_id            | string    | Unique identifier for the port entry. |
| **dbsync_processes**         | pid                | string    | Process ID. |
|                              | name               | string    | Process name. |
|                              | state              | string    | Current process state. |
|                              | ppid               | long      | Parent process ID. |
|                              | utime              | long      | User mode CPU time used. |
|                              | stime              | long      | System mode CPU time used. |
|                              | cmd                | string    | Command executed by the process. |
|                              | argvs              | string    | Arguments passed to the process. |
|                              | euser              | string    | Efective user. |
|                              | ruser              | string    | Real user. |
|                              | suser              | string    | Saved-set user. |
|                              | egroup             | string    | Effective group. |
|                              | rgroup             | string    | Real group. |
|                              | sgroup             | string    | Saved-set group. |
|                              | fgroup             | string    | Filesystem group name. |
|                              | priority           | long      | Kernel scheduling priority. |
|                              | nice               | long      | Nice value of the process. |
|                              | size               | long      | Total size of the process. |
|                              | vm_size            | long      | Total VM size (KB). |
|                              | resident           | long      | Resident set size of the process (KB). |
|                              | share              | long      | Shared memory. |
|                              | start_time         | long      | Time when the process started. |
|                              | pgrp               | long      | Process group. |
|                              | session            | long      | Session of the process. |
|                              | nlwp               | long      | Number of light weight processes. |
|                              | tgid               | long      | Thread Group ID. |
|                              | tty                | long      | Number of TTY of the process. |
|                              | processor          | long      | Number of the processor. |
| **dbsync_packages**          | name               | string    | Package name. |
|                              | version            | string    | Package version. |
|                              | vendor             | string    | Vendor or maintainer of the package. |
|                              | install_time       | string    | Installation timestamp. |
|                              | location           | string    | Path where the package is installed. |
|                              | architecture       | string    | Package architecture. |
|                              | groups             | string    | Package category or group. |
|                              | description        | string    | Description of the package. |
|                              | size               | long      | Size of the package in bytes. |
|                              | priority           | string    | Priority of the package. |
|                              | multiarch          | string    | Multiarchitecture support. |
|                              | source             | string    | Source of the package. |
|                              | format             | string    | Format of the package. |
|                              | item_id            | string    | Unique identifier for the package entry. |


### SyncMsg table
- Main table in flatbuffer schema for synchronization events.

| Table                        | Field              | Type      | Description |
|------------------------------|--------------------|-----------|-------------|
| **SyncMsg**                  | agent_info         | AgentInfo | Event type description. |
|                              | data               | DataUnion | Data changes in the agent. |


### DataUnion table union
- DataUnion table union for synchronization events.

| Table                        | Type                    | Description |
|------------------------------|-------------------------|-------------|
| **DataUnion** (Union)        | state                   | Network interfaces description. |
|                              | integrity_check_global  | Network protocol configuration for detected interfaces. |
|                              | integrity_check_left    | Network address information for detected interfaces. |
|                              | integrity_check_right   | Host operating system. |
|                              | integrity_clear         | Hardware information. |


### State table
- State event type for synchronization events.

| Table                        | Field                   | Type            | Description |
|------------------------------|-------------------------|-----------------|-------------|
| **state**                    | attributes              | AttributesUnion | Aggregated attributes of the entity. |
|                              | index                   | string          | Index of the entity. |
|                              | path                    | string          | Absolute path of the file or registry entry. |
|                              | value_name              | string          | Name of the registry value. |
|                              | arch                    | string          | System architecture (x86, x64). |


### AttributesUnion table union
- Different event component types for synchronization events.

| Table                        | Type                            | Description |
|------------------------------|---------------------------------|-------------|
| **AttributesUnion**          | syscollector_hotfixes           | Equivalent to dbsync_programs. |
|                              | syscollector_hwinfo             | Equivalent to dbsync_hwinfo . |
|                              | syscollector_network_address    | Equivalent to dbsync_network_address . |
|                              | syscollector_network_iface      | Equivalent to dbsync_iface . |
|                              | syscollector_network_protocol   | Equivalent to dbsync_protocol . |
|                              | syscollector_osinfo             | Equivalent to dbsync_osinfo . |
|                              | syscollector_packages           | Equivalent to dbsync_packages . |
|                              | syscollector_ports              | Equivalent to dbsync_ports . |
|                              | syscollector_processes          | Equivalent to dbsync_processes . |
|                              | fim_file                        | File monitoring. |
|                              | fim_registry_key                | Registry monitoring key. |
|                              | fim_registry_value              | Registry monitoring value. |


### fim_file table
- fim_file table for file monitoring in synchronization events.

| Table                          | Field          | Type      | Description |
|--------------------------------|----------------|-----------|-------------|
| **fim_file**                   | gid            | string    | Group ID associated with the file. |
|                                | group_name     | string    | Name of the group that owns the file. |
|                                | hash_md5       | string    | MD5 hash of the file content. |
|                                | hash_sha1      | string    | SHA-1 hash of the file content. |
|                                | hash_sha256    | string    | SHA-256 hash of the file content. |
|                                | inode          | long      | Inode number of the file. |
|                                | mtime          | long      | Last modified timestamp. |
|                                | size           | long      | File size in bytes. |
|                                | type           | string    | File type (e.g., directory, file, symlink). |
|                                | uid            | string    | User ID associated with the file. |
|                                | user_name      | string    | Name of the file owner. |


### fim_registry_key table
- fim_registry_key table for registry monitoring in synchronization events.

| Table                          | Field          | Type      | Description |
|--------------------------------|----------------|-----------|-------------|
| **fim_registry_key**           | gid            | string    | Group ID associated with the registry. |
|                                | group_name     | string    | Name of the group that owns the registry. |
|                                | mtime          | long      | Last modified timestamp. |
|                                | uid            | string    | User ID associated with the registry. |
|                                | type           | string    | Registry type. |
|                                | user_name      | string    | Name of the registry owner. |


### fim_registry_value
- fim_registry_value table for registry monitoring in synchronization events.

| Table                          | Field          | Type      | Description |
|--------------------------------|----------------|-----------|-------------|
| **fim_registry_value**         | hash_md5       | string    | MD5 hash of the registry content. |
|                                | hash_sha1      | string    | SHA-1 hash of the registry content. |
|                                | hash_sha256    | string    | SHA-256 hash of the registry content. |
|                                | size           | long      | Registry size in bytes. |
|                                | type           | string    | Registry type. |
