# Database Schema

This document describes the database schema additions specific to Syscollector (Inventory) persistence implementation used by the Agent Sync Protocol.

---

## Overview

Syscollector uses a SQLite database with multiple tables to store different types of system inventory data. Each table is designed to track specific system components and their changes over time. The schema is defined in `src/wazuh_modules/syscollector/src/syscollectorTablesDef.hpp`.

---

## Database Tables

### Operating System Information (`dbsync_osinfo`)

Stores operating system details and characteristics.

```sql
CREATE TABLE dbsync_osinfo (
    hostname TEXT,
    architecture TEXT,
    os_name TEXT,
    os_version TEXT,
    os_codename TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_patch TEXT,
    os_build TEXT,
    os_platform TEXT,
    os_kernel_name TEXT,
    os_kernel_release TEXT,
    os_kernel_version TEXT,
    os_distribution_release TEXT,
    os_full TEXT,
    checksum TEXT,
    PRIMARY KEY (os_name)
) WITHOUT ROWID;
```

**Key Fields:**
- `os_name`: Primary key identifying the operating system
- `checksum`: Hash for change detection
- Various OS-specific version and build information

---

### Hardware Information (`dbsync_hwinfo`)

Stores hardware specifications and configuration.

```sql
CREATE TABLE dbsync_hwinfo (
    serial_number TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_speed DOUBLE,
    memory_total INTEGER,
    memory_free INTEGER,
    memory_used INTEGER,
    checksum TEXT,
    PRIMARY KEY (serial_number)
) WITHOUT ROWID;
```

**Key Fields:**
- `serial_number`: Primary key identifying hardware system
- `cpu_*`: CPU-related specifications
- `memory_*`: Memory usage information in bytes

---

### Software Packages (`dbsync_packages`)

Stores installed software packages and their metadata.

```sql
CREATE TABLE dbsync_packages(
    name TEXT,
    version TEXT,
    vendor TEXT,
    installed TEXT,
    path TEXT,
    architecture TEXT,
    category TEXT,
    description TEXT,
    size BIGINT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    type TEXT,
    checksum TEXT,
    PRIMARY KEY (name,version,architecture,type,path)
) WITHOUT ROWID;
```

**Key Fields:**
- Composite primary key: `(name,version,architecture,type,path)`
- `size`: Package size in bytes
- `installed`: Installation timestamp
- `type`: Package type (rpm, deb, msi, etc.)

---

### Network Interfaces (`dbsync_network_iface`)

Stores network interface configuration and statistics.

```sql
CREATE TABLE dbsync_network_iface (
    interface_name TEXT,
    interface_alias TEXT,
    interface_type TEXT,
    interface_state TEXT,
    interface_mtu INTEGER,
    host_mac TEXT,
    host_network_egress_packages INTEGER,
    host_network_ingress_packages INTEGER,
    host_network_egress_bytes INTEGER,
    host_network_ingress_bytes INTEGER,
    host_network_egress_errors INTEGER,
    host_network_ingress_errors INTEGER,
    host_network_egress_drops INTEGER,
    host_network_ingress_drops INTEGER,
    checksum TEXT,
    PRIMARY KEY (interface_name,interface_alias,interface_type)
) WITHOUT ROWID;
```

**Key Fields:**
- Composite primary key: `(interface_name,interface_alias,interface_type)`
- Traffic statistics: packets, bytes, errors, drops (ingress/egress)

---

### Network Protocol Configuration (`dbsync_network_protocol`)

Stores network protocol settings per interface.

```sql
CREATE TABLE dbsync_network_protocol (
    interface_name TEXT,
    network_type TEXT,
    network_gateway TEXT,
    network_dhcp INTEGER,
    network_metric TEXT,
    checksum TEXT,
    PRIMARY KEY (interface_name,network_type)
) WITHOUT ROWID;
```

---

### Network Addresses (`dbsync_network_address`)

Stores IP address assignments per interface.

```sql
CREATE TABLE dbsync_network_address (
    interface_name TEXT,
    network_type INTEGER,
    network_ip TEXT,
    network_netmask TEXT,
    network_broadcast TEXT,
    checksum TEXT,
    PRIMARY KEY (interface_name,network_type,network_ip)
) WITHOUT ROWID;
```

---

### Open Ports (`dbsync_ports`)

Stores information about open ports and listening services.

```sql
CREATE TABLE dbsync_ports (
    network_transport TEXT,
    source_ip TEXT,
    source_port BIGINT,
    destination_ip TEXT,
    destination_port BIGINT,
    host_network_egress_queue BIGINT,
    host_network_ingress_queue BIGINT,
    file_inode BIGINT,
    interface_state TEXT,
    process_pid BIGINT,
    process_name TEXT,
    checksum TEXT,
    PRIMARY KEY (file_inode, network_transport, source_ip, source_port)
) WITHOUT ROWID;
```

**Key Fields:**
- Composite primary key: `(file_inode, network_transport, source_ip, source_port)`
- Links ports to processes via `process_pid` and `process_name`

---

### Running Processes (`dbsync_processes`)

Stores information about running processes.

```sql
CREATE TABLE dbsync_processes (
    pid TEXT,
    name TEXT,
    state TEXT,
    parent_pid BIGINT,
    utime BIGINT,
    stime BIGINT,
    command_line TEXT,
    args TEXT,
    args_count BIGINT,
    start BIGINT,
    checksum TEXT,
    PRIMARY KEY (pid)
) WITHOUT ROWID;
```

**Key Fields:**
- `pid`: Process ID (primary key)
- `utime`/`stime`: CPU time usage
- `start`: Process start timestamp

---

### System Users (`dbsync_users`)

Stores user account information and authentication details.

```sql
CREATE TABLE dbsync_users (
    user_name TEXT,
    user_full_name TEXT,
    user_home TEXT,
    user_id BIGINT,
    user_uid_signed BIGINT,
    user_uuid TEXT,
    user_groups TEXT,
    user_group_id BIGINT,
    user_group_id_signed BIGINT,
    user_created DOUBLE,
    user_roles TEXT,
    user_shell TEXT,
    user_type TEXT,
    user_is_hidden INTEGER,
    user_is_remote INTEGER,
    user_last_login BIGINT,
    user_auth_failed_count BIGINT,
    user_auth_failed_timestamp DOUBLE,
    user_password_last_change DOUBLE,
    user_password_expiration_date INTEGER,
    user_password_hash_algorithm TEXT,
    user_password_inactive_days INTEGER,
    user_password_max_days_between_changes INTEGER,
    user_password_min_days_between_changes INTEGER,
    user_password_status TEXT,
    user_password_warning_days_before_expiration INTEGER,
    process_pid BIGINT,
    host_ip TEXT,
    login_status INTEGER,
    login_tty TEXT,
    login_type TEXT,
    checksum TEXT,
    PRIMARY KEY (user_name)
) WITHOUT ROWID;
```

**Key Fields:**
- `user_name`: Primary key
- Extensive password policy and authentication tracking
- Login session information

---

### System Groups (`dbsync_groups`)

Stores system group information and membership.

```sql
CREATE TABLE dbsync_groups (
    group_id BIGINT,
    group_name TEXT,
    group_description TEXT,
    group_id_signed BIGINT,
    group_uuid TEXT,
    group_is_hidden INTEGER,
    group_users TEXT,
    checksum TEXT,
    PRIMARY KEY (group_name)
) WITHOUT ROWID;
```

**Key Fields:**
- `group_name`: Primary key
- `group_users`: Comma-separated list of group members

---

### System Services (`dbsync_services`)

Stores system service configuration and status.

```sql
CREATE TABLE dbsync_services (
    service_id TEXT,
    service_name TEXT,
    service_description TEXT,
    service_type TEXT,
    service_state TEXT,
    service_sub_state TEXT,
    service_enabled TEXT,
    service_start_type TEXT,
    service_restart TEXT,
    service_frequency BIGINT,
    service_starts_on_mount INTEGER,
    service_starts_on_path_modified TEXT,
    service_starts_on_not_empty_directory TEXT,
    service_inetd_compatibility INTEGER,
    process_pid BIGINT,
    process_executable TEXT,
    process_args TEXT,
    process_user_name TEXT,
    process_group_name TEXT,
    process_working_dir TEXT,
    process_root_dir TEXT,
    file_path TEXT,
    service_address TEXT,
    log_file_path TEXT,
    error_log_file_path TEXT,
    service_exit_code INTEGER,
    service_win32_exit_code INTEGER,
    service_following TEXT,
    service_object_path TEXT,
    service_target_ephemeral_id BIGINT,
    service_target_type TEXT,
    service_target_address TEXT,
    checksum TEXT,
    PRIMARY KEY (service_id, file_path)
) WITHOUT ROWID;
```

**Key Fields:**
- Composite primary key: `(service_id, file_path)`
- Comprehensive service configuration and runtime information

---

### Browser Extensions (`dbsync_browser_extensions`)

Stores browser extension information across different browsers and user profiles.

```sql
CREATE TABLE dbsync_browser_extensions (
    browser_name TEXT,
    user_id TEXT,
    package_name TEXT,
    package_id TEXT,
    package_version TEXT,
    package_description TEXT,
    package_vendor TEXT,
    package_build_version TEXT,
    package_path TEXT,
    browser_profile_name TEXT,
    browser_profile_path TEXT,
    package_reference TEXT,
    package_permissions TEXT,
    package_type TEXT,
    package_enabled INTEGER,
    package_visible INTEGER,
    package_autoupdate INTEGER,
    package_persistent INTEGER,
    package_from_webstore INTEGER,
    browser_profile_referenced INTEGER,
    package_installed TEXT,
    file_hash_sha256 TEXT,
    checksum TEXT,
    PRIMARY KEY (browser_name,user_id,browser_profile_name,package_name,package_version)
) WITHOUT ROWID;
```

**Key Fields:**
- Composite primary key: `(browser_name,user_id,browser_profile_name,package_name,package_version)`
- Security-relevant extension permissions and source information

---

### Windows Hotfixes (`dbsync_hotfixes`)

Stores Windows system hotfix/patch information.

```sql
CREATE TABLE dbsync_hotfixes(
    hotfix_name TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix_name)
) WITHOUT ROWID;
```

**Key Fields:**
- `hotfix_name`: Primary key (KB number or patch identifier)

---
