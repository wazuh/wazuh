# Database Schema

Syscollector uses a local SQLite database to store system inventory data and track changes between scans.

## Database Location

The Syscollector database is typically located at:
- **Linux/Unix/macOS**: `/var/ossec/queue/syscollector/db/local.db`
- **Windows**: `C:\Program Files (x86)\ossec-agent\queue\syscollector\db\local.db`

## Database Tables

### System Information Tables

#### `dbsync_osinfo` - Operating System Information

Stores operating system and kernel details.

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
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    os_display_version TEXT,
    checksum TEXT,
    PRIMARY KEY (os_name)
) WITHOUT ROWID;
```

#### `dbsync_hwinfo` - Hardware Information

Stores hardware specifications.

```sql
CREATE TABLE dbsync_hwinfo (
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_mhz DOUBLE,
    ram_total INTEGER,
    ram_free INTEGER,
    ram_usage INTEGER,
    checksum TEXT,
    PRIMARY KEY (board_serial)
) WITHOUT ROWID;
```

### Software Tables

#### `dbsync_packages` - Installed Packages

Stores information about installed software packages.

```sql
CREATE TABLE dbsync_packages (
    name TEXT,
    version TEXT,
    vendor TEXT,
    install_time TEXT,
    location TEXT,
    architecture TEXT,
    groups TEXT,
    description TEXT,
    size BIGINT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    format TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (name, version, architecture, format, location)
) WITHOUT ROWID;
```

#### `dbsync_hotfixes` - Windows Hotfixes

Stores Windows security updates and hotfixes.

```sql
CREATE TABLE dbsync_hotfixes (
    hotfix TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix)
) WITHOUT ROWID;
```

### Network Tables

#### `dbsync_network_iface` - Network Interfaces

Stores network interface configuration and statistics.

```sql
CREATE TABLE dbsync_network_iface (
    name TEXT,
    adapter TEXT,
    type TEXT,
    state TEXT,
    mtu INTEGER,
    mac TEXT,
    tx_packets INTEGER,
    rx_packets INTEGER,
    tx_bytes INTEGER,
    rx_bytes INTEGER,
    tx_errors INTEGER,
    rx_errors INTEGER,
    tx_dropped INTEGER,
    rx_dropped INTEGER,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (name, adapter, type)
) WITHOUT ROWID;
```

#### `dbsync_network_address` - Network Addresses

Stores IP addresses assigned to interfaces.

```sql
CREATE TABLE dbsync_network_address (
    iface TEXT,
    proto INTEGER,
    address TEXT,
    netmask TEXT,
    broadcast TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (iface, proto, address)
) WITHOUT ROWID;
```

#### `dbsync_network_protocol` - Network Protocols

Stores network protocol configuration.

```sql
CREATE TABLE dbsync_network_protocol (
    iface TEXT,
    type TEXT,
    gateway TEXT,
    dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
    metric TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (iface, type)
) WITHOUT ROWID;
```

#### `dbsync_ports` - Network Ports

Stores information about open network ports.

```sql
CREATE TABLE dbsync_ports (
    protocol TEXT,
    local_ip TEXT,
    local_port BIGINT,
    remote_ip TEXT,
    remote_port BIGINT,
    tx_queue BIGINT,
    rx_queue BIGINT,
    inode BIGINT,
    state TEXT,
    pid BIGINT,
    process TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (inode, protocol, local_ip, local_port)
) WITHOUT ROWID;
```

### Process and System Tables

#### `dbsync_processes` - Running Processes

Stores information about running system processes.

```sql
CREATE TABLE dbsync_processes (
    pid TEXT,
    name TEXT,
    state TEXT,
    ppid BIGINT,
    utime BIGINT,
    stime BIGINT,
    cmd TEXT,
    argvs TEXT,
    euser TEXT,
    ruser TEXT,
    suser TEXT,
    egroup TEXT,
    rgroup TEXT,
    sgroup TEXT,
    fgroup TEXT,
    priority BIGINT,
    nice BIGINT,
    size BIGINT,
    vm_size BIGINT,
    resident BIGINT,
    share BIGINT,
    start_time BIGINT,
    pgrp BIGINT,
    session BIGINT,
    nlwp BIGINT,
    tgid BIGINT,
    tty BIGINT,
    processor BIGINT,
    checksum TEXT,
    PRIMARY KEY (pid)
) WITHOUT ROWID;
```

#### `dbsync_users` - System Users

Stores system user account information.

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

#### `dbsync_groups` - System Groups

Stores system group information.

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

#### `dbsync_services` - System Services

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
    item_id TEXT,
    PRIMARY KEY (service_id, file_path)
) WITHOUT ROWID;
```

### Additional Tables

#### `dbsync_browser_extensions` - Browser Extensions

Stores installed browser extensions and add-ons.

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
    item_id TEXT,
    PRIMARY KEY (browser_name, user_id, browser_profile_name, package_name, package_version)
) WITHOUT ROWID;
```

## Database Design

### Primary Keys
Each table uses composite primary keys that uniquely identify records based on their natural identifiers.

### Change Detection
All tables include a `checksum` column containing an MD5 hash of the record data, used for efficient change detection between scans.

### Item ID Fields
Many tables include an `item_id` column that serves as a composite identifier for synchronization purposes, constructed from key fields.

### Storage Optimization
- Tables use `WITHOUT ROWID` optimization for better performance
- Primary keys are chosen to minimize storage overhead
- Indexes are automatically created for primary key columns

### Data Types
- `TEXT`: UTF-8 encoded strings
- `INTEGER`: 64-bit signed integers
- `BIGINT`: 64-bit signed integers (for large values)
- `DOUBLE`: Double-precision floating-point numbers

## Database Operations

### Initialization
The database is automatically created when Syscollector starts for the first time.

### Maintenance
Syscollector performs automatic database maintenance including:
- Cleanup of obsolete records
- Vacuum operations to reclaim space
- Index rebuilding as needed

### Backup
The database file can be safely backed up while the agent is running, as SQLite supports concurrent readers.

## Troubleshooting

### Database Corruption
If the database becomes corrupted, delete the file and restart the agent:
```bash
sudo rm /var/ossec/queue/syscollector/db/local.db
sudo systemctl restart wazuh-agent
```

### Large Database Size
Monitor database size and consider adjusting scan intervals if it grows too large:
```bash
ls -lh /var/ossec/queue/syscollector/db/local.db
```

### Performance Issues
For performance analysis, use SQLite tools to examine the database:
```bash
sqlite3 /var/ossec/queue/syscollector/db/local.db ".schema"
```