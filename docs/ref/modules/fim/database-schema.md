# Database Schema

The FIM module uses multiple database schemas to store and manage file integrity monitoring data. The architecture includes both local FIMDB databases for state comparison and sync protocol databases for reliable message persistence.

---

## FIM Local Databases (FIMDB + DBSync)

FIM uses FIMDB as a wrapper around DBSync to maintain local SQLite databases for storing current file and registry states for comparison during monitoring. The actual database operations are handled by DBSync, while FIMDB provides FIM-specific functionality.

### File Entries Table

Stores metadata for monitored files:

```sql
CREATE TABLE IF NOT EXISTS file_entry (
    path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    device INTEGER,
    inode INTEGER,
    size INTEGER,
    permissions TEXT,
    attributes TEXT,
    uid TEXT,
    gid TEXT,
    owner TEXT,
    group_ TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    PRIMARY KEY(path)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS path_index ON file_entry (path);
CREATE INDEX IF NOT EXISTS inode_index ON file_entry (device, inode);
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `path` | TEXT | Full file path (primary key) |
| `checksum` | TEXT | File checksum for change detection |
| `device` | INTEGER | Device ID where file resides |
| `inode` | INTEGER | File system inode number |
| `size` | INTEGER | File size in bytes |
| `permissions` | TEXT | File permissions (e.g., "755") |
| `attributes` | TEXT | File attributes (platform-specific) |
| `uid` | TEXT | User ID of file owner |
| `gid` | TEXT | Group ID of file owner |
| `owner` | TEXT | Username of file owner |
| `group_` | TEXT | Group name of file owner |
| `hash_md5` | TEXT | MD5 hash of file contents |
| `hash_sha1` | TEXT | SHA1 hash of file contents |
| `hash_sha256` | TEXT | SHA256 hash of file contents |
| `mtime` | INTEGER | Last modification time (Unix timestamp) |

---

### Registry Key Table (Windows Only)

Stores metadata for monitored registry keys:

```sql
CREATE TABLE IF NOT EXISTS registry_key (
    path TEXT NOT NULL,
    permissions TEXT,
    uid TEXT,
    gid TEXT,
    owner TEXT,
    group_ TEXT,
    mtime INTEGER,
    architecture TEXT CHECK (architecture IN ('[x32]', '[x64]')),
    checksum TEXT NOT NULL,
    PRIMARY KEY (architecture, path)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS path_index ON registry_key (path);
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `path` | TEXT | Registry key path |
| `permissions` | TEXT | Registry key permissions |
| `uid` | TEXT | User ID with access |
| `gid` | TEXT | Group ID with access |
| `owner` | TEXT | Owner of registry key |
| `group_` | TEXT | Group with access |
| `mtime` | INTEGER | Last modification time |
| `architecture` | TEXT | Architecture (`[x32]` or `[x64]`) |
| `checksum` | TEXT | Registry key checksum |

**Primary Key:** `(architecture, path)` - Allows same path in different architectures

---

### Registry Data Table (Windows Only)

Stores individual registry values:

```sql
CREATE TABLE IF NOT EXISTS registry_data (
    path TEXT,
    architecture TEXT CHECK (architecture IN ('[x32]', '[x64]')),
    value TEXT NOT NULL,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    checksum TEXT NOT NULL,
    PRIMARY KEY(path, architecture, value),
    FOREIGN KEY (path) REFERENCES registry_key(path),
    FOREIGN KEY (architecture) REFERENCES registry_key(architecture)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS key_name_index ON registry_data (path, value);
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `path` | TEXT | Registry key path (foreign key) |
| `architecture` | TEXT | Architecture (`[x32]` or `[x64]`) |
| `value` | TEXT | Registry value name |
| `type` | INTEGER | Registry value type (REG_SZ, REG_DWORD, etc.) |
| `size` | INTEGER | Size of registry value data |
| `hash_md5` | TEXT | MD5 hash of value data |
| `hash_sha1` | TEXT | SHA1 hash of value data |
| `hash_sha256` | TEXT | SHA256 hash of value data |
| `checksum` | TEXT | Value checksum for change detection |

**Primary Key:** `(path, architecture, value)` - Unique per registry value
**Foreign Keys:** References `registry_key` table

---

### Table Metadata

Tracks synchronization state for FIM tables to support recovery operations:

```sql
CREATE TABLE IF NOT EXISTS table_metadata (
    table_name TEXT PRIMARY KEY,
    last_sync_time INTEGER NOT NULL
);
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `table_name` | TEXT | Name of the FIM table being tracked (primary key) |
| `last_sync_time` | INTEGER | Unix timestamp of last synchronization attempt |

#### Purpose

The `table_metadata` table supports FIM recovery functionality by tracking each table's last synchronization attempt. This allows the system to trigger recovery operations with the frequency specified by the `integtrity_interal` option's value.

**Tracked Tables:**
- `file_entry` - File monitoring state
- `registry_key` - Registry key monitoring state (Windows only)
- `registry_data` - Registry value monitoring state (Windows only)

---

## Sync Protocol Database

The sync protocol maintains its own persistence layer in a separate SQLite database for reliable message delivery.

### Persistent Queue Table

```sql
CREATE TABLE IF NOT EXISTS persistent_queue (
    id TEXT PRIMARY KEY NOT NULL,
    idx TEXT NOT NULL,
    data TEXT NOT NULL,
    operation INTEGER NOT NULL,
    sync_status INTEGER NOT NULL DEFAULT 0,
    create_status INTEGER NOT NULL DEFAULT 0,
    operation_syncing INTEGER NOT NULL DEFAULT 3
);
```

#### Field Descriptions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | TEXT | - | Unique identifier for FIM entry (SHA1 hash of file path) |
| `idx` | TEXT | - | Index identifier for grouping related entries |
| `data` | TEXT | - | JSON serialized FIM data |
| `operation` | INTEGER | - | Type of operation (0=CREATE, 1=UPDATE, 2=DELETE) |
| `sync_status` | INTEGER | 0 | Current sync state (0=PENDING, 1=SYNCING, 2=SYNCING_UPDATED) |
| `create_status` | INTEGER | 0 | Creation tracking (0=EXISTING, 1=NEW, 2=NEW_DELETED) |
| `operation_syncing` | INTEGER | 3 | Original operation being synchronized |

#### Sync Status Values

```c
enum class SyncStatus : int {
    PENDING = 0,        // Message waiting to be synchronized
    SYNCING = 1,        // Message currently being synchronized
    SYNCING_UPDATED = 2 // Message being synchronized with updated contents
};
```

#### Create Status Values

```c
enum class CreateStatus : int {
    EXISTING = 0,     // Message existed prior to current session
    NEW = 1,          // Message newly created during current session
    NEW_DELETED = 2   // Message created then deleted before sync
};
```

---

## Database Operations Flow

### State Comparison Process

1. **File System Scan**: FIM detects file/registry changes
2. **Database Transaction**: Start transaction with FIMDB
3. **State Comparison**: Compare current state with stored state
4. **Change Detection**: Determine operation type (create/update/delete)
5. **Event Generation**: Generate stateless and stateful events
6. **Persistence**: Store stateful event in sync protocol database

### Database Maintenance

#### Index Optimization

Both databases use indexes to optimize common queries:

**FIMDB Indexes:**
- `path_index`: Fast file path lookups
- `inode_index`: Detect file moves/renames
- `key_name_index`: Registry value lookups

**Sync Protocol:** Uses primary key for fast ID-based operations

---

## Database File Locations

### Fixed Paths

Database files are stored in fixed locations relative to Wazuh installation:

- **FIM Database**: `queue/fim/db/fim.db`
- **Sync Protocol Database**: `queue/fim/db/fim_sync.db`

### Database Configuration

**SQLite Pragmas** used for optimization:

```sql
-- Sync protocol database optimizations
PRAGMA synchronous = NORMAL;    -- Balanced durability/performance
PRAGMA journal_mode = WAL;      -- Write-Ahead Logging for concurrency
```
