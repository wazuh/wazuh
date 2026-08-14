# Integration Guide

This guide provides step-by-step examples for integrating the Agent Sync Protocol into internal Wazuh modules such as FIM, SCA, and Syscollector.

## Prerequisites

Before integrating the Agent Sync Protocol, ensure you have:

1. Access to the protocol headers in `src/shared_modules/sync_protocol/include/`
2. A unique module name identifier
3. A dedicated SQLite database path for persistent storage (or `std::nullopt`/`NULL` for in-memory-only use)

There is no message-queue setup to wire in: the protocol carries a whole session over its own local `queue-sync` socket by default (see [API Reference](api-reference.md#transport-abstraction)); nothing needs to be passed in for that.

## Basic Integration Steps

### Step 1: Include Required Headers

#### C++ Integration
```cpp
#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"

// For custom queue implementations (optional, mainly for testing)
#include "ipersistent_queue.hpp"
```

#### C Integration
```c
#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol_c_interface_types.h"
```

### Step 2: Initialize the Protocol

#### C++ Example
```cpp
// Define logger function
LoggerFunc logger = [](modules_log_level_t level, const std::string& message) {
    switch (level) {
        case LOG_DEBUG:   mdebug1("%s", message.c_str()); break;
        case LOG_INFO:    minfo("%s", message.c_str());   break;
        case LOG_WARNING: mwarn("%s", message.c_str());   break;
        case LOG_ERROR:   merror("%s", message.c_str());  break;
        default: break;
    }
};

// Create protocol instance. queue and syncTransport are left at their
// defaults (real SQLite queue, real queue-sync socket transport).
auto protocol = std::make_unique<AgentSyncProtocol>(
    "fim",                              // Module name
    "/var/ossec/queue/fim/fim_sync.db", // Database path
    logger                              // Logger callback
);
```

#### C Example
```c
// Define logger function
void module_logger(modules_log_level_t level, const char* message) {
    switch (level) {
        case LOG_DEBUG:   mdebug1("%s", message); break;
        case LOG_INFO:    minfo("%s", message);   break;
        case LOG_WARNING: mwarn("%s", message);   break;
        case LOG_ERROR:   merror("%s", message);  break;
        default: break;
    }
}

// Create protocol handle
AgentSyncProtocolHandle* handle = asp_create(
    "sca",
    "/var/ossec/queue/sca/sca_sync.db",
    module_logger
);

if (!handle) {
    merror("Failed to create sync protocol instance");
    return -1;
}
```

### Step 3: Persist Module Data

#### C++ Example - FIM File Change
```cpp
// File creation event
void onFileCreated(const std::string& filepath, const FileInfo& info) {
    std::string id = generateHash(filepath);

    nlohmann::json data = {
        {"path", filepath},
        {"size", info.size},
        {"permissions", info.permissions},
        {"owner", info.owner},
        {"group", info.group},
        {"mtime", info.mtime},
        {"hash_md5", info.hash_md5},
        {"hash_sha256", info.hash_sha256}
    };

    protocol->persistDifference(
        id,
        Operation::CREATE,
        "fim_files",
        data.dump(),
        info.version
    );
}

// File modification event
void onFileModified(const std::string& filepath, const FileInfo& info) {
    std::string id = generateHash(filepath);
    nlohmann::json data = buildFileJson(info);

    protocol->persistDifference(
        id,
        Operation::MODIFY,
        "fim_files",
        data.dump(),
        info.version
    );
}

// File deletion event
void onFileDeleted(const std::string& filepath, uint64_t version) {
    std::string id = generateHash(filepath);

    protocol->persistDifference(
        id,
        Operation::DELETE_,
        "fim_files",
        "{\"path\": \"" + filepath + "\"}",
        version
    );
}
```

#### C Example - SCA Policy Check
```c
// Policy check result
void persist_policy_check(const char* policy_id, CheckResult* result, uint64_t version) {
    char json_data[4096];
    snprintf(json_data, sizeof(json_data),
        "{\"policy_id\": \"%s\", \"status\": \"%s\", \"score\": %d, \"timestamp\": %ld}",
        policy_id, result->status, result->score, result->timestamp);

    asp_persist_diff(
        handle,
        policy_id,
        OPERATION_MODIFY,
        "sca_checks",
        json_data,
        version
    );
}
```

#### C++ Example - Vulnerability-Detection Context Data

Items that carry vulnerability-detection context (no upsert/delete semantics, stored but not indexed) are persisted with `isDataContext = true`. They can be mixed freely with regular items — both end up in the same session's `SyncData` payload:

```cpp
protocol->persistDifference(
    "pkg_ctx_" + pkg.name,
    Operation::CREATE,
    "vd_packages",
    contextData.dump(),
    1,
    /* isDataContext = */ true
);
```

#### C++ Example - Full-Replace Recovery (DataClean + DELTA)

There is no in-memory recovery API or `Mode::FULL`: a full-replace resync clears the target
index first, then streams the fresh snapshot through the normal persistent-queue DELTA path
(which safely splits into as many sessions as needed) — see
[Protocol Lifecycle](lifecycle.md#full-replace-recovery-dataclean-then-delta) for why.

```cpp
void recoverModuleData(const std::string& index) {
    minfo("Starting module recovery process");

    // Clear the manager's index before resending the fresh snapshot.
    if (!protocol->notifyDataClean({index})) {
        merror("Failed to clear index %s before recovery; will retry later", index.c_str());
        return;
    }

    std::vector<RecoveryItem> recoveryItems = loadRecoveryData();

    for (const auto& item : recoveryItems) {
        protocol->persistDifference(
            item.id,
            Operation::CREATE,
            item.index,
            item.data,
            item.version
        );
    }

    minfo("Persisted %zu recovery items", recoveryItems.size());

    SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);

    if (result.success) {
        minfo("Recovery completed successfully");
    } else {
        merror("Recovery synchronization failed: %s", result.failureReason.c_str());
    }
}
```

#### C Example - Integrity Check Before Sync
```c
bool should_perform_full_sync(const char* index) {
    char checksum[65];
    calculate_index_checksum(index, checksum);

    // Sends one FullSession carrying a ChecksumModule payload and waits for the EndAck
    bool needs_full_sync = asp_requires_full_sync(handle, index, checksum);

    if (needs_full_sync) {
        minfo("Checksum mismatch detected for index %s, full sync required", index);
    } else {
        minfo("Checksum valid for index %s, delta sync sufficient", index);
    }

    return needs_full_sync;
}
```

### Step 4: Process Manager Responses

The manager's answer (an `EndAck`, or the HTTPS transport's own result code) needs to reach `parseResponseBuffer()` for the in-flight `synchronizeModule()`/`notifyDataClean()`/`requiresFullSync()`/`synchronizeMetadataOrGroups()` call to unblock. In practice, this is wired up once by the transport that delivers the manager's HTTPS response back to the module, not called ad hoc by each module.

#### C++ Example
```cpp
void onManagerResponse(const uint8_t* buffer, size_t length) {
    bool parsed = protocol->parseResponseBuffer(buffer, length);

    if (!parsed) {
        merror("Failed to parse manager response");
    }
}
```

#### C Example
```c
void on_manager_response(const uint8_t* buffer, size_t length) {
    bool parsed = asp_parse_response_buffer(handle, buffer, length);

    if (!parsed) {
        merror("Failed to parse manager response");
    }
}
```

### Step 5: Trigger Synchronization

#### C++ Example - Periodic Sync
```cpp
void performPeriodicSync() {
    SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);

    if (result.success) {
        minfo("Synchronization completed successfully");
    } else if (result.stopped) {
        mdebug1("Synchronization aborted by shutdown");
    } else if (result.managerNotReady) {
        // Escalate to WARNING only once consecutiveFailures crosses
        // SYNC_MANAGER_NOT_READY_TOLERANCE; see the API reference.
        mdebug1("Manager not ready yet (%u consecutive)", result.consecutiveFailures);
    } else {
        merror("Synchronization failed: %s", result.failureReason.c_str());
    }
}

// Schedule periodic synchronization
std::thread syncThread([&protocol]() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        performPeriodicSync();
    }
});
```

#### C Example - Event-Driven Sync
```c
void check_and_sync(size_t buffer_size) {
    const size_t SYNC_THRESHOLD = 1000;

    if (buffer_size >= SYNC_THRESHOLD) {
        SyncModuleResult_t result = asp_sync_module(handle, MODE_DELTA);

        if (!result.success) {
            merror("Failed to synchronize module data: %s", result.failure_reason);
        }
    }
}
```

#### C Example - Metadata Synchronization
```c
// Synchronize metadata at agent startup
void sync_agent_metadata(uint64_t global_version) {
    minfo("Synchronizing agent metadata");

    const char* indices[] = {"agent_metadata"};
    SyncModuleResult_t result = asp_sync_metadata_or_groups(
        handle,
        MODE_METADATA_DELTA,
        indices,
        1,
        global_version
    );

    if (result.success) {
        minfo("Agent metadata synchronized successfully");
    } else {
        merror("Failed to synchronize agent metadata: %s", result.failure_reason);
    }
}
```

## Complete Module Integration Example

### Syscollector-Style Module Integration

```cpp
class InventorySync
{
public:
    InventorySync(const std::string& dbPath)
    {
        m_protocol = std::make_unique<AgentSyncProtocol>(
            "syscollector",
            dbPath,
            [](modules_log_level_t level, const std::string& msg)
            {
                log_message(level, "InventorySync", msg.c_str());
            });

        m_syncThread = std::thread(&InventorySync::syncWorker, this);
    }

    ~InventorySync()
    {
        m_protocol->stop();
        m_running = false;
        if (m_syncThread.joinable())
        {
            m_syncThread.join();
        }
    }

    // Called when system inventory changes
    void onInventoryChange(const std::string& category, const nlohmann::json& data, uint64_t version)
    {
        std::string id = generateInventoryId(category, data);

        m_protocol->persistDifference(
            id,
            Operation::MODIFY,
            "inventory_" + category,
            data.dump(),
            version);
    }

    // Called when a new package is installed
    void onPackageInstalled(const PackageInfo& pkg)
    {
        nlohmann::json data = {
            {"name", pkg.name},
            {"version", pkg.version},
            {"architecture", pkg.arch},
            {"vendor", pkg.vendor},
            {"install_time", pkg.installTime}
        };

        m_protocol->persistDifference(
            pkg.name + "_" + pkg.version,
            Operation::CREATE,
            "inventory_packages",
            data.dump(),
            1);
    }

    // Called when a package is removed
    void onPackageRemoved(const std::string& pkgName, uint64_t version)
    {
        m_protocol->persistDifference(
            pkgName,
            Operation::DELETE_,
            "inventory_packages",
            "{\"name\": \"" + pkgName + "\"}",
            version);
    }

private:
    void syncWorker()
    {
        int syncCount = 0;

        while (m_running)
        {
            std::this_thread::sleep_for(std::chrono::minutes(15));

            SyncModuleResult result;

            // Full-replace resync every 4 hours (16 * 15 min): clear the index, re-persist a
            // fresh snapshot, then sync via DELTA. Every other cycle is a plain delta sync of
            // whatever is already pending. See the recovery example above for why there is no
            // Mode::FULL to reach for here.
            if (++syncCount % 16 == 0)
            {
                if (!m_protocol->notifyDataClean({"inventory_packages"}))
                {
                    merror("Failed to clear inventory_packages before full-replace resync");
                    continue;
                }

                for (const auto& pkg : loadAllInstalledPackages())
                {
                    onPackageInstalled(pkg);
                }
            }

            result = m_protocol->synchronizeModule(Mode::DELTA);

            if (!result.success)
            {
                merror("Inventory sync failed: %s", result.failureReason.c_str());
            }
        }
    }

    std::string generateInventoryId(const std::string& category, const nlohmann::json& data)
    {
        std::string keyData = category;

        if (data.contains("name"))
        {
            keyData += "_" + data["name"].get<std::string>();
        }

        if (data.contains("id"))
        {
            keyData += "_" + data["id"].get<std::string>();
        }

        return sha256(keyData);
    }

    std::unique_ptr<AgentSyncProtocol> m_protocol;
    std::atomic<bool> m_running{true};
    std::thread m_syncThread;
};
```

## Best Practices

### 1. Error Handling

Always check `SyncModuleResult`/`SyncModuleResult_t` and use its fields to decide how loudly to log, rather than treating every failure the same way:

```cpp
const auto result = protocol->synchronizeModule(Mode::DELTA);

if (!result.success)
{
    if (result.stopped)
    {
        mdebug1("Sync aborted by shutdown");
    }
    else if (result.managerNotReady && result.consecutiveFailures < SYNC_MANAGER_NOT_READY_TOLERANCE)
    {
        mdebug1("Manager not ready yet, will retry next cycle");
    }
    else
    {
        mwarn("Sync failed: %s", result.failureReason.c_str());
    }
    // No explicit retry scheduling needed: the module's own periodic
    // cycle is what retries. The protocol itself does not re-attempt.
}
```

### 2. Resource Management

#### C++
Use RAII and smart pointers:
```cpp
auto protocol = std::make_unique<AgentSyncProtocol>(...);
// Automatic cleanup when protocol goes out of scope
```

#### C
Always clean up resources:
```c
AgentSyncProtocolHandle* handle = asp_create(...);
// Use handle...
asp_destroy(handle);  // Required cleanup
```

### 3. Shutdown

Call `stop()`/`asp_stop()` before tearing down a module so any in-flight `synchronizeModule()`/`notifyDataClean()`/`requiresFullSync()` call unblocks instead of waiting indefinitely for a transport callback that will never arrive. `reset()`/`asp_reset()` clears the stop flag if the module restarts in the same process.

### 4. Logging Integration

```cpp
LoggerFunc logger = [](modules_log_level_t level, const std::string& message) {
    const std::string prefix = "[SyncProtocol] ";

    switch (level) {
        case LOG_DEBUG:
            mdebug1("%s%s", prefix.c_str(), message.c_str());
            break;
        case LOG_INFO:
            minfo("%s%s", prefix.c_str(), message.c_str());
            break;
        case LOG_WARNING:
            mwarn("%s%s", prefix.c_str(), message.c_str());
            break;
        case LOG_ERROR:
            merror("%s%s", prefix.c_str(), message.c_str());
            break;
        default:
            break;
    }
};
```

## Testing Your Integration

### Unit Testing

Mock the `IAgentSyncProtocol` interface for unit tests:

```cpp
class MockAgentSyncProtocol : public IAgentSyncProtocol
{
public:
    MOCK_METHOD(void, persistDifference,
                (const std::string&, Operation, const std::string&, const std::string&, uint64_t, bool),
                (override));
    MOCK_METHOD(SyncModuleResult, synchronizeModule, (Mode, Option), (override));
    MOCK_METHOD(bool, requiresFullSync, (const std::string&, const std::string&), (override));
    MOCK_METHOD(bool, notifyDataClean, (const std::vector<std::string>&, Option), (override));
    MOCK_METHOD(bool, parseResponseBuffer, (const uint8_t*, size_t), (override));
    // ... plus the remaining IAgentSyncProtocol methods as needed by the test.
};
```

### Integration Testing

Test with a real `AgentSyncProtocol` instance but a fake transport, so the test controls the manager's answer without a real socket or HTTPS round trip — this is the same `ISyncSessionTransport` seam `agent_sync_protocol_tests` itself uses (`tests/mocks/mock_sync_transport.hpp`):

```cpp
class FakeSyncTransport : public ISyncSessionTransport
{
public:
    bool checkStatus() override { return true; }

    bool sendSession(uint64_t /*session*/, const std::vector<uint8_t>& message) override
    {
        lastMessage = message;
        return true; // pretend the local hand-off succeeded
    }

    std::vector<uint8_t> lastMessage;
};

auto transport = std::make_shared<FakeSyncTransport>();
auto protocol = std::make_unique<AgentSyncProtocol>(
    "test_module",
    ":memory:",  // in-memory SQLite for testing
    testLogger,
    nullptr,     // default persistent queue
    transport);

// ... trigger a sync on another thread, then feed a synthetic EndAck back in:
protocol->parseResponseBuffer(endAckBytes, endAckLength);
```

## Troubleshooting

### Common Issues

1. **Database Lock Errors**
   - Ensure only one process accesses the database file
   - Check file permissions and disk space

2. **`queue-sync` Socket Failures**
   - Verify the socket path and permissions
   - Check that `agentd`/`https_client` is running and bound to the intake socket
   - `SYNC_HANDOFF_RETRIES` (fixed at 3) only covers a transiently-unavailable local socket; it does not retry HTTP-level failures

3. **Synchronization Never Returns**
   - The protocol waits indefinitely for the manager's answer once the local hand-off succeeds; a hang here usually means the HTTPS transport's own timeout (`statefulTimeoutMs`) hasn't fired yet, or `stop()` was never called during shutdown
   - Check `agentd`/`https_client` logs and network connectivity to the manager

4. **Memory Issues**
   - Monitor persistent-queue size
   - `Option::VDFIRST`/`Option::VDSYNC` bypass the `FullSession` byte cap — make sure that is intentional for the flow using it

5. **Checksum Mismatch Issues**
   - Ensure consistent checksum calculation algorithm
   - Verify the checksum is calculated for the correct index/table
   - Check for data corruption in persistent storage

6. **Metadata/Groups Sync Failures**
   - Verify the correct mode is used (`METADATA_DELTA`, `METADATA_CHECK`, `GROUP_DELTA`, `GROUP_CHECK`)
   - These modes never populate a `SessionPayload` — only `Start`/`End` are sent
   - Check manager logs for additional error details
