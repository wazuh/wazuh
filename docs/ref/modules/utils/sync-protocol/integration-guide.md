# Integration Guide

This guide provides step-by-step examples for integrating the Agent Sync Protocol into internal Wazuh modules such as FIM, SCA, and Inventory.

## Prerequisites

Before integrating the Agent Sync Protocol, ensure you have:

1. Access to the protocol headers in `src/shared_modules/sync_protocol/include/`
2. A unique module name identifier
3. A dedicated SQLite database path for persistent storage
4. Message queue functions configured for your environment

## Basic Integration Steps

### Step 1: Include Required Headers

#### C++ Integration
```cpp
#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"

// For custom queue implementations (optional)
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
auto logger = [](int level, const std::string& message) {
    switch(level) {
        case 0: debug("%s", message.c_str()); break;
        case 1: info("%s", message.c_str()); break;
        case 2: warning("%s", message.c_str()); break;
        case 3: error("%s", message.c_str()); break;
    }
};

// Setup message queue functions
MQ_Functions mqFuncs = {
    .start = mq_start_wrapper,       // Your mq_start_fn implementation
    .send_binary = mq_send_wrapper   // Your mq_send_binary_fn implementation
};

// Create protocol instance
auto protocol = std::make_unique<AgentSyncProtocol>(
    "FIM",                              // Module name
    "/var/ossec/queue/fim/fim_sync.db", // Database path
    mqFuncs,                            // MQ functions
    logger                              // Logger callback
);
```

#### C Example
```c
// Define logger function
void module_logger(modules_log_level_t level, const char* message) {
    switch(level) {
        case 0: debug("%s", message); break;
        case 1: info("%s", message); break;
        case 2: warning("%s", message); break;
        case 3: error("%s", message); break;
    }
}

// Setup message queue functions
MQ_Functions mq_funcs = {
    .start = mq_start_wrapper,       // Your mq_start_fn implementation
    .send_binary = mq_send_wrapper   // Your mq_send_binary_fn implementation
};

// Create protocol handle
AgentSyncProtocolHandle* handle = asp_create(
    "SCA",
    "/var/ossec/queue/sca/sca_sync.db",
    &mq_funcs,
    module_logger
);

if (!handle) {
    error("Failed to create sync protocol instance");
    return -1;
}
```

### Step 3: Persist Module Data

#### C++ Example - FIM File Change
```cpp
// File creation event
void onFileCreated(const std::string& filepath, const FileInfo& info) {
    // Generate unique ID (hash of filepath)
    std::string id = generateHash(filepath);

    // Build JSON data
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

    // Persist the difference
    protocol->persistDifference(
        id,
        Operation::CREATE,
        "fim_events",
        data.dump()
    );
}

// File modification event
void onFileModified(const std::string& filepath, const FileInfo& info) {
    std::string id = generateHash(filepath);
    nlohmann::json data = buildFileJson(info);

    protocol->persistDifference(
        id,
        Operation::UPDATE,
        "fim_events",
        data.dump()
    );
}

// File deletion event
void onFileDeleted(const std::string& filepath) {
    std::string id = generateHash(filepath);

    protocol->persistDifference(
        id,
        Operation::DELETE,
        "fim_events",
        "{\"path\": \"" + filepath + "\"}"
    );
}
```

#### C Example - SCA Policy Check
```c
// Policy check result
void persist_policy_check(const char* policy_id, CheckResult* result) {
    // Build JSON data
    char json_data[4096];
    snprintf(json_data, sizeof(json_data),
        "{\"policy_id\": \"%s\", \"status\": \"%s\", \"score\": %d, \"timestamp\": %ld}",
        policy_id,
        result->status,
        result->score,
        result->timestamp
    );

    // Persist the check result
    asp_persist_diff(
        handle,
        policy_id,
        OPERATION_MODIFY,
        "sca_checks",
        json_data
    );
}
```

#### C++ Example - Recovery Using In-Memory Storage
```cpp
// Module recovery scenario
void recoverModuleData() {
    info("Starting module recovery process");

    // Clear in-memory data before sync attempt
    protocol->clearInMemoryData();

    // Read recovery data from backup source
    std::vector<RecoveryItem> recoveryItems = loadRecoveryData();

    // Persist all recovery data in memory
    for (const auto& item : recoveryItems) {
        protocol->persistDifferenceInMemory(
            item.id,
            Operation::CREATE,
            item.index,
            item.data
        );
    }

    info("Persisted %zu recovery items in memory", recoveryItems.size());

    // Synchronize the in-memory data with the manager
    bool success = protocol->synchronizeModule(
        Mode::FULL,
        std::chrono::seconds(60),
        5,
        2000
    );

    if (success) {
        info("Recovery completed successfully");
    } else {
        error("Recovery synchronization failed, will retry later");
    }
}
```

#### C Example - Integrity Check Before Sync
```c
// Check if full sync is needed before synchronization
bool should_perform_full_sync(const char* index) {
    // Calculate checksum for the index
    char checksum[65];
    calculate_index_checksum(index, checksum);

    // Check with manager if full sync is required
    bool needs_full_sync = asp_requires_full_sync(
        handle,
        index,
        checksum,
        30,   // timeout in seconds
        3,    // retries
        1000  // max EPS
    );

    if (needs_full_sync) {
        info("Checksum mismatch detected for index %s, full sync required", index);
        return true;
    } else {
        info("Checksum valid for index %s, delta sync sufficient", index);
        return false;
    }
}
```

### Step 4: Process Manager Responses

When the manager sends responses, you need to parse them using the protocol:

#### C++ Example
```cpp
// Message receive callback
void onMessageReceived(const uint8_t* buffer, size_t length) {
    // Parse the FlatBuffer response from manager
    bool parsed = protocol->parseResponseBuffer(buffer, length);

    if (parsed) {
        info("Successfully processed manager response");
    } else {
        error("Failed to parse manager response");
    }
}
```

#### C Example
```c
// Message receive callback
void on_message_received(const uint8_t* buffer, size_t length) {
    // Parse the FlatBuffer response from manager
    bool parsed = asp_parse_response(handle, buffer, length);

    if (parsed) {
        info("Successfully processed manager response");
    } else {
        error("Failed to parse manager response");
    }
}
```

### Step 5: Trigger Synchronization

#### C++ Example - Periodic Sync
```cpp
void performPeriodicSync() {
    // Delta sync with 30-second timeout, 3 retries, 1000 EPS limit
    bool success = protocol->synchronizeModule(
        Mode::DELTA,
        std::chrono::seconds(30),
        3,
        1000
    );

    if (success) {
        info("Synchronization completed successfully");
    } else {
        error("Synchronization failed");
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
// Trigger sync when buffer reaches threshold
void check_and_sync(size_t buffer_size) {
    const size_t SYNC_THRESHOLD = 1000;

    if (buffer_size >= SYNC_THRESHOLD) {
        bool success = asp_sync_module(
            handle,
            MODE_DELTA,
            30,    // timeout in seconds
            3,     // retries
            500    // max EPS
        );

        if (!success) {
            error("Failed to synchronize module data");
        }
    }
}
```

#### C Example - Metadata Synchronization
```c
// Synchronize metadata at agent startup
void sync_agent_metadata() {
    info("Synchronizing agent metadata");

    bool success = asp_sync_metadata_or_groups(
        handle,
        MODE_METADATA_DELTA,
        30,  // timeout in seconds
        3,   // retries
        0,   // no EPS limit
        0
    );

    if (success) {
        info("Agent metadata synchronized successfully");
    } else {
        error("Failed to synchronize agent metadata");
    }
}
```

## Complete Module Integration Example

### Inventory Module Integration

```cpp
class InventorySync {
private:
    std::unique_ptr<AgentSyncProtocol> m_protocol;
    std::atomic<bool> m_running{true};
    std::thread m_syncThread;

public:
    InventorySync(const std::string& dbPath, const MQ_Functions& mqFuncs) {
        // Initialize protocol
        m_protocol = std::make_unique<AgentSyncProtocol>(
            "Inventory",
            dbPath,
            mqFuncs,
            [](int level, const std::string& msg) {
                log_message(level, "InventorySync", msg.c_str());
            }
        );

        // Start sync thread
        m_syncThread = std::thread(&InventorySync::syncWorker, this);
    }

    ~InventorySync() {
        m_running = false;
        if (m_syncThread.joinable()) {
            m_syncThread.join();
        }
    }

    // Called when system inventory changes
    void onInventoryChange(const std::string& category, const nlohmann::json& data) {
        std::string id = generateInventoryId(category, data);

        m_protocol->persistDifference(
            id,
            Operation::UPDATE,
            "inventory_" + category,
            data.dump()
        );
    }

    // Called when new package is installed
    void onPackageInstalled(const PackageInfo& pkg) {
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
            data.dump()
        );
    }

    // Called when package is removed
    void onPackageRemoved(const std::string& pkgName) {
        m_protocol->persistDifference(
            pkgName,
            Operation::DELETE,
            "inventory_packages",
            "{\"name\": \"" + pkgName + "\"}"
        );
    }

private:
    void syncWorker() {
        while (m_running) {
            // Wait for sync interval
            std::this_thread::sleep_for(std::chrono::minutes(15));

            // Perform full sync every 4 hours, delta sync otherwise
            static int syncCount = 0;
            Mode mode = (++syncCount % 16 == 0) ? Mode::Full : Mode::Delta;

            bool success = m_protocol->synchronizeModule(
                mode,
                std::chrono::seconds(60),  // 1 minute timeout
                5,                         // 5 retries
                2000                       // 2000 EPS limit
            );

            if (!success) {
                error("Inventory sync failed, will retry in next interval");
            }
        }
    }

    std::string generateInventoryId(const std::string& category,
                                   const nlohmann::json& data) {
        // Generate unique ID based on category and key fields
        std::string keyData = category;
        if (data.contains("name")) {
            keyData += "_" + data["name"].get<std::string>();
        }
        if (data.contains("id")) {
            keyData += "_" + data["id"].get<std::string>();
        }
        return sha256(keyData);
    }
};
```

## Best Practices

### 1. Error Handling

Always check return values and handle failures gracefully:

```cpp
if (!protocol->synchronizeModule(Mode::DELTA, timeout, retries, maxEps)) {
    // Log error
    error("Sync failed, scheduling retry");

    // Schedule retry with exponential backoff
    scheduleRetry(calculateBackoff(attemptNumber));
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

### 3. Logging Integration

Provide detailed logging for debugging:

```cpp
auto logger = [](int level, const std::string& message) {
    std::string prefix = "[SyncProtocol] ";

    switch(level) {
        case 0: // Debug
            if (debug_enabled) {
                mdebug1("%s%s", prefix.c_str(), message.c_str());
            }
            break;
        case 1: // Info
            minfo("%s%s", prefix.c_str(), message.c_str());
            break;
        case 2: // Warning
            mwarn("%s%s", prefix.c_str(), message.c_str());
            break;
        case 3: // Error
            merror("%s%s", prefix.c_str(), message.c_str());
            break;
    }
};
```

## Testing Your Integration

### Unit Testing

Mock the protocol interface for unit tests:

```cpp
class MockAgentSyncProtocol : public IAgentSyncProtocol {
public:
    MOCK_METHOD(void, persistDifference,
                (const std::string&, Operation, const std::string&, const std::string&),
                (override));
    MOCK_METHOD(bool, synchronizeModule,
                (Mode, std::chrono::seconds, unsigned int, size_t),
                (override));
    MOCK_METHOD(bool, parseResponseBuffer,
                (const uint8_t*, size_t),
                (override));
};
```

### Integration Testing

Test with a real protocol instance but mock message queue:

```cpp
MQ_Functions testMqFuncs = {
    .open = [](const char*, int) { return 1; },
    .send = [](int, const char*, const char*, const char*) { return 0; },
    .recv = [](int, char*, unsigned int, unsigned int*) { return 0; },
    .close = [](int) {}
};

auto protocol = std::make_unique<AgentSyncProtocol>(
    "TestModule",
    ":memory:",  // In-memory SQLite for testing
    testMqFuncs,
    testLogger
);
```

## Troubleshooting

### Common Issues

1. **Database Lock Errors**
   - Ensure only one process accesses the database file
   - Check file permissions and disk space

2. **Message Queue Failures**
   - Verify queue path and permissions
   - Check queue size limits

3. **Synchronization Timeouts**
   - Increase timeout values for slow networks
   - Check network connectivity to manager
   - Verify manager is processing messages

4. **Memory Issues**
   - Monitor queue size and implement flow control
   - Use EPS limiting to control memory usage
   - Implement periodic cleanup of old data

5. **Checksum Mismatch Issues**
   - Ensure consistent checksum calculation algorithm
   - Verify checksum is calculated for the correct index/table
   - Check for data corruption in persistent storage

6. **Metadata/Groups Sync Failures**
   - Verify correct mode is used (METADATA_DELTA, METADATA_CHECK, GROUP_DELTA, GROUP_CHECK)
   - Ensure no data messages are sent during metadata/groups sync
   - Check manager logs for additional error details
