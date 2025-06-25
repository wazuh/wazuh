#pragma once

#include "inventorySync_generated.h"

#include <optional>

enum class ModuleType {
    FIM,
    SCA,
    INV,
    OTHER
};

struct PersistedData {
    uint64_t seq;
    std::string id;
    std::string index;
    std::string data;
    Wazuh::SyncSchema::Operation operation;
};

class IPersistentQueue {
public:
    virtual ~IPersistentQueue() = default;

    virtual uint64_t submit(ModuleType module, const std::string& id,
                            const std::string& index,
                            const std::string& data,
                            Wazuh::SyncSchema::Operation operation) = 0;
    virtual std::optional<PersistedData> fetchNext(ModuleType module) = 0;
    virtual void remove(ModuleType module, uint64_t sequence) = 0;
};
