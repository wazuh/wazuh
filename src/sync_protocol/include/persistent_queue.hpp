#pragma once

#include "ipersistent_queue.hpp"

#include <string>
#include <map>
#include <vector>
#include <optional>
#include <mutex>
#include <memory>
#include <atomic>

class PersistentQueue : public IPersistentQueue {
public:
    PersistentQueue();
    ~PersistentQueue() override;

    uint64_t submit(ModuleType module, const std::string& id,
                    const std::string& index,
                    const std::string& data,
                    Wazuh::SyncSchema::Operation operation) override;

    std::optional<PersistedData> fetchNext(ModuleType module) override;
    void remove(ModuleType module, uint64_t sequence) override;

private:
    std::mutex m_mutex;
    std::map<ModuleType, std::vector<PersistedData>> m_store;
    std::map<ModuleType, std::atomic<uint64_t>> m_seqCounter;

    void loadFromStorage(ModuleType module);
    void persistMessage(const PersistedData& data);
    void deleteMessage(ModuleType module, uint64_t sequence);
};
