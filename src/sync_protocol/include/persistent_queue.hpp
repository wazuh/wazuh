#pragma once

#include "ipersistent_queue.hpp"
#include "ipersistent_queue_storage.hpp"

#include <string>
#include <map>
#include <vector>
#include <optional>
#include <mutex>
#include <memory>
#include <atomic>

class PersistentQueue : public IPersistentQueue
{
    public:
        explicit PersistentQueue(std::shared_ptr<IPersistentQueueStorage> storage = nullptr);

        ~PersistentQueue() override;

        uint64_t submit(const std::string& module, const std::string& id,
                        const std::string& index,
                        const std::string& data,
                        Wazuh::SyncSchema::Operation operation) override;

        std::optional<PersistedData> fetchNext(const std::string& module) override;
        std::vector<PersistedData> fetchAll(const std::string& module) override;
        std::vector<PersistedData> fetchRange(const std::string& module, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) override;
        void remove(const std::string& module, uint64_t sequence) override;
        void removeAll(const std::string& module) override;

    private:
        std::mutex m_mutex;
        std::map<std::string, std::vector<PersistedData>> m_store;
        std::map<std::string, std::atomic<uint64_t>> m_seqCounter;
        std::shared_ptr<IPersistentQueueStorage> m_storage;

        void loadFromStorage(const std::string& module);
        void persistMessage(const std::string& module, const PersistedData& data);
        void deleteMessage(const std::string& module, uint64_t sequence);
        void deleteAllMessages(const std::string& module);
};
