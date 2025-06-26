#pragma once

#include <vector>
#include "ipersistent_queue.hpp"

class IPersistentQueueStorage
{
    public:
        virtual ~IPersistentQueueStorage() = default;

        virtual void save(const std::string& module, const PersistedData& data) = 0;
        virtual void remove(const std::string& module, uint64_t sequence) = 0;
        virtual void removeAll(const std::string& module) = 0;
        virtual std::vector<PersistedData> loadAll(const std::string& module) = 0;
};
