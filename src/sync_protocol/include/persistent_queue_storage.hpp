#pragma once

#include "ipersistent_queue_storage.hpp"
#include "../../shared_modules/utils/sqlite3Wrapper.hpp"

class PersistentQueueStorage : public IPersistentQueueStorage
{
    public:
        inline static constexpr const char* DEFAULT_DB_PATH = "queue/agent_modules_state.db";

        explicit PersistentQueueStorage(const std::string& dbPath = DEFAULT_DB_PATH);
        ~PersistentQueueStorage() override = default;

        void save(const std::string& module, const PersistedData& data) override;
        void remove(const std::string& module, uint64_t sequence) override;
        void removeAll(const std::string& module) override;
        std::vector<PersistedData> loadAll(const std::string& module) override;

    private:
        SQLite::Connection m_connection;

        void createTableIfNotExists();
        SQLite::Connection createOrOpenDatabase(const std::string& dbPath);
};
