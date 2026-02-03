#pragma once

#include <idbsync.hpp>
#include <json.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

class SCASyncManager
{
    public:
        struct LimitResult
        {
            std::vector<std::string> promotedIds;
            std::vector<std::string> demotedIds;
        };

        struct DeleteResult
        {
            bool wasSynced {false};
            std::vector<std::string> promotedIds;
        };

        explicit SCASyncManager(std::shared_ptr<IDBSync> dbSync);

        void initialize();
        LimitResult updateHandshake(uint64_t syncLimit, const std::string& clusterName);

        // Precompute the first N check ids (ORDER BY rowid LIMIT N) once per batch so
        // shouldSyncInsert/shouldSyncModify avoid per-event DB queries.
        void preparePolicyDeltaWindow();
        void clearPolicyDeltaWindow();

        bool shouldSyncInsert(const nlohmann::json& checkData);
        bool shouldSyncModify(const nlohmann::json& checkData);
        DeleteResult handleDelete(const nlohmann::json& checkData);
        void applyDeferredUpdates();
        void reconcile();

    private:
        struct PendingUpdate
        {
            std::string checkId;
            uint64_t version {0};
            int syncValue {0};
        };

        void ensureInitializedLocked();
        LimitResult enforceLimitLocked();
        void updateSyncFlag(const std::string& checkId, uint64_t version, int syncValue);
        void deferSyncFlagUpdate(const std::string& checkId, uint64_t version, int syncValue);
        void setPolicyDeltaWindowLocked(std::unordered_set<std::string> windowIds);
        std::vector<nlohmann::json> selectChecks(const std::string& filter, uint32_t limit) const;
        std::string clusterNameForLog() const;

        std::shared_ptr<IDBSync> m_dBSync;
        mutable std::mutex m_mutex;
        bool m_initialized {false};
        uint64_t m_syncLimit {0};
        uint64_t m_totalCount {0};
        uint64_t m_syncedCount {0};
        std::unordered_set<std::string> m_syncedIds;
        std::unordered_set<std::string> m_policyDeltaWindowIds;
        bool m_hasPolicyDeltaWindow {false};
        std::vector<PendingUpdate> m_pendingUpdates;
        std::string m_clusterName;
};
