#include <sca_sync_manager.hpp>

#include <dbsync.hpp>

#include <algorithm>

#include "logging_helper.hpp"
#include "stringHelper.h"

namespace
{
    std::string extractId(const nlohmann::json& data)
    {
        if (!data.contains("id"))
        {
            return {};
        }

        if (data["id"].is_string())
        {
            return data["id"].get<std::string>();
        }

        if (data["id"].is_number_integer())
        {
            return std::to_string(data["id"].get<int>());
        }

        return {};
    }

    std::string escapeSqlString(std::string input)
    {
        Utils::replaceAll(input, "'", "''");
        return input;
    }
}

SCASyncManager::SCASyncManager(std::shared_ptr<IDBSync> dbSync)
    : m_dBSync(std::move(dbSync))
{
}

void SCASyncManager::initialize()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    enforceLimitLocked();
    m_initialized = true;
}

void SCASyncManager::updateHandshake(uint64_t syncLimit, const std::string& clusterName)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const bool limitChanged = (syncLimit != m_syncLimit);

    m_syncLimit = syncLimit;

    if (!clusterName.empty())
    {
        m_clusterName = clusterName;
    }

    if (!m_initialized)
    {
        return;
    }

    if (limitChanged)
    {
        enforceLimitLocked();
    }
}

bool SCASyncManager::shouldSyncInsert(const nlohmann::json& checkData)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureInitializedLocked();

    const std::string checkId = extractId(checkData);

    if (checkId.empty())
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "SCA sync manager: insert without check id");
        return false;
    }

    ++m_totalCount;

    bool shouldSync = true;

    if (m_syncLimit != 0)
    {
        if (!m_dBSync)
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "SCA sync manager: DBSync not available on insert");
            return false;
        }

        const std::string escapedId = escapeSqlString(checkId);
        uint64_t rowRank = 0;

        auto countQuery = SelectQuery::builder()
                          .table("sca_check")
                          .columnList({"COUNT(*) AS count"})
                          .rowFilter("WHERE rowid <= (SELECT rowid FROM sca_check WHERE id = '" + escapedId + "')")
                          .build();

        const auto countCallback = [&rowRank](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("count") && resultData["count"].is_number())
            {
                rowRank = resultData["count"].get<uint64_t>();
            }
        };

        m_dBSync->selectRows(countQuery.query(), countCallback);

        shouldSync = (rowRank != 0 && rowRank <= m_syncLimit);
    }

    const int desiredSync = shouldSync ? 1 : 0;

    int currentSync = 0;

    if (checkData.contains("sync") && checkData["sync"].is_number())
    {
        currentSync = checkData["sync"].get<int>();
    }

    if (shouldSync)
    {
        m_syncedIds.insert(checkId);
        ++m_syncedCount;
    }

    if (currentSync != desiredSync)
    {
        if (!checkData.contains("version"))
        {
            LoggingHelper::getInstance().log(LOG_ERROR,
                                             "SCA sync manager: insert without version for check " + checkId);
        }
        else
        {
            deferSyncFlagUpdate(checkId, checkData["version"].get<uint64_t>(), desiredSync);
        }
    }

    return shouldSync;
}

bool SCASyncManager::shouldSyncModify(const nlohmann::json& checkData)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureInitializedLocked();

    const std::string checkId = extractId(checkData);

    if (checkId.empty())
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "SCA sync manager: modify without check id");
        return false;
    }

    if (m_syncLimit == 0)
    {
        return true;
    }

    if (m_syncedIds.find(checkId) != m_syncedIds.end())
    {
        return true;
    }

    if (m_syncedCount >= m_syncLimit)
    {
        return false;
    }

    if (!checkData.contains("version"))
    {
        LoggingHelper::getInstance().log(LOG_ERROR,
                                         "SCA sync manager: modify without version for check " + checkId);
        return false;
    }

    deferSyncFlagUpdate(checkId, checkData["version"].get<uint64_t>(), 1);
    m_syncedIds.insert(checkId);
    ++m_syncedCount;

    LoggingHelper::getInstance().log(
        LOG_INFO,
        "SCA sync limit promotion: promoted check " + checkId + " on modify for cluster '" + clusterNameForLog() + "'");

    return true;
}

SCASyncManager::DeleteResult SCASyncManager::handleDelete(const nlohmann::json& checkData)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureInitializedLocked();

    DeleteResult result;
    const std::string checkId = extractId(checkData);

    if (checkId.empty())
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "SCA sync manager: delete without check id");
        return result;
    }

    if (m_totalCount > 0)
    {
        --m_totalCount;
    }

    auto it = m_syncedIds.find(checkId);

    if (it != m_syncedIds.end())
    {
        result.wasSynced = true;
        m_syncedIds.erase(it);

        if (m_syncedCount > 0)
        {
            --m_syncedCount;
        }
    }

    if (m_syncLimit == 0)
    {
        return result;
    }

    const uint64_t desiredSynced = std::min(m_syncLimit, m_totalCount);

    if (m_syncedCount >= desiredSynced)
    {
        return result;
    }

    const auto needed = static_cast<uint32_t>(desiredSynced - m_syncedCount);
    const auto rows = selectChecks("WHERE sync = 0", needed);

    for (const auto& row : rows)
    {
        const std::string promoteId = extractId(row);

        if (promoteId.empty() || !row.contains("version"))
        {
            continue;
        }

        deferSyncFlagUpdate(promoteId, row["version"].get<uint64_t>(), 1);
        m_syncedIds.insert(promoteId);
        ++m_syncedCount;
        result.promotedIds.push_back(promoteId);

        if (m_syncedCount >= desiredSynced)
        {
            break;
        }
    }

    if (!result.promotedIds.empty())
    {
        LoggingHelper::getInstance().log(
            LOG_INFO,
            "SCA sync limit promotion: promoted " + std::to_string(result.promotedIds.size()) +
            " check(s) for cluster '" + clusterNameForLog() + "'");
    }

    return result;
}

void SCASyncManager::ensureInitializedLocked()
{
    if (!m_initialized)
    {
        enforceLimitLocked();
        m_initialized = true;
    }
}

void SCASyncManager::enforceLimitLocked()
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "SCA sync manager: DBSync not available");
        return;
    }

    m_syncedIds.clear();
    m_totalCount = 0;
    m_syncedCount = 0;

    const auto rows = selectChecks("", 0);
    const bool unlimited = (m_syncLimit == 0);

    for (const auto& row : rows)
    {
        ++m_totalCount;
        const std::string checkId = extractId(row);

        if (checkId.empty() || !row.contains("version"))
        {
            continue;
        }

        const bool shouldSync = unlimited || (m_syncedCount < m_syncLimit);
        const int desiredSync = shouldSync ? 1 : 0;

        if (shouldSync)
        {
            m_syncedIds.insert(checkId);
            ++m_syncedCount;
        }

        int currentSync = 0;

        if (row.contains("sync") && row["sync"].is_number())
        {
            currentSync = row["sync"].get<int>();
        }

        if (currentSync != desiredSync)
        {
            updateSyncFlag(checkId, row["version"].get<uint64_t>(), desiredSync);
        }
    }

    if (m_syncLimit == 0)
    {
        LoggingHelper::getInstance().log(
            LOG_INFO,
            "SCA sync limit disabled; syncing " + std::to_string(m_syncedCount) +
            " check(s) for cluster '" + clusterNameForLog() + "'");
    }
    else
    {
        LoggingHelper::getInstance().log(
            LOG_INFO,
            "SCA sync limit enforced: limit=" + std::to_string(m_syncLimit) +
            " synced=" + std::to_string(m_syncedCount) +
            " total=" + std::to_string(m_totalCount) +
            " cluster='" + clusterNameForLog() + "'");
    }
}

void SCASyncManager::updateSyncFlag(const std::string& checkId, uint64_t version, int syncValue)
{
    if (!m_dBSync)
    {
        return;
    }

    nlohmann::json data;
    data["id"] = checkId;
    data["sync"] = syncValue;
    data["version"] = version;

    auto updateQuery = SyncRowQuery::builder().table("sca_check").data(data).build();
    const auto callback = [](ReturnTypeCallback, const nlohmann::json&)
    {
    };
    m_dBSync->syncRow(updateQuery.query(), callback);
}

void SCASyncManager::deferSyncFlagUpdate(const std::string& checkId, uint64_t version, int syncValue)
{
    m_pendingUpdates.push_back({checkId, version, syncValue});
}

void SCASyncManager::applyDeferredUpdates()
{
    std::vector<PendingUpdate> pending;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pendingUpdates.empty())
        {
            return;
        }

        pending.swap(m_pendingUpdates);
    }

    for (const auto& update : pending)
    {
        updateSyncFlag(update.checkId, update.version, update.syncValue);
    }
}

std::vector<nlohmann::json> SCASyncManager::selectChecks(const std::string& filter, uint32_t limit) const
{
    std::vector<nlohmann::json> rows;

    if (!m_dBSync)
    {
        return rows;
    }

    auto builder = SelectQuery::builder()
                   .table("sca_check")
                   .columnList({"rowid", "id", "version", "sync"})
                   .orderByOpt("rowid");

    if (!filter.empty())
    {
        builder.rowFilter(filter);
    }

    if (limit > 0)
    {
        builder.countOpt(limit);
    }

    auto query = builder.build();

    const auto callback = [&rows](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
    {
        if (returnTypeCallback == SELECTED)
        {
            rows.push_back(resultData);
        }
    };

    m_dBSync->selectRows(query.query(), callback);

    return rows;
}

std::string SCASyncManager::clusterNameForLog() const
{
    return m_clusterName.empty() ? "unknown" : m_clusterName;
}
