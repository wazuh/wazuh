#pragma once

#include "logging_helper.h"

#include <functional>
#include <string>
#include <vector>

class IDBSync;
class IAgentSyncProtocol;

/**
 * @brief Handles startup cleanup for collectors that are now disabled.
 *
 * @details This service exists for one small job. Sometimes a collector was
 *          enabled before, wrote data to the local database, and is now
 *          disabled in the new configuration. When that happens, Syscollector
 *          must find that old data, notify the sync layer, and then remove the
 *          local rows.
 *
 *          Keeping that logic here makes Syscollector easier to read. The main
 *          class can stay focused on scan and sync flow, while this service
 *          owns the cleanup steps for disabled collectors.
 *
 *          The service keeps a short-lived list of the affected indices so the
 *          notify step and the delete step use the same snapshot.
 */
class DisabledCollectorsCleanupService final
{
    public:
        /**
         * @brief Tells the service which collectors are enabled right now.
         *
         * @details Syscollector already knows the current configuration. This
         *          struct is the simple input passed to the cleanup service so
         *          it can decide which disabled collectors still have old data
         *          in the database.
         */
        struct CollectorSelection
        {
            bool hardware;
            bool os;
            bool network;
            bool packages;
            bool ports;
            bool processes;
            bool hotfixes;
            bool groups;
            bool users;
            bool services;
            bool browserExtensions;
        };

        /**
         * @brief Creates the service with Syscollector's logger.
         *
         * @details Cleanup may remove local inventory data, so it is important
         *          to log what the service is doing. The service reuses the
         *          same logger as Syscollector instead of introducing a new
         *          logging layer.
         *
         * @param logFunction Callback used for info, debug and error logs.
         */
        explicit DisabledCollectorsCleanupService(std::function<void(const modules_log_level_t, const std::string&)> logFunction);

        /**
         * @brief Builds the list of disabled indices that still have data.
         *
         * @details This is the first cleanup step. The method checks the
         *          related DBSync tables, maps those tables to sync indices,
         *          and stores only the indices that are disabled and still have
         *          rows in the database.
         *
         *          It also handles the VD dependency. If old OS, packages or
         *          hotfixes data is found, the vulnerabilities index is also
         *          marked for cleanup.
         *
         * @param collectors Current collector enablement snapshot.
         * @param dbSync Database access used to check whether tables have rows.
         */
        void refreshDisabledIndices(const CollectorSelection& collectors, IDBSync* dbSync);

        /**
         * @brief Sends DataClean messages for the tracked disabled indices.
         *
         * @details Syscollector still decides when cleanup should happen. This
         *          method only uses the indices found earlier and asks the sync
         *          protocol to notify the manager before local data is deleted.
         *
         * @param syncProtocol Sync protocol used to send DataClean messages.
         * @return true if there is nothing to notify or the notification
         *         succeeds. Returns false if there is cleanup to do but the
         *         protocol is missing or the notification fails.
         */
        bool notifyDataClean(IAgentSyncProtocol* syncProtocol) const;

        /**
         * @brief Deletes local rows for the tracked disabled indices.
         *
         * @details This is the local cleanup step. The method clears every
         *          table linked to the tracked indices, then clears the in-memory
         *          list so the same cleanup is not reused by mistake.
         *
         * @param dbSync Database access used to clear the affected tables.
         */
        void deleteDisabledData(IDBSync* dbSync);

        /**
         * @brief Tells whether there is pending cleanup work.
         *
         * @return true when disabled indices with old data were found, false
         *         otherwise.
         */
        bool hasDisabledData() const;

        /**
         * @brief Clears the tracked cleanup state.
         *
         * @details Syscollector uses this after special cases, such as full
         *          database deletion, where the stored list is no longer useful.
         */
        void clearTrackedIndices();

    private:
        /**
         * @brief Checks whether a table has any rows.
         *
         * @details Cleanup only needs to know whether old data exists. One row
         *          is enough to mark the related index as stale.
         *
         * @param dbSync Database access used to run the count query.
         * @param tableName Table to inspect.
         * @return true when the table has at least one row, false otherwise or
         *         if the query fails.
         */
        bool hasDataInTable(IDBSync* dbSync, const std::string& tableName) const;

        /**
         * @brief Clears the tables that belong to the given indices.
         *
         * @details The sync side talks in index names, but local deletion works
         *          on DBSync tables. This helper translates from indices to
         *          table names and clears each table.
         *
         * @param dbSync Database access used to obtain the DBSync handle.
         * @param indices Indices whose tables must be cleared.
         */
        void clearTablesForIndices(IDBSync* dbSync, const std::vector<std::string>& indices) const;

        /**
         * @brief Formats the tracked indices for logging.
         *
         * @details This keeps string building out of the cleanup flow methods so
         *          those methods stay focused on the actual cleanup logic.
         *
         * @return Comma-separated list of tracked sync indices.
         */
        std::string formatIndices() const;

        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;
        std::vector<std::string> m_disabledCollectorsIndicesWithData;
};
