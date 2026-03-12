/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "disabledCollectorsCleanupService.hpp"

#include "dbsync.hpp"
#include "iagent_sync_protocol.hpp"
#include "syscollector.h"
#include "syscollectorTablesDef.hpp"

#include <map>
#include <utility>

namespace
{
    constexpr auto QUEUE_SIZE
    {
        4096
    };

    const std::map<std::string, std::string> INDEX_MAP
    {
        {OS_TABLE, SYSCOLLECTOR_SYNC_INDEX_SYSTEM},
        {HW_TABLE, SYSCOLLECTOR_SYNC_INDEX_HARDWARE},
        {HOTFIXES_TABLE, SYSCOLLECTOR_SYNC_INDEX_HOTFIXES},
        {PACKAGES_TABLE, SYSCOLLECTOR_SYNC_INDEX_PACKAGES},
        {PROCESSES_TABLE, SYSCOLLECTOR_SYNC_INDEX_PROCESSES},
        {PORTS_TABLE, SYSCOLLECTOR_SYNC_INDEX_PORTS},
        {NET_IFACE_TABLE, SYSCOLLECTOR_SYNC_INDEX_INTERFACES},
        {NET_PROTOCOL_TABLE, SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS},
        {NET_ADDRESS_TABLE, SYSCOLLECTOR_SYNC_INDEX_NETWORKS},
        {USERS_TABLE, SYSCOLLECTOR_SYNC_INDEX_USERS},
        {GROUPS_TABLE, SYSCOLLECTOR_SYNC_INDEX_GROUPS},
        {SERVICES_TABLE, SYSCOLLECTOR_SYNC_INDEX_SERVICES},
        {BROWSER_EXTENSIONS_TABLE, SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS},
    };
}

DisabledCollectorsCleanupService::DisabledCollectorsCleanupService(std::function<void(const modules_log_level_t, const std::string&)> logFunction)
    : m_logFunction(std::move(logFunction))
{
}

void DisabledCollectorsCleanupService::refreshDisabledIndices(const CollectorSelection& collectors, IDBSync* dbSync)
{
    m_disabledCollectorsIndicesWithData.clear();
    bool alreadyIncludedVd = false;

    if (!collectors.hardware && hasDataInTable(dbSync, HW_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_HARDWARE);
    }

    if (!collectors.os && hasDataInTable(dbSync, OS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

        if (!alreadyIncludedVd)
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES);
            alreadyIncludedVd = true;
        }
    }

    if (!collectors.packages && hasDataInTable(dbSync, PACKAGES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

        if (!alreadyIncludedVd)
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES);
            alreadyIncludedVd = true;
        }
    }

    if (!collectors.hotfixes && hasDataInTable(dbSync, HOTFIXES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

        if (!alreadyIncludedVd)
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES);
        }
    }

    if (!collectors.processes && hasDataInTable(dbSync, PROCESSES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PROCESSES);
    }

    if (!collectors.ports && hasDataInTable(dbSync, PORTS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PORTS);
    }

    if (!collectors.users && hasDataInTable(dbSync, USERS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_USERS);
    }

    if (!collectors.groups && hasDataInTable(dbSync, GROUPS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_GROUPS);
    }

    if (!collectors.services && hasDataInTable(dbSync, SERVICES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_SERVICES);
    }

    if (!collectors.browserExtensions && hasDataInTable(dbSync, BROWSER_EXTENSIONS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS);
    }

    if (!collectors.network)
    {
        if (hasDataInTable(dbSync, NET_IFACE_TABLE))
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_INTERFACES);
        }

        if (hasDataInTable(dbSync, NET_PROTOCOL_TABLE))
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS);
        }

        if (hasDataInTable(dbSync, NET_ADDRESS_TABLE))
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_NETWORKS);
        }
    }

    if (!m_disabledCollectorsIndicesWithData.empty() && m_logFunction)
    {
        m_logFunction(LOG_INFO, "Disabled collectors indices with data detected: " + formatIndices());
    }
}

bool DisabledCollectorsCleanupService::notifyDataClean(IAgentSyncProtocol* syncProtocol) const
{
    if (m_disabledCollectorsIndicesWithData.empty())
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "No disabled collectors indices with data to notify for cleanup");
        }

        return true;
    }

    if (!syncProtocol)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Sync protocol not initialized, cannot notify data clean");
        }

        return false;
    }

    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Notifying DataClean for disabled collectors indices: " + formatIndices());
    }

    return syncProtocol->notifyDataClean(m_disabledCollectorsIndicesWithData);
}

void DisabledCollectorsCleanupService::deleteDisabledData(IDBSync* dbSync)
{
    if (m_disabledCollectorsIndicesWithData.empty())
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "No disabled collectors indices with data to delete");
        }

        return;
    }

    if (m_logFunction)
    {
        m_logFunction(LOG_INFO, "Deleting data for disabled collectors indices: " + formatIndices());
    }

    clearTablesForIndices(dbSync, m_disabledCollectorsIndicesWithData);
    m_disabledCollectorsIndicesWithData.clear();
}

bool DisabledCollectorsCleanupService::hasDisabledData() const
{
    return !m_disabledCollectorsIndicesWithData.empty();
}

void DisabledCollectorsCleanupService::clearTrackedIndices()
{
    m_disabledCollectorsIndicesWithData.clear();
}

bool DisabledCollectorsCleanupService::hasDataInTable(IDBSync* dbSync, const std::string& tableName) const
{
    if (!dbSync)
    {
        return false;
    }

    try
    {
        int count = 0;
        auto selectQuery = SelectQuery::builder().table(tableName).columnList({"COUNT(*) AS count"}).build();

        const auto callback = [&count](ReturnTypeCallback returnType, const nlohmann::json & resultData)
        {
            if (returnType == SELECTED && resultData.contains("count"))
            {
                if (resultData["count"].is_number())
                {
                    count = resultData["count"].get<int>();
                }
            }
        };

        dbSync->selectRows(selectQuery.query(), callback);
        return count > 0;
    }
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Error checking data in table " + tableName + ": " + std::string(ex.what()));
        }

        return false;
    }
}

void DisabledCollectorsCleanupService::clearTablesForIndices(IDBSync* dbSync, const std::vector<std::string>& indices) const
{
    if (!dbSync)
    {
        return;
    }

    auto dbHandle = dbSync->handle();

    if (dbHandle == nullptr)
    {
        return;
    }

    for (const auto& index : indices)
    {
        std::string tableName;

        for (const auto& [table, mappedIndex] : INDEX_MAP)
        {
            if (mappedIndex == index)
            {
                tableName = table;
                break;
            }
        }

        if (!tableName.empty())
        {
            try
            {
                const auto deleteCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

                DBSyncTxn txn
                {
                    dbHandle,
                    nlohmann::json {tableName},
                    0,
                    QUEUE_SIZE,
                    deleteCallback
                };

                nlohmann::json emptyInput;
                emptyInput["table"] = tableName;
                emptyInput["data"] = nlohmann::json::array();

                txn.syncTxnRow(emptyInput);
                txn.getDeletedRows(deleteCallback);

                if (m_logFunction)
                {
                    m_logFunction(LOG_DEBUG, "Cleared table " + tableName);
                }
            }
            catch (const std::exception& ex)
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_ERROR, "Error clearing table " + tableName + ": " + std::string(ex.what()));
                }
            }
        }
    }
}

std::string DisabledCollectorsCleanupService::formatIndices() const
{
    std::string indices;

    for (const auto& index : m_disabledCollectorsIndicesWithData)
    {
        if (!indices.empty())
        {
            indices += ", ";
        }

        indices += index;
    }

    return indices;
} // LCOV_EXCL_LINE
