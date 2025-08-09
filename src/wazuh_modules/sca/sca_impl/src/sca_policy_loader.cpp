#include <sca_policy_loader.hpp>

#include <sca_checksum.hpp>
#include <sca_policy.hpp>
#include <sca_policy_parser.hpp>
#include <sca_utils.hpp>

#include <dbsync.hpp>
#include <filesystem_wrapper.hpp>

#include <algorithm>

#include "logging_helper.hpp"

SCAPolicyLoader::SCAPolicyLoader(const std::vector<sca::PolicyData>& policies,
                                 std::shared_ptr<IFileSystemWrapper> fileSystemWrapper,
                                 std::shared_ptr<IDBSync> dBSync)
    : m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper)
                                            : std::make_shared<file_system::FileSystemWrapper>())
    , m_dBSync(std::move(dBSync))
{
    const auto loadPoliciesPathsFromConfig = [this](const std::vector<sca::PolicyData>& policiesStrPaths)
    {
        std::vector<sca::PolicyData> returnPolicies;

        for (const auto& policy : policiesStrPaths)
        {
            if (m_fileSystemWrapper->exists(policy.path))
            {
                returnPolicies.emplace_back(policy);
            }
            else
            {
                LoggingHelper::getInstance().log(LOG_WARNING, "Policy file does not exist: " + policy.path);
            }
        }
        return returnPolicies;
    };

    m_customPoliciesPaths = loadPoliciesPathsFromConfig(policies);
}

std::vector<std::unique_ptr<ISCAPolicy>> SCAPolicyLoader::LoadPolicies(const int commandsTimeout,
                                 const bool remoteEnabled,const CreateEventsFunc& createEvents) const
{
    std::vector<std::unique_ptr<ISCAPolicy>> policies;
    nlohmann::json policiesAndChecks;
    policiesAndChecks["policies"] = nlohmann::json::array();
    policiesAndChecks["checks"] = nlohmann::json::array();

    for (const auto& pol : m_customPoliciesPaths)
    {
        if (pol.isEnabled)
        {
            try
            {
                LoggingHelper::getInstance().log(LOG_DEBUG, "Loading policy from " + pol.path);

                PolicyParser parser(pol.path, commandsTimeout, remoteEnabled || !pol.isRemote);

                if (auto policy = parser.ParsePolicy(policiesAndChecks); policy)
                {
                    policies.emplace_back(std::move(policy));
                }
                else
                {
                    LoggingHelper::getInstance().log(LOG_WARNING, "Failed to parse policy from  " + pol.path);
                }
            }
            catch (const std::exception& e)
            {
                LoggingHelper::getInstance().log(LOG_WARNING, "Failed to parse policy from  " + pol.path + ": " + e.what());
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_INFO, "Policy " + pol.path + " is disabled");
        }
    }

    if (!policiesAndChecks["policies"].empty() && !policiesAndChecks["checks"].empty())
    {
        SyncPoliciesAndReportDelta(policiesAndChecks, createEvents);
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_WARNING, "No policies and checks found to synchronize");
    }

    return policies;
}

void SCAPolicyLoader::SyncPoliciesAndReportDelta(const nlohmann::json& data, const CreateEventsFunc& createEvents) const
{
    std::unordered_map<std::string, nlohmann::json> modifiedPoliciesMap;
    std::unordered_map<std::string, nlohmann::json> modifiedChecksMap;

    if (data.contains("policies") && data.at("policies").is_array())
    {
        modifiedPoliciesMap = SyncWithDBSync(data["policies"], SCA_POLICY_TABLE_NAME);
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "No policies found in data");
        return;
    }

    if (data.contains("checks") && data.at("checks").is_array())
    {
        modifiedChecksMap = SyncWithDBSync(data["checks"], SCA_CHECK_TABLE_NAME);

        for (auto& check : modifiedChecksMap)
        {
            try
            {
                if (check.second["result"] == INSERTED)
                {
                    check.second["data"]["result"] = sca::CheckResultToString(sca::CheckResult::NotRun);
                }
                else if (check.second["result"] == MODIFIED)
                {
                    check.second["data"]["new"]["result"] = sca::CheckResultToString(sca::CheckResult::NotRun);
                    UpdateCheckResult(check.second["data"]["new"]);
                }
            }
            catch (const std::exception& e)
            {
                LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to update check result: ") + e.what());
            }
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "No checks found in data");
        return;
    }

    createEvents(modifiedPoliciesMap, modifiedChecksMap);
}

std::unordered_map<std::string, nlohmann::json> SCAPolicyLoader::SyncWithDBSync(const nlohmann::json& data,
                                                                                const std::string& tableName) const
{
    static std::unordered_map<std::string, nlohmann::json> modifiedDataMap;
    modifiedDataMap.clear();

    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot synchronize data");
        return modifiedDataMap;
    }

    const auto callback {[](ReturnTypeCallback result, const nlohmann::json& rowData)
                         {
                             if (result != DB_ERROR)
                             {
                                 std::string id;
                                 if (result == MODIFIED && rowData.contains("new") && rowData["new"].is_object())
                                 {
                                     if (rowData["new"].contains("id") && rowData["new"]["id"].is_string())
                                     {
                                         id = rowData["new"]["id"];
                                     }
                                 }
                                 else if ((result == INSERTED || result == DELETED) && rowData.contains("id") &&
                                          rowData["id"].is_string())
                                 {
                                     id = rowData["id"];
                                 }

                                 if (!id.empty())
                                 {
                                     modifiedDataMap[id] = nlohmann::json {{"result", result}, {"data", rowData}};
                                 }
                                 else
                                 {
                                     LoggingHelper::getInstance().log(LOG_ERROR, "Invalid data:  " + rowData.dump());
                                 }
                             }
                             else
                             {
                                 LoggingHelper::getInstance().log(LOG_ERROR,
                                                                  "Failed to parse policy from  " + rowData.dump());
                             }
                         }};

    DBSyncTxn txn {m_dBSync->handle(), nlohmann::json {tableName}, 0, DBSYNC_QUEUE_SIZE, callback};

    nlohmann::json input;
    input["table"] = tableName;
    input["data"] = NormalizeDataWithChecksum(data, tableName);
    input["options"]["return_old_data"] = true;

    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);

    return modifiedDataMap;
}

void SCAPolicyLoader::UpdateCheckResult(const nlohmann::json& check) const
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot update check result");
        return;
    }

    // Calculate and add checksum to the check data
    nlohmann::json checkWithChecksum = check;

    try
    {
        const auto checksum = sca::calculateChecksum(checkWithChecksum);
        checkWithChecksum["checksum"] = checksum;
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(
            LOG_ERROR, "Failed to calculate checksum for check result update: " + std::string(e.what()));

        return;
    }

    auto updateResultQuery = SyncRowQuery::builder().table(SCA_CHECK_TABLE_NAME).data(checkWithChecksum).build();

    const auto callback = [](ReturnTypeCallback, const nlohmann::json&) {
    };

    m_dBSync->syncRow(updateResultQuery.query(), callback);
}

nlohmann::json SCAPolicyLoader::NormalizeData(nlohmann::json data) const
{
    for (auto& entry : data)
    {
        if (entry.contains("references"))
        {
            entry["refs"] = entry["references"];
            entry.erase("references");
        }

        if (entry.contains("title"))
        {
            entry["name"] = entry["title"];
            entry.erase("title");
        }
    }

    return data;
}

nlohmann::json SCAPolicyLoader::NormalizeDataWithChecksum(nlohmann::json data, const std::string& tableName) const
{
    data = NormalizeData(data);

    // If this is check data, calculate and add checksums
    if (tableName == SCA_CHECK_TABLE_NAME)
    {
        for (auto& entry : data)
        {
            try
            {
                const auto checksum = sca::calculateChecksum(entry);
                entry["checksum"] = checksum;
            }
            catch (const std::exception& e)
            {
                LoggingHelper::getInstance().log(
                    LOG_ERROR, "Failed to calculate checksum for check: " + entry.dump() + " - " + e.what());
            }
        }
    }

    return data;
}
