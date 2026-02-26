#include <sca_checksum.hpp>
#include <sca_event_handler.hpp>
#include <sca_sync_manager.hpp>

#include <dbsync.hpp>
#include <hashHelper.h>
#include <stringHelper.h>
#include <timeHelper.h>

#include <map>
#include <sstream>

#include "logging_helper.hpp"
#include "agent_sync_protocol.hpp"
#include "sca.h"
#include "schemaValidator.hpp"

/// @brief Map of stateless operations
static const std::map<ReturnTypeCallback, std::string> STATELESS_OPERATION_MAP
{
    // LCOV_EXCL_START
    {MODIFIED, "modified"},
    {DELETED, "deleted"},
    {INSERTED, "created"},
    // LCOV_EXCL_STOP
};

/// @brief Map of stateful operations
static const std::map<ReturnTypeCallback, Operation_t> OPERATION_STATES_MAP
{
    // LCOV_EXCL_START
    {MODIFIED, OPERATION_MODIFY},
    {DELETED, OPERATION_DELETE},
    {INSERTED, OPERATION_CREATE},
    // LCOV_EXCL_STOP
};

SCAEventHandler::SCAEventHandler(std::shared_ptr<IDBSync> dBSync,
                                 std::function<int(const std::string&)> pushStatelessMessage,
                                 std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> pushStatefulMessage,
                                 std::shared_ptr<SCASyncManager> syncManager)
    : m_pushStatelessMessage(std::move(pushStatelessMessage))
    , m_pushStatefulMessage(std::move(pushStatefulMessage))
    , m_dBSync(std::move(dBSync))
    , m_syncManager(std::move(syncManager)) {};

void SCAEventHandler::ReportPoliciesDelta(
    const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
    const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap) const
{
    const nlohmann::json events = ProcessEvents(modifiedPoliciesMap, modifiedChecksMap);

    // Vector to accumulate checks that fail validation for deferred deletion
    std::vector<nlohmann::json> failedChecks;

    if (m_syncManager)
    {
        m_syncManager->prepareBatchAllowedIds();
    }

    const auto extractCheckData = [](const nlohmann::json & event)
    {
        nlohmann::json checkData;

        if (event.contains("check") && event["check"].is_object())
        {
            if (event["check"].contains("new") && event["check"]["new"].is_object())
            {
                checkData = event["check"]["new"];
            }
            else
            {
                checkData = event["check"];
            }
        }

        return checkData;
    };

    const auto extractCheckId = [](const nlohmann::json & checkData)
    {
        if (checkData.contains("id"))
        {
            if (checkData["id"].is_string())
            {
                return checkData["id"].get<std::string>();
            }

            if (checkData["id"].is_number_integer())
            {
                return std::to_string(checkData["id"].get<int>());
            }
        }

        return std::string {};
    };

    for (const auto& event : events)
    {
        // Validate and handle stateful message
        nlohmann::json checkDataForDelete = extractCheckData(event);
        const std::string checkId = extractCheckId(checkDataForDelete);

        bool shouldPushStateful = true;
        std::vector<std::string> promotedIds;

        if (m_syncManager)
        {
            const auto result = static_cast<ReturnTypeCallback>(event["result"].get<int>());

            if (result == INSERTED)
            {
                shouldPushStateful = m_syncManager->shouldSyncInsert(checkDataForDelete);
            }
            else if (result == MODIFIED)
            {
                shouldPushStateful = m_syncManager->shouldSyncModify(checkDataForDelete);
            }
            else if (result == DELETED)
            {
                auto deleteResult = m_syncManager->handleDelete(checkDataForDelete);
                shouldPushStateful = deleteResult.wasSynced;
                promotedIds = std::move(deleteResult.promotedIds);
            }
        }

        const auto [processedStatefulEvent, operation, version] = ProcessStateful(event);

        const bool validationPassed = ValidateAndHandleStatefulMessage(
                                          processedStatefulEvent,
                                          "policy/check event",
                                          checkDataForDelete,
                                          &failedChecks
                                      );

        if (validationPassed && shouldPushStateful)
        {
            PushStateful(processedStatefulEvent, operation, version);
        }

        const auto processedStatelessEvent = ProcessStateless(event);

        if (!processedStatelessEvent.empty())
        {
            PushStateless(processedStatelessEvent);
        }

        if (!promotedIds.empty())
        {
            ProcessPromotedChecks(promotedIds, &failedChecks);
        }
    }

    HandleFailedChecks(std::move(failedChecks));

    if (m_syncManager)
    {
        m_syncManager->applyDeferredUpdates();
        m_syncManager->clearBatchAllowedIds();
    }
}

void SCAEventHandler::ReportDemotedChecks(const std::vector<std::string>& demotedIds) const
{
    if (demotedIds.empty())
    {
        return;
    }

    std::vector<nlohmann::json> failedChecks;

    ProcessDemotedChecks(demotedIds, &failedChecks);

    if (!failedChecks.empty())
    {
        HandleFailedChecks(std::move(failedChecks));
    }
}

void SCAEventHandler::ReportCheckResult(const std::string& policyId,
                                        const std::string& checkId,
                                        const std::string& checkResult,
                                        const std::string& reason) const
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot report check result");
        return;
    }

    auto policyData = GetPolicyById(policyId);
    auto checkData = GetPolicyCheckById(checkId);

    // Check if the check exists in DB (may have been deleted due to validation failure)
    if (checkData.empty() || !checkData.contains("id"))
    {
        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "Check " + checkId + " not found in DB (may have been deleted due to validation failure), skipping report");
        return;
    }

    checkData["result"] = checkResult;

    // Set reason field if provided and check result indicates an invalid check
    if (!reason.empty() && checkResult == "Not applicable")
    {
        checkData["reason"] = reason;
    }

    try
    {
        const auto checksum = sca::calculateChecksum(checkData);
        checkData["checksum"] = checksum;
    }
    catch (const std::exception& e)
    {
        // LCOV_EXCL_START
        LoggingHelper::getInstance().log(LOG_ERROR,
                                         "Failed to calculate checksum for check result: " + std::string(e.what()));

        return;
        // LCOV_EXCL_STOP
    }

    auto updateResultQuery = SyncRowQuery::builder().table("sca_check").data(checkData).returnOldData().build();

    // List to accumulate checks that fail validation for deferred deletion
    std::vector<nlohmann::json> failedChecks;

    const auto callback = [&, this](ReturnTypeCallback result, const nlohmann::json & rowData)
    {
        if (result == MODIFIED)
        {
            const nlohmann::json event =
            {
                {"policy", policyData}, {"check", rowData}, {"result", result}, {"collector", "check"}
            };

            bool shouldPushStateful = true;

            // Validate and handle stateful message
            nlohmann::json dataForDelete;

            if (rowData.contains("new"))
            {
                dataForDelete = rowData["new"];
            }
            else
            {
                dataForDelete = rowData;
            }

            if (m_syncManager)
            {
                shouldPushStateful = m_syncManager->shouldSyncModify(dataForDelete);
            }

            const auto [stateful, operation, version] = ProcessStateful(event);

            const bool validationPassed = ValidateAndHandleStatefulMessage(
                                              stateful,
                                              "checkId: " + checkId,
                                              dataForDelete,
                                              &failedChecks
                                          );

            if (validationPassed && shouldPushStateful)
            {
                PushStateful(stateful, operation, version);
            }

            const auto stateless = ProcessStateless(event);

            if (!stateless.empty())
            {
                PushStateless(stateless);
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Failed to update check result: " + rowData.dump()); // LCOV_EXCL_LINE
        }
    };

    m_dBSync->syncRow(updateResultQuery.query(), callback);

    HandleFailedChecks(std::move(failedChecks));

    if (m_syncManager)
    {
        m_syncManager->applyDeferredUpdates();
    }
}

nlohmann::json
SCAEventHandler::ProcessEvents(const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
                               const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap) const
{
    nlohmann::json events = nlohmann::json::array();

    try
    {
        for (const auto& policyEntry : modifiedPoliciesMap)
        {
            const std::string policyId = policyEntry.first;
            const nlohmann::json policyData = policyEntry.second["data"];
            const int policyResult = policyEntry.second["result"];

            const std::vector<nlohmann::json> checksForPolicy = GetChecksForPolicy(policyId);

            for (auto checkData : checksForPolicy)
            {
                const std::string checkId = checkData["id"];

                if (modifiedChecksMap.find(checkId) != modifiedChecksMap.end())
                {
                    continue;
                }

                const nlohmann::json event =
                {
                    {"policy", policyData}, {"check", checkData}, {"result", policyResult}, {"collector", "policy"}
                };
                events.push_back(event);
            }
        }

        for (const auto& checkEntry : modifiedChecksMap)
        {
            nlohmann::json policyData;
            nlohmann::json checkData = checkEntry.second["data"];
            int checkResult = checkEntry.second["result"];

            std::string policyId;

            if (checkResult == MODIFIED)
            {
                policyId = checkData["new"]["policy_id"];
            }
            else
            {
                policyId = checkData["policy_id"];
            }

            if (modifiedPoliciesMap.find(policyId) != modifiedPoliciesMap.end())
            {
                policyData = modifiedPoliciesMap.at(policyId)["data"];
            }
            else
            {
                policyData = GetPolicyById(policyId);
            }

            const nlohmann::json event =
            {
                {"policy", policyData}, {"check", checkData}, {"result", checkResult}, {"collector", "check"}
            };
            events.push_back(event);
        }
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to create events: ") + e.what());
    }

    return events;
}

std::vector<nlohmann::json> SCAEventHandler::GetChecksForPolicy(const std::string& policyId) const
{
    std::vector<nlohmann::json> checks;

    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot get checks for policy");
        return checks;
    }

    const std::string filter = "WHERE policy_id = '" + policyId + "'";
    auto selectQuery = SelectQuery::builder()
                       .table("sca_check")
                       .columnList({"checksum",
                                    "id",
                                    "policy_id",
                                    "name",
                                    "description",
                                    "rationale",
                                    "remediation",
                                    "refs",
                                    "result",
                                    "reason",
                                    "condition",
                                    "compliance",
                                    "rules",
                                    "version"})
                       .rowFilter(filter)
                       .build();

    const auto callback = [&checks](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
    {
        if (returnTypeCallback == SELECTED)
        {
            checks.push_back(resultData);
        }
    };

    m_dBSync->selectRows(selectQuery.query(), callback);

    return checks;
}

nlohmann::json SCAEventHandler::GetPolicyById(const std::string& policyId) const
{
    nlohmann::json policy;

    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot get policy by id");
        return policy;
    }

    const std::string filter = "WHERE id = '" + policyId + "'";
    auto selectQuery = SelectQuery::builder()
                       .table("sca_policy")
                       .columnList({"id", "name", "description", "file", "refs"})
                       .rowFilter(filter)
                       .build();

    const auto callback = [&policy](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
    {
        if (returnTypeCallback == SELECTED)
        {
            policy = resultData;
        }
    };

    m_dBSync->selectRows(selectQuery.query(), callback);

    return policy;
}

nlohmann::json SCAEventHandler::GetPolicyCheckById(const std::string& policyCheckId) const
{
    nlohmann::json check;

    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot get policy check by id");
        return check;
    }

    const std::string filter = "WHERE id = '" + policyCheckId + "'";
    auto selectQuery = SelectQuery::builder()
                       .table("sca_check")
                       .columnList({"checksum",
                                    "id",
                                    "policy_id",
                                    "name",
                                    "description",
                                    "rationale",
                                    "remediation",
                                    "refs",
                                    "result",
                                    "reason",
                                    "condition",
                                    "compliance",
                                    "rules",
                                    "version"})
                       .rowFilter(filter)
                       .build();

    const auto callback = [&check](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
    {
        if (returnTypeCallback == SELECTED)
        {
            check = resultData;
        }
    };

    m_dBSync->selectRows(selectQuery.query(), callback);

    return check;
}

std::tuple<nlohmann::json, ReturnTypeCallback, uint64_t> SCAEventHandler::ProcessStateful(const nlohmann::json& event) const
{
    nlohmann::json check;
    nlohmann::json policy;
    nlohmann::json jsonEvent;
    uint64_t document_version = 0;

    try
    {
        if (event.contains("check") && event["check"].is_object())
        {
            if (event["check"].contains("new") && event["check"]["new"].is_object())
            {
                check = event["check"]["new"];
            }
            else
            {
                check = event["check"];
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Stateful event does not contain check");
            return {{}, SELECTED, 0};
        }

        if (event.contains("policy") && event["policy"].is_object())
        {
            if (event["policy"].contains("new") && event["policy"]["new"].is_object())
            {
                policy = event["policy"]["new"];
            }
            else
            {
                policy = event["policy"];
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Stateful event does not contain policy");
            return {{}, SELECTED, 0};
        }

        NormalizeCheck(check);
        NormalizePolicy(policy);

        // Modify where the checksum is stored in the json structured to what the server expects
        nlohmann::json checksumObj = nlohmann::json::object();

        if (check.contains("checksum") && !check["checksum"].empty())
        {
            checksumObj = {{"hash", {{"sha1", check["checksum"]}}}};
            check.erase("checksum");
        }

        // Add state modified_at and version fields for stateful events only
        nlohmann::json state;
        state["modified_at"] = Utils::getCurrentISO8601();

        // Include document_version field in state for synchronization
        if (check.contains("version"))
        {
            document_version = check["version"].get<uint64_t>();
            state["document_version"] = document_version;
            check.erase("version");
        }

        jsonEvent = {{"checksum", checksumObj}, {"check", check}, {"policy", policy}, {"state", state}};
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Error processing stateful event: ") + e.what());
        return {{}, SELECTED, 0};
    }

    return {jsonEvent, static_cast<ReturnTypeCallback>(event["result"]), document_version};
}

nlohmann::json SCAEventHandler::ProcessStateless(const nlohmann::json& event) const
{
    nlohmann::json check;
    nlohmann::json policy;
    nlohmann::json changedFields = nlohmann::json::array();
    nlohmann::json jsonEvent;

    try
    {
        if (event.contains("check") && event["check"].is_object())
        {
            if (event["check"].contains("new") && event["check"]["new"].is_object())
            {
                check = event["check"]["new"];
            }
            else
            {
                check = event["check"];
            }

            if (check.contains("sync"))
            {
                check.erase("sync");
            }

            if (event["check"].contains("old") && event["check"]["old"].is_object())
            {
                const auto& old = event["check"]["old"];
                nlohmann::json previous;

                for (auto& [key, value] : old.items())
                {
                    if (key == "id" || key == "sync")
                    {
                        continue;
                    }

                    previous[key] = value;
                    changedFields.push_back("check." + key);
                }

                check["previous"] = previous;
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Stateless event does not contain check");
            return {};
        }

        if (event.contains("policy") && event["policy"].is_object())
        {
            if (event["policy"].contains("new") && event["policy"]["new"].is_object())
            {
                policy = event["policy"]["new"];
            }
            else
            {
                policy = event["policy"];
            }

            if (event["policy"].contains("old") && event["policy"]["old"].is_object())
            {
                const auto& old = event["policy"]["old"];
                nlohmann::json previous;

                for (auto& [key, value] : old.items())
                {
                    if (key == "id")
                    {
                        continue;
                    }

                    previous[key] = value;
                    changedFields.push_back("policy." + key);
                }

                policy["previous"] = previous;
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Stateless event does not contain policy");
            return {};
        }

        NormalizeCheck(check);
        NormalizePolicy(policy);

        jsonEvent =
        {
            {"collector", event.at("collector")},
            {"module", "sca"},
            {
                "data", {
                    {
                        "event", {
                            {"changed_fields", changedFields},
                            {"created", Utils::getCurrentISO8601()},
                            {"type", STATELESS_OPERATION_MAP.at(event["result"])}
                        }
                    },
                    {"check", check},
                    {"policy", policy}
                }
            }
        };
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Error processing stateless event: ") + e.what());
    }

    return jsonEvent;
}

std::string SCAEventHandler::CalculateHashId(const nlohmann::json& data) const
{
    const std::string baseId = data["policy"]["id"].get<std::string>() + ":" + data["check"]["id"].get<std::string>();

    Utils::HashData hash(Utils::HashType::Sha1);
    hash.update(baseId.c_str(), baseId.size());

    return Utils::asciiToHex(hash.hash());
}

void SCAEventHandler::PushStateful(const nlohmann::json& event, ReturnTypeCallback operation, uint64_t version) const
{
    if (!m_pushStatefulMessage)
    {
        throw std::runtime_error("PushStatefulMessage function not set, cannot send message.");
    }

    m_pushStatefulMessage(CalculateHashId(event), OPERATION_STATES_MAP.at(operation), SCA_SYNC_INDEX, event.dump(), version);

    LoggingHelper::getInstance().log(LOG_DEBUG_VERBOSE, "Stateful event queued: " + event.dump());
}

void SCAEventHandler::PushStateless(const nlohmann::json& event) const
{
    if (!m_pushStatelessMessage)
    {
        throw std::runtime_error("PushStatelessMessage function not set, cannot send message.");
    }

    m_pushStatelessMessage(event.dump());

    LoggingHelper::getInstance().log(LOG_DEBUG_VERBOSE, "Stateless event queued: " + event.dump());
}

nlohmann::json SCAEventHandler::StringToJsonArray(const std::string& input) const
{
    nlohmann::json result = nlohmann::json::array();
    std::istringstream stream(input);
    std::string token;

    while (std::getline(stream, token, ','))
    {
        // Trim all whitespace characters including \n, \r, \t, \v, \f, and spaces
        token = Utils::trim(token, " \t\n\r\v\f");

        if (!token.empty())
        {
            result.push_back(token);
        }
    }

    return result;
}

nlohmann::json SCAEventHandler::TransformComplianceToIndexerFormat(const std::string& complianceStr)
{
    // Mapping: YAML compliance key → { new indexer schema key, version (empty if N/A) }.
    // YAML keys absent from this map (e.g. cis, cis_csc_v7/v8, gpg_13) are not present
    // in the new indexer schema and are silently dropped.
    struct Mapping
    {
        std::string targetKey;
        std::string version;
    };

    static const std::map<std::string, Mapping> KEY_MAP =
    {
        {"cmmc_v2.0",         {"cmmc",          "2.0"  }},
        {"cmmc_v2.1",         {"cmmc",          "2.1"  }},
        {"fedramp",           {"fedramp",        ""     }},
        {"gdpr",              {"gdpr",           ""     }},
        {"gdpr_IV",           {"gdpr",           ""     }},
        {"hipaa",             {"hipaa",          ""     }},
        {"iso_27001-2013",    {"iso_27001",      "2013" }},
        {"iso_27001-2022",    {"iso_27001",      "2022" }},
        {"mitre_mitigations", {"mitre_attack",   ""     }},
        {"mitre_tactics",     {"mitre_attack",   ""     }},
        {"mitre_techniques",  {"mitre_attack",   ""     }},
        {"nis2",              {"nis2",           ""     }},
        {"nist_800_171",      {"nist_800_171",   ""     }},
        {"nist_800-171",      {"nist_800_171",   ""     }},
        {"nist_sp_800-171",   {"nist_800_171",   ""     }},
        {"nist_800_53",       {"nist_800_53",    ""     }},
        {"nist_800-53",       {"nist_800_53",    ""     }},
        {"nist_sp_800-53",    {"nist_800_53",    ""     }},
        {"pci_dss",           {"pci_dss",        ""     }},
        {"pci_dss_v3.2.1",    {"pci_dss",        "3.2.1"}},
        {"pci_dss_3.2.1",     {"pci_dss",        "3.2.1"}},
        {"pci_dss_v4.0",      {"pci_dss",        "4.0"  }},
        {"pci_dss_4.0",       {"pci_dss",        "4.0"  }},
        {"soc_2",             {"tsc",            ""     }},
        {"tsc",               {"tsc",            ""     }},
    };

    // Canonical metadata for each target framework (standardized per standards body,
    // not organization-specific). These values are fixed for every deployment.
    struct FrameworkMeta
    {
        std::string name;
        std::string publisher;
        std::string category;
    };

    static const std::map<std::string, FrameworkMeta> FRAMEWORK_META =
    {
        {"cmmc",         {"Cybersecurity Maturity Model Certification",               "U.S. Department of Defense",                    "cybersecurity"           }},
        {"fedramp",      {"Federal Risk and Authorization Management Program",         "U.S. General Services Administration",           "federal-cloud-security"  }},
        {"gdpr",         {"General Data Protection Regulation",                       "European Union",                                "data-protection"         }},
        {"hipaa",        {"Health Insurance Portability and Accountability Act",       "U.S. Department of Health and Human Services",   "healthcare"              }},
        {"iso_27001",    {"ISO/IEC 27001 Information Security Management",             "ISO/IEC",                                       "information-security"    }},
        {"mitre_attack", {"MITRE ATT&CK",                                             "MITRE Corporation",                             "threat-intelligence"     }},
        {"nis2",         {"Network and Information Security Directive 2",              "European Union",                                "cybersecurity"           }},
        {"nist_800_171", {"NIST SP 800-171 Protecting Controlled Unclassified Info",   "NIST",                                          "federal-information-systems"}},
        {"nist_800_53",  {"NIST SP 800-53 Security and Privacy Controls",              "NIST",                                          "federal-information-systems"}},
        {"pci_dss",      {"Payment Card Industry Data Security Standard",              "PCI Security Standards Council",                "payment-security"        }},
        {"tsc",          {"Trust Services Criteria",                                   "AICPA",                                         "service-organization"    }},
    };

    nlohmann::json parsed;

    try
    {
        parsed = nlohmann::json::parse(complianceStr);
    }
    catch (const std::exception&)
    {
        return nullptr;
    }

    if (parsed.empty())
    {
        return nullptr;
    }

    // New format: compliance is already a structured object matching the indexer schema
    // (e.g. {"cmmc":{"requirements":[...],"version":"2.0"}, ...}).
    // Pass it through directly without transformation.
    if (parsed.is_object())
    {
        return parsed;
    }

    if (!parsed.is_array())
    {
        return nullptr;
    }

    // Old format: compliance is an array of single-key objects
    // (e.g. [{"cmmc_v2.0":["AC.L1-3.1.1"]},{"hipaa":["164.308"]}]).
    // Apply key mapping and aggregate requirements.

    // Accumulate requirements and versions per target framework.
    struct FrameworkData
    {
        std::vector<std::string> requirements;
        std::vector<std::string> versions; // unique; few items so linear search is fine
    };

    std::map<std::string, FrameworkData> accum;

    for (const auto& item : parsed)
    {
        if (!item.is_object())
        {
            continue;
        }

        for (auto it = item.begin(); it != item.end(); ++it)
        {
            auto mappingIt = KEY_MAP.find(it.key());

            if (mappingIt == KEY_MAP.end())
            {
                continue;
            }

            const auto& mapping = mappingIt->second;
            auto& data = accum[mapping.targetKey];

            if (!mapping.version.empty())
            {
                bool alreadyPresent = false;

                for (const auto& v : data.versions)
                {
                    if (v == mapping.version)
                    {
                        alreadyPresent = true;
                        break;
                    }
                }

                if (!alreadyPresent)
                {
                    data.versions.push_back(mapping.version);
                }
            }

            const auto& values = it.value();

            if (values.is_array())
            {
                for (const auto& val : values)
                {
                    if (val.is_string())
                    {
                        data.requirements.push_back(val.get<std::string>());
                    }
                }
            }
        }
    }

    if (accum.empty())
    {
        return nullptr;
    }

    nlohmann::json result = nlohmann::json::object();

    for (const auto& [framework, data] : accum)
    {
        nlohmann::json frameworkObj = nlohmann::json::object();
        frameworkObj["requirements"] = data.requirements;

        if (data.versions.size() == 1)
        {
            frameworkObj["version"] = data.versions.front();
        }
        else if (data.versions.size() > 1)
        {
            frameworkObj["version"] = data.versions;
        }

        auto metaIt = FRAMEWORK_META.find(framework);

        if (metaIt != FRAMEWORK_META.end())
        {
            frameworkObj["name"]      = metaIt->second.name;
            frameworkObj["publisher"] = metaIt->second.publisher;
            frameworkObj["category"]  = metaIt->second.category;
        }

        result[framework] = frameworkObj;
    }

    return result;
}

void SCAEventHandler::NormalizeCheck(nlohmann::json& check) const
{
    if (check.contains("refs") && check["refs"].is_string())
    {
        check["references"] = StringToJsonArray(check["refs"].get<std::string>());
        check.erase("refs");
    }

    if (check.contains("compliance") && check["compliance"].is_string())
    {
        auto structured = TransformComplianceToIndexerFormat(check["compliance"].get<std::string>());
        check["compliance"] = structured.is_null() ? nlohmann::json(nullptr) : structured;
    }

    if (check.contains("rules") && check["rules"].is_string())
    {
        check["rules"] = StringToJsonArray(check["rules"].get<std::string>());
    }

    if (check.contains("policy_id"))
    {
        check.erase("policy_id");
    }

    // Remove internal field not part of indexer schema
    if (check.contains("regex_type"))
    {
        check.erase("regex_type");
    }

    // Remove sync field - internal use only
    if (check.contains("sync"))
    {
        check.erase("sync");
    }

    // Remove impact field - present in YAML but not in database schema or indexer mapping
    if (check.contains("impact"))
    {
        check.erase("impact");
    }
}

void SCAEventHandler::NormalizePolicy(nlohmann::json& policy) const
{
    if (policy.contains("refs") && policy["refs"].is_string())
    {
        policy["references"] = StringToJsonArray(policy["refs"].get<std::string>());
        policy.erase("refs");
    }

    // Remove internal field not part of indexer schema
    if (policy.contains("regex_type"))
    {
        policy.erase("regex_type");
    }
}

bool SCAEventHandler::ValidateAndHandleStatefulMessage(const nlohmann::json& statefulEvent,
                                                       const std::string& context,
                                                       const nlohmann::json& checkData,
                                                       std::vector<nlohmann::json>* failedChecks) const
{
    if (statefulEvent.empty())
    {
        return true;
    }

    auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

    if (!validatorFactory.isInitialized())
    {
        return true;
    }

    auto validator = validatorFactory.getValidator(SCA_SYNC_INDEX);

    if (!validator)
    {
        return true;
    }

    std::string statefulData = statefulEvent.dump();
    auto validationResult = validator->validate(statefulData);

    if (validationResult.isValid)
    {
        return true;
    }

    // Validation failed - log errors
    std::string errorMsg = "Schema validation failed for SCA message (" + context +
                           ", index: " + std::string(SCA_SYNC_INDEX) + "). Errors: ";

    for (const auto& error : validationResult.errors)
    {
        errorMsg += "  - " + error;
    }

    LoggingHelper::getInstance().log(LOG_ERROR, errorMsg);
    LoggingHelper::getInstance().log(LOG_ERROR, "Raw event that failed validation: " + statefulData);

    // Handle deletion from DBSync to prevent integrity sync loops
    if (!checkData.empty() && failedChecks)
    {
        // Deferred deletion: accumulate for batch deletion with transaction
        LoggingHelper::getInstance().log(LOG_DEBUG, "Marking SCA check for deferred deletion due to validation failure");
        failedChecks->push_back(checkData);
    }

    return false;
}

void SCAEventHandler::DeleteFailedChecksFromDB(const std::vector<nlohmann::json>& failedChecks) const
{
    if (failedChecks.empty() || !m_dBSync)
    {
        return;
    }

    // LCOV_EXCL_START
    try
    {
        DBSyncTxn deleteTxn(m_dBSync->handle(),
                            nlohmann::json::array(),
                            0, 1,
        [](ReturnTypeCallback, const nlohmann::json&) {});

        for (const auto& failedCheck : failedChecks)
        {
            auto deleteQuery = DeleteQuery::builder()
                               .table("sca_check")
                               .data(failedCheck)
                               .build();

            m_dBSync->deleteRows(deleteQuery.query());
        }

        // Finalize transaction to commit changes
        deleteTxn.getDeletedRows([](ReturnTypeCallback, const nlohmann::json&) {});

        LoggingHelper::getInstance().log(LOG_DEBUG, "Deleted " + std::to_string(failedChecks.size()) +
                                         " SCA check(s) from DBSync due to validation failure");
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Failed to delete from DBSync: " + std::string(e.what()));
    }

    // LCOV_EXCL_STOP
}

void SCAEventHandler::HandleFailedChecks(std::vector<nlohmann::json> failedChecks) const
{
    while (!failedChecks.empty())
    {
        DeleteFailedChecksFromDB(failedChecks);

        if (!m_syncManager)
        {
            return;
        }

        std::vector<nlohmann::json> promotedFailures;

        for (const auto& failedCheck : failedChecks)
        {
            const auto deleteResult = m_syncManager->handleDelete(failedCheck);

            if (!deleteResult.promotedIds.empty())
            {
                ProcessPromotedChecks(deleteResult.promotedIds, &promotedFailures);
            }
        }

        failedChecks = std::move(promotedFailures);
    }
}

void SCAEventHandler::ProcessPromotedChecks(const std::vector<std::string>& promotedIds,
                                            std::vector<nlohmann::json>* failedChecks) const
{
    if (promotedIds.empty())
    {
        return;
    }

    for (const auto& checkId : promotedIds)
    {
        const auto checkData = GetPolicyCheckById(checkId);

        if (checkData.empty() || !checkData.contains("policy_id"))
        {
            LoggingHelper::getInstance().log(LOG_WARNING, "Promoted check not found in DB: " + checkId);
            continue;
        }

        std::string policyId;

        if (checkData["policy_id"].is_string())
        {
            policyId = checkData["policy_id"].get<std::string>();
        }
        else if (checkData["policy_id"].is_number_integer())
        {
            policyId = std::to_string(checkData["policy_id"].get<int>());
        }

        if (policyId.empty())
        {
            LoggingHelper::getInstance().log(LOG_WARNING,
                                             "Invalid policy_id for promoted check " + checkId + ", skipping");
            continue;
        }

        const auto policyData = GetPolicyById(policyId);

        if (policyData.empty())
        {
            LoggingHelper::getInstance().log(LOG_WARNING,
                                             "Policy not found for promoted check " + checkId + ", skipping");
            continue;
        }

        const nlohmann::json event =
        {
            {"policy", policyData},
            {"check", checkData},
            {"result", INSERTED},
            {"collector", "sync"}
        };

        const auto [stateful, operation, version] = ProcessStateful(event);

        const bool validationPassed = ValidateAndHandleStatefulMessage(
                                          stateful,
                                          "sync promotion checkId: " + checkId,
                                          checkData,
                                          failedChecks
                                      );

        if (validationPassed)
        {
            PushStateful(stateful, operation, version);
        }
    }
}

void SCAEventHandler::ProcessDemotedChecks(const std::vector<std::string>& demotedIds,
                                           std::vector<nlohmann::json>* failedChecks) const
{
    if (demotedIds.empty())
    {
        return;
    }

    for (const auto& checkId : demotedIds)
    {
        const auto checkData = GetPolicyCheckById(checkId);

        if (checkData.empty() || !checkData.contains("policy_id"))
        {
            LoggingHelper::getInstance().log(LOG_WARNING, "Demoted check not found in DB: " + checkId);
            continue;
        }

        std::string policyId;

        if (checkData["policy_id"].is_string())
        {
            policyId = checkData["policy_id"].get<std::string>();
        }
        else if (checkData["policy_id"].is_number_integer())
        {
            policyId = std::to_string(checkData["policy_id"].get<int>());
        }

        if (policyId.empty())
        {
            LoggingHelper::getInstance().log(LOG_WARNING,
                                             "Invalid policy_id for demoted check " + checkId + ", skipping");
            continue;
        }

        const auto policyData = GetPolicyById(policyId);

        if (policyData.empty())
        {
            LoggingHelper::getInstance().log(LOG_WARNING,
                                             "Policy not found for demoted check " + checkId + ", skipping");
            continue;
        }

        const nlohmann::json event =
        {
            {"policy", policyData},
            {"check", checkData},
            {"result", DELETED},
            {"collector", "sync"}
        };

        const auto [stateful, operation, version] = ProcessStateful(event);

        const bool validationPassed = ValidateAndHandleStatefulMessage(
                                          stateful,
                                          "sync demotion checkId: " + checkId,
                                          checkData,
                                          failedChecks
                                      );

        if (validationPassed)
        {
            PushStateful(stateful, operation, version);
        }
    }
}
