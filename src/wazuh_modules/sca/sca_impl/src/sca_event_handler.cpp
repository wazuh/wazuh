#include <sca_checksum.hpp>
#include <sca_event_handler.hpp>

#include <dbsync.hpp>
#include <hashHelper.h>
#include <stringHelper.h>
#include <timeHelper.h>

#include <sstream>

#include "logging_helper.hpp"
#include "agent_sync_protocol.hpp"

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

/// @brief Sync protocol index name
static const std::string SCA_SYNC_INDEX = "wazuh-states-sca";

SCAEventHandler::SCAEventHandler(std::shared_ptr<IDBSync> dBSync,
                                 std::function<int(const std::string&)> pushStatelessMessage,
                                 std::function<int(const std::string&, Operation_t, const std::string&, const std::string&)> pushStatefulMessage)
    : m_pushStatelessMessage(std::move(pushStatelessMessage))
    , m_pushStatefulMessage(std::move(pushStatefulMessage))
    , m_dBSync(std::move(dBSync)) {};

void SCAEventHandler::ReportPoliciesDelta(
    const std::unordered_map<std::string, nlohmann::json>& modifiedPoliciesMap,
    const std::unordered_map<std::string, nlohmann::json>& modifiedChecksMap) const
{
    const nlohmann::json events = ProcessEvents(modifiedPoliciesMap, modifiedChecksMap);

    for (const auto& event : events)
    {
        const auto [processedStatefulEvent, operation] = ProcessStateful(event);

        if (!processedStatefulEvent.empty())
        {
            PushStateful(processedStatefulEvent, operation);
        }

        const auto processedStatelessEvent = ProcessStateless(event);

        if (!processedStatelessEvent.empty())
        {
            PushStateless(processedStatelessEvent);
        }
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

    const auto callback = [&, this](ReturnTypeCallback result, const nlohmann::json & rowData)
    {
        if (result == MODIFIED)
        {
            const nlohmann::json event =
            {
                {"policy", policyData}, {"check", rowData}, {"result", result}, {"collector", "check"}
            };

            const auto [stateful, operation] = ProcessStateful(event);

            if (!stateful.empty())
            {
                PushStateful(stateful, operation);
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
                                    "rules"})
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
                                    "rules"})
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

std::pair<nlohmann::json, ReturnTypeCallback> SCAEventHandler::ProcessStateful(const nlohmann::json& event) const
{
    nlohmann::json check;
    nlohmann::json policy;
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
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Stateful event does not contain check");
            return {{}, SELECTED};
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
            return {{}, SELECTED};
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

        // Add state modified_at field for stateful events only
        nlohmann::json state;
        state["modified_at"] = Utils::getCurrentISO8601();

        jsonEvent = {{"checksum", checksumObj}, {"check", check}, {"policy", policy}, {"state", state}};
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Error processing stateful event: ") + e.what());
        return {{}, SELECTED};
    }

    return {jsonEvent, static_cast<ReturnTypeCallback>(event["result"])};
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

            if (event["check"].contains("old") && event["check"]["old"].is_object())
            {
                const auto& old = event["check"]["old"];
                nlohmann::json previous;

                for (auto& [key, value] : old.items())
                {
                    if (key == "id")
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

void SCAEventHandler::PushStateful(const nlohmann::json& event, ReturnTypeCallback operation) const
{
    if (!m_pushStatefulMessage)
    {
        throw std::runtime_error("PushStatefulMessage function not set, cannot send message.");
    }

    m_pushStatefulMessage(CalculateHashId(event), OPERATION_STATES_MAP.at(operation), SCA_SYNC_INDEX, event.dump());

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
        token = Utils::trim(token, " \t");

        if (!token.empty())
        {
            result.push_back(token);
        }
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
        check["compliance"] = StringToJsonArray(check["compliance"].get<std::string>());
    }

    if (check.contains("rules") && check["rules"].is_string())
    {
        check["rules"] = StringToJsonArray(check["rules"].get<std::string>());
    }

    if (check.contains("policy_id"))
    {
        check.erase("policy_id");
    }
}

void SCAEventHandler::NormalizePolicy(nlohmann::json& policy) const
{
    if (policy.contains("refs") && policy["refs"].is_string())
    {
        policy["references"] = StringToJsonArray(policy["refs"].get<std::string>());
        policy.erase("refs");
    }
}
