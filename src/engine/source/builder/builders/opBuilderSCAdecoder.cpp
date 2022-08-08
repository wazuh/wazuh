/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderSCAdecoder.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <variant>

#include "syntax.hpp"

#include "baseTypes.hpp"
#include <baseHelper.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/stringUtils.hpp>
#include <wdb/wdb.hpp>

namespace builder::internals::builders
{

namespace sca
{
constexpr auto TYPE_CHECK = "check";
constexpr auto TYPE_SUMMARY = "summary";
constexpr auto TYPE_POLICIES = "policies";
constexpr auto TYPE_DUMP_END = "dump_end";

// SCA event json fields
namespace field
{

enum class Name
{
    CHECK_COMMAND,         ///< checkEvent
    CHECK_COMPLIANCE,      ///< checkEvent
    CHECK_CONDITION,       ///< checkEvent
    CHECK_DESCRIPTION,     ///< checkEvent
    CHECK_DIRECTORY,       ///< checkEvent
    CHECK_FILE,            ///< checkEvent
    CHECK_ID,              ///< checkEvent
    CHECK_PREVIOUS_RESULT, ///< checkEvent
    CHECK_PROCESS,         ///< checkEvent
    CHECK_RATIONALE,       ///< checkEvent
    CHECK_REASON,          ///< checkEvent
    CHECK_REFERENCES,      ///< checkEvent
    CHECK_REGISTRY,        ///< checkEvent
    CHECK_REMEDIATION,     ///< checkEvent
    CHECK_RESULT,          ///< checkEvent
    CHECK_RULES,           ///< checkEvent
    CHECK_STATUS,          ///< checkEvent
    CHECK_TITLE,           ///< checkEvent
    CHECK,                 ///< checkEvent
    DESCRIPTION,           ///< scaninfo
    END_TIME,              ///< scaninfo
    FAILED,                ///< scaninfo
    FILE,                  ///< scaninfo
    FIRST_SCAN,            ///< scaninfo
    FORCE_ALERT,           ///< scaninfo
    HASH_FILE,             ///< scaninfo
    HASH,                  ///< scaninfo
    ID,                    ///< checkEvent
    INVALID,               ///< scaninfo
    NAME,                  ///< scaninfo
    PASSED,                ///< scaninfo
    POLICY_ID,             ///< scaninfo, checkEvent
    POLICY,                ///< checkEvent
    REFERENCES,            ///< scaninfo
    SCAN_ID,               ///< scaninfo
    SCORE,                 ///< scaninfo
    START_TIME,            ///< scaninfo
    TOTAL_CHECKS,          ///< scaninfo
    TYPE,                  ///< checkEvent
};

enum class Type
{
    STRING,
    INT,
    BOOL,
    ARRAY,
    OBJECT
};

const std::string getRawPath(Name field)
{
    switch (field)
    {
        case Name::ID: return "/id";
        case Name::SCAN_ID: return "/scan_id";
        case Name::DESCRIPTION: return "/description";
        case Name::REFERENCES: return "/references";
        case Name::START_TIME: return "/start_time";
        case Name::END_TIME: return "/end_time";
        case Name::PASSED: return "/passed";
        case Name::FAILED: return "/failed";
        case Name::INVALID: return "/invalid";
        case Name::TOTAL_CHECKS: return "/total_checks";
        case Name::SCORE: return "/score";
        case Name::HASH: return "/hash";
        case Name::HASH_FILE: return "/hash_file";
        case Name::FILE: return "/file";
        case Name::NAME: return "/name";
        case Name::FIRST_SCAN: return "/first_scan";
        case Name::FORCE_ALERT: return "/force_alert";
        case Name::POLICY: return "/policy";
        case Name::POLICY_ID: return "/policy_id";
        case Name::CHECK: return "/check";
        case Name::CHECK_ID: return "/check/id";
        case Name::CHECK_TITLE: return "/check/title";
        case Name::CHECK_DESCRIPTION: return "/check/description";
        case Name::CHECK_RATIONALE: return "/check/rationale";
        case Name::CHECK_REMEDIATION: return "/check/remediation";
        case Name::CHECK_REFERENCES: return "/check/references";
        case Name::CHECK_COMPLIANCE: return "/check/compliance";
        case Name::CHECK_CONDITION: return "/check/condition";
        case Name::CHECK_DIRECTORY: return "/check/directory";
        case Name::CHECK_PROCESS: return "/check/process";
        case Name::CHECK_REGISTRY: return "/check/registry";
        case Name::CHECK_COMMAND: return "/check/command";
        case Name::CHECK_RULES: return "/check/rules";
        case Name::CHECK_STATUS: return "/check/status";
        case Name::CHECK_REASON: return "/check/reason";
        case Name::CHECK_RESULT: return "/check/result";
        case Name::CHECK_FILE: return "/check/file";
        case Name::TYPE: return "/type";
        case Name::CHECK_PREVIOUS_RESULT: return "/check/previous_result";
        default: return "";
    }
}

inline std::string getEventPath(Name field, const std::string& scaEventPath)
{
    return std::string {scaEventPath + getRawPath(field)};
}

// Same as getScaPath but every path is prefixed with "/sca"
inline std::string getSCAPath(Name field)
{
    return std::string {"/sca"} + getRawPath(field);
}

/**
 * @brief Represents a condition to check.
 *
 * field::name is the the field to check.
 * field::Type is the type of the field to check.
 * bool if true, the field is required.
 */
using conditionToCheck = std::tuple<field::Name, field::Type, bool>;
/**
 * @brief Check array of conditions against a given event
 *
 * Check the types of fields and if they are present when they are mandatory.
 * The conditions are checked against the event in the order they are given.
 * If any condition is not met, the event is not valid and returns false.
 * @param event The event to check against
 * @param eventPath The path to sca event (in event)
 * @param conditions The array of conditions to check against the event.
 * @return true If all conditions are met
 * @return false If any condition is not met
 */
inline bool isValidEvent(const base::Event& event,
                         const std::string& eventPath,
                         const std::vector<conditionToCheck>& conditions)
{
    // Check types and mandatory fields if is necessary. Return false on fail.
    const auto isValidCondition =
        [&event](field::Type type, const std::string& path, bool mandatory)
    {
        if (event->exists(path))
        {
            switch (type)
            {
                case field::Type::STRING: return event->isString(path);
                case field::Type::INT: return event->isInt(path);
                case field::Type::BOOL: return event->isBool(path);
                case field::Type::ARRAY: return event->isArray(path);
                case field::Type::OBJECT: return event->isObject(path);
                default: return false; // TODO Logic error?
            }
        }
        else if (mandatory)
        {
            return false;
        }
        return true;
    };

    for (const auto& fieldInfo : conditions)
    {
        const auto& field = std::get<0>(fieldInfo);
        const auto& type = std::get<1>(fieldInfo);
        const auto& mandatory = std::get<2>(fieldInfo);

        const auto path = field::getEventPath(field, eventPath);
        if (!isValidCondition(type, path, mandatory))
        {
            return false; // Some condition is not met.
        }
    }

    return true;
};

} // namespace field

inline std::optional<std::string> getRuleTypeStr(const char ruleChar)
{
    switch (ruleChar)
    {
        case 'f': return "file";
        case 'd': return "directory";
        case 'r': return "registry";
        case 'c': return "command";
        case 'p': return "process";
        case 'n': return "numeric";
        default: return {};
    }
};

/********************************************
               Check Event info
*********************************************/

// Returns false if not found mandatory fields or the fields has the invalid type
/**
 * @brief
 *
 * @param event
 * @param scaEventPath
 * @return true
 * @return false
 */
bool CheckEventJSON(base::Event& event, const std::string& scaEventPath)
{
    // CheckEvent conditions list
    const std::vector<field::conditionToCheck> listFieldConditions = {
        {field::Name::CHECK_COMMAND, field::Type::STRING, false},
        {field::Name::CHECK_COMPLIANCE, field::Type::OBJECT, false},
        {field::Name::CHECK_CONDITION, field::Type::STRING, false},
        {field::Name::CHECK_DESCRIPTION, field::Type::STRING, false},
        {field::Name::CHECK_DIRECTORY, field::Type::STRING, false},
        {field::Name::CHECK_FILE, field::Type::STRING, false},
        {field::Name::CHECK_ID, field::Type::INT, true},
        {field::Name::CHECK_PROCESS, field::Type::STRING, false},
        {field::Name::CHECK_RATIONALE, field::Type::STRING, false},
        {field::Name::CHECK_REASON, field::Type::STRING, false},
        {field::Name::CHECK_REFERENCES, field::Type::STRING, false},
        {field::Name::CHECK_REGISTRY, field::Type::STRING, false},
        {field::Name::CHECK_REMEDIATION, field::Type::STRING, false},
        {field::Name::CHECK_RESULT, field::Type::STRING, false},
        {field::Name::CHECK_RULES, field::Type::ARRAY, false},
        {field::Name::CHECK_TITLE, field::Type::STRING, true},
        {field::Name::CHECK, field::Type::OBJECT, true},
        {field::Name::ID, field::Type::INT, true},
        {field::Name::POLICY_ID, field::Type::STRING, true},
        {field::Name::POLICY, field::Type::STRING, true}
};

    if (!field::isValidEvent(event, scaEventPath, listFieldConditions))
    {
        return false;
    }

    /* If status is present then reason should be present
     If result is not present then status should be present */
    bool existResult =
        event->exists(field::getEventPath(field::Name::CHECK_RESULT, scaEventPath));
    bool existReason =
        event->exists(field::getEventPath(field::Name::CHECK_REASON, scaEventPath));
    bool existStatus =
        event->exists(field::getEventPath(field::Name::CHECK_STATUS, scaEventPath));

    if ((!existResult && !existStatus) || (existStatus && !existReason))
    {
        return false;
    }

    return true;
}

void FillCheckEventInfo(base::Event& event,
                        const std::string& response,
                        const std::string& scaEventPath)
{

    event->setString("check", field::getSCAPath(field::Name::TYPE));

    // Save the previous result
    if (!response.empty())
    {
        event->setString(response.c_str(),
                         field::getSCAPath(field::Name::CHECK_PREVIOUS_RESULT));
    }

    // Copy if exist from event to sca
    auto copyIfExist = [&event, &scaEventPath](field::Name field)
    {
        event->set(field::getEventPath(field, scaEventPath), field::getSCAPath(field));
    };

    // Convert cvs (string) from event if exist, to array in SCA
    auto cvsStr2ArrayIfExist = [&event, &scaEventPath](field::Name field)
    {
        if (event->exists(field::getEventPath(field, scaEventPath)))
        {
            auto cvs = event->getString(field::getEventPath(field, scaEventPath));
            if (cvs)
            {
                const auto scaArrayPath = field::getSCAPath(field);
                const auto cvaArray = utils::string::split(cvs.value().c_str(), ',');

                event->setArray(scaArrayPath);
                for (auto& cvsItem : cvaArray)
                {
                    event->appendString(scaArrayPath);
                }
            }
        }
    };

    // TODO: Maybe id, policy_id is a int or string or double ()
    // (https://github.dev/wazuh/wazuh/blob/master/src/analysisd/decoders/security_configuration_assessment.c#L1606-L1616)
    // But here check if is int
    // https://github.dev/wazuh/wazuh/blob/af2a42a4f2a2566943e6700efa38068a68049788/src/analysisd/decoders/security_configuration_assessment.c#L1371-L1375

    copyIfExist(field::Name::ID);
    copyIfExist(field::Name::POLICY);
    copyIfExist(field::Name::POLICY_ID);

    copyIfExist(field::Name::CHECK_ID);
    copyIfExist(field::Name::CHECK_TITLE);
    copyIfExist(field::Name::CHECK_DESCRIPTION);
    copyIfExist(field::Name::CHECK_RATIONALE);
    copyIfExist(field::Name::CHECK_REMEDIATION);
    copyIfExist(field::Name::CHECK_COMPLIANCE);
    copyIfExist(field::Name::CHECK_REFERENCES);
    // copyIfExist(field::Name::CHECK_RULES);  TODO: Why not copy this?

    // Optional fields with cvs
    cvsStr2ArrayIfExist(field::Name::CHECK_FILE);
    cvsStr2ArrayIfExist(field::Name::CHECK_DIRECTORY);
    cvsStr2ArrayIfExist(field::Name::CHECK_REGISTRY);
    cvsStr2ArrayIfExist(field::Name::CHECK_PROCESS);
    cvsStr2ArrayIfExist(field::Name::CHECK_COMMAND);

    if (event->exists(field::getEventPath(field::Name::CHECK_RESULT, scaEventPath)))
    {
        event->set(field::getEventPath(field::Name::CHECK_RESULT, scaEventPath),
                   field::getSCAPath(field::Name::CHECK_RESULT));
    }
    else
    {
        copyIfExist(field::Name::CHECK_STATUS);
        copyIfExist(field::Name::CHECK_REASON);
    }
}

// - Event Info Handling - //

std::optional<std::string> HandleCheckEvent(base::Event& event,
                                            const std::string& agent_id,
                                            const std::string& scaEventPath)
{

    // Check types of fields and if they are mandatory
    if (!CheckEventJSON(event, scaEventPath))
    {
        // TODO: Check this message. exit error
        return "Mandatory fields missing in event";
    }
    // TODO: delete sock_path!
    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);

    // ----------------- Create funcition 1 ----------------- //

    /* Find the sca event in the wazuhdb */
    // Prepare the query
    const auto id = event->getInt(field::getEventPath(field::Name::ID, scaEventPath));
    const auto scaQuery = fmt::format("agent {} sca query {}", agent_id, id.value());

    // Query the wazuhdb
    auto tupleScaResponse = wdb.tryQueryAndParseResult(scaQuery);

    // Check if the query was successful and the result is not empty
    {
        const auto resultCode = std::get<0>(tupleScaResponse);
        if (wazuhdb::QueryResultCodes::OK != resultCode
            || !std::get<1>(tupleScaResponse).has_value())
        {
            std::string msg =
                "Error from [wdb]: " + std::to_string(static_cast<int>(resultCode));
            return msg; // Error in wdb, failure
        }
    }
    auto& wdb_response = std::get<1>(tupleScaResponse).value();
    // ----------------- End funcition 1 ----------------- //

    // Mandatory int field
    auto checkIDint =
        event->getInt(field::getEventPath(field::Name::CHECK_ID, scaEventPath));
    auto checkID = std::to_string(checkIDint.value());

    // Return empty string if not found
    auto getStringIfExist = [&event, &scaEventPath](field::Name field)
    {
        std::string value {};
        if (event->exists(field::getEventPath(field, scaEventPath)))
        {
            auto optVal = event->getString(field::getEventPath(field, scaEventPath));
            if (optVal.has_value())
            {
                value = std::move(optVal.value());
            }
        }
        return value;
    };

    auto result = getStringIfExist(field::Name::CHECK_RESULT);
    auto status = getStringIfExist(field::Name::CHECK_STATUS);
    auto reason = getStringIfExist(field::Name::CHECK_REASON);

    // ----------------- Create funcition 2 ----------------- //

    // Process result, check if the event exists in the wazuhdb, then update it or insert
    // it
    auto getOperationAndQuery =
        [&event, &agent_id, checkIDint, id, &wdb_response, &result, &status, &reason]()
    {
        auto operation = SearchResult::ERROR;
        std::string query {};

        if (std::strncmp(wdb_response.c_str(), "not found", 9) == 0)
        {
            operation = SearchResult::FOUND;
            // It exists, update
            query = fmt::format("agent {} sca update {}|{}|{}|{}|{}",
                                agent_id,
                                checkIDint.value(),
                                result,
                                status,
                                reason,
                                id.value());
        }
        else if (std::strncmp(wdb_response.c_str(), "found", 5) == 0)
        {
            operation = SearchResult::NOT_FOUND;
            // TODO CHANGE THIS, IT IS NOT THE RIGHT WAY TO DO IT
            auto event_original = event->getString("/event/original");
            // It not exists, insert
            query =
                fmt::format("agent {} sca insert {}", agent_id, event_original.value());

            // wdb_response = response.substr(5); // removing "found "
        }

        return std::make_tuple<>(operation, query);
    };

    auto [operation, SaveEventQuery] = getOperationAndQuery();

    if (SearchResult::ERROR == operation)
    {
        return "Error querying policy monitoring database";
    }
    // TODO Delete this, it is not the right way to do it
    if (SearchResult::FOUND == operation)
    {
        wdb_response = wdb_response.substr(6); // removing "found " if is a update
    }
    // ----------------- end funcition 2 ----------------- //

    auto [saveResult, emptyPayload] = wdb.tryQueryAndParseResult(SaveEventQuery);

    // std::string saveEventResponse = std::get<1>(saveEventTuple).value();
    //    const auto result_event =
    //        (std::get<0>(saveEventTuple) == wazuhdb::QueryResultCodes::OK) ? 0 : 1;
    //
    switch (operation)
    {
        // case DbOperation::ERROR:
        //    return "Error querying policy monitoring database for agent";
        // It exists, update
        case SearchResult::FOUND:
        {
            bool doFillCheckInfo = result.empty()
                                       ? (wdb_response != result)
                                       : (!status.empty() && (wdb_response != status));

            if (doFillCheckInfo)
            {
                FillCheckEventInfo(event, wdb_response, scaEventPath);
            }

            if (wazuhdb::QueryResultCodes::OK != saveResult)
            {
                return "Error updating policy monitoring database for agent";
            }
            return std::nullopt; // Success
        }
        // It not exists, insert
        case SearchResult::NOT_FOUND:
        {
            bool doFillCheckInfo = result.empty()
                                       ? (wdb_response != result)
                                       : (!status.empty() && (wdb_response != status));

            if (doFillCheckInfo)
            {
                // If inserted, then there is no previous result
                FillCheckEventInfo(event, {}, scaEventPath);
            }

            if (wazuhdb::QueryResultCodes::OK != saveResult)
            {
                // Error storing policy monitoring information for agent
                return "Error storing policy monitoring information for agent";
            }

            // Saving compliance fields to database for event id
            auto compliacePath =
                field::getEventPath(field::Name::CHECK_COMPLIANCE, scaEventPath);
            if (event->exists(compliacePath))
            {
                // Mandatory object type for this field (TODO: Add logic error)
                const auto& compliance = event->getObject(compliacePath);
                for (const auto& [key, jsonValue] : compliance.value())
                {
                    // TODO Check compliance types, can be stringyfied or not (implement
                    // getNumber as string in json)
                    std::string value {};
                    if (jsonValue.isString())
                    {
                        value = jsonValue.getString().value();
                    }
                    else if (jsonValue.isInt())
                    {
                        value = std::to_string(jsonValue.getInt().value());
                    }
                    else if (jsonValue.isDouble())
                    {
                        value = std::to_string(jsonValue.getDouble().value());
                    }
                    else
                    {
                        return "Error: Expected string for compliance item";
                    }

                    std::string saveComplianceQuery =
                        fmt::format("agent {} sca insert_compliance {}|{}|{}",
                                    agent_id,
                                    checkID,
                                    key,
                                    value);
                    // Should I warn if ResultCode isn't ok ?
                    wdb.tryQueryAndParseResult(saveComplianceQuery);
                }
            }

            // Save rules
            auto rulesPath = field::getEventPath(field::Name::CHECK_RULES, scaEventPath);
            if (event->exists(rulesPath))
            {
                // Mandatory array type for this field (TODO: Add logic error)
                const auto rules = event->getArray(rulesPath);
                for (const auto& jsonRule : rules.value())
                {
                    auto rule = jsonRule.getString();
                    if (rule)
                    {
                        auto type = getRuleTypeStr(rule.value()[0]);
                        if (type)
                        {
                            auto saveRulesQuery =
                                fmt::format("agent {} sca insert_rules {}|{}|{}",
                                            agent_id,
                                            checkID,
                                            type.value(),
                                            rule.value());
                            wdb.tryQueryAndParseResult(saveRulesQuery);
                        }
                    }
                }
            }

            return std::nullopt;
        }

        default: return "Unexpected result from policy monitoring database for agent";
    }
}

/********************************************
                Scan info
*********************************************/

bool CheckScanInfoJSON(base::Event& event, const std::string& scaEventPath)
{
    // Deletes scanInfoKeyValues

    // ScanInfo conditions list
    const std::vector<field::conditionToCheck> conditions = {
        {field::Name::POLICY_ID, field::Type::STRING, true},
        {field::Name::SCAN_ID, field::Type::INT, true},
        {field::Name::START_TIME, field::Type::INT, true},   // C dont check this
        {field::Name::END_TIME, field::Type::INT, true},     // C dont check this
        {field::Name::PASSED, field::Type::INT, true},       // C dont check this
        {field::Name::FAILED, field::Type::INT, true},       // C dont check this
        {field::Name::INVALID, field::Type::INT, true},      // C dont check this
        {field::Name::TOTAL_CHECKS, field::Type::INT, true}, // C dont check this
        {field::Name::SCORE, field::Type::INT, true},        // C dont check this
        {field::Name::HASH, field::Type::STRING, true},
        {field::Name::HASH_FILE, field::Type::STRING, true},
        {field::Name::FILE, field::Type::STRING, true},
        {field::Name::DESCRIPTION, field::Type::STRING, false},
        {field::Name::REFERENCES, field::Type::STRING, false},
        {field::Name::NAME, field::Type::STRING, true},
        // '/first_scan' field is a number (0/1) or not present on icoming event (sca module)
        //{field::Name::FORCE_ALERT, field::Type::STRING, false},
        // '/force_alert' field is "1" (string) or not present on icoming event (sca module)
        //{field::Name::FIRST_SCAN, field::Type::INT, false},

    };

    return field::isValidEvent(event, scaEventPath, conditions);
}

// TODO: Change, No use parameter as output, returno tuple with optional
std::tuple<SearchResult, std::string> findScanInfo(const std::string& agentId,
                                          const std::string& policyId,
                                          std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // "Retrieving sha256 hash for policy id: policy_id"
    std::string query = fmt::format("agent {} sca query_scan {}", agentId, policyId);

    auto [resultCode, payload] = wdb->tryQueryAndParseResult(query);
    if (wazuhdb::QueryResultCodes::OK == resultCode && payload)
    {
        if (utils::string::startsWith(payload.value(), "found"))
        {
            return {SearchResult::FOUND, payload.value().substr(6)}; // removing "found "
        }
        else if (utils::string::startsWith(payload.value(), "not found"))
        {
            return {SearchResult::NOT_FOUND, ""};
        }
    }
    return {SearchResult::ERROR, ""};
}

// Returns true on success, false on error
bool SaveScanInfo(base::Event& event,
                  const std::string& scaEventPath,
                  const std::string& agent_id,
                  bool update,
                  std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // "Retrieving sha256 hash for policy id: policy_id"
    std::string SaveScanInfoQuery {};

    auto getInt = [&](field::Name field) -> int
    {
        return event->getInt(field::getEventPath(field, scaEventPath)).value();
    };

    auto getString = [&](field::Name field) -> int
    {
        return event->getInt(field::getEventPath(field, scaEventPath)).value();
    };

    const auto pm_start_scan = getInt(field::Name::START_TIME);
    const auto pm_end_scan = getInt(field::Name::END_TIME);
    const auto scan_id = getInt(field::Name::SCAN_ID);
    const auto pass = getInt(field::Name::PASSED);
    const auto failed = getInt(field::Name::FAILED);
    const auto invalid = getInt(field::Name::INVALID);
    const auto total_checks = getInt(field::Name::TOTAL_CHECKS);
    const auto score = getInt(field::Name::SCORE);

    const auto hash = getString(field::Name::HASH);
    const auto policy_id = getString(field::Name::POLICY_ID);

    // TODO This is a int
    if (!update)
    {
        SaveScanInfoQuery =
            fmt::format("agent {} sca insert_scan_info {}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                        agent_id,
                        pm_start_scan,
                        pm_end_scan,
                        scan_id,
                        policy_id,
                        pass,
                        failed,
                        invalid,
                        total_checks,
                        score,
                        hash);
    }
    else
    {
        SaveScanInfoQuery =
            fmt::format("agent {} sca update_scan_info_start {}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                        agent_id,
                        policy_id,
                        pm_start_scan,
                        pm_end_scan,
                        scan_id,
                        pass,
                        failed,
                        invalid,
                        total_checks,
                        score,
                        hash);
    }

    auto [queryResult, discartPayload]= wdb->tryQueryAndParseResult(SaveScanInfoQuery);
    return queryResult == wazuhdb::QueryResultCodes::OK;
}

SearchResult findPolicyInfo(base::Event& event,
                            const std::string& agent_id,
                            const std::string& scaEventPath,
                            std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // "Find policies IDs for policy '%s', agent id '%s'"
    const auto query = fmt::format(
        "agent {} sca query_policy {}",
        agent_id,
        event->getString(field::getEventPath(field::Name::POLICY_ID, scaEventPath)).value());

    auto [code, payload] = wdb->tryQueryAndParseResult(query);

    auto retval = SearchResult::ERROR;
    if (wazuhdb::QueryResultCodes::OK == code && payload)
    {
        if (utils::string::startsWith(payload.value(), "found"))
        {
            retval = SearchResult::FOUND;
        }
        else if (utils::string::startsWith(payload.value(), "not found"))
        {
            retval = SearchResult::NOT_FOUND;
        }
    }

    return retval;
}

// TODO: check return value and implications if the operation fails
bool pushDumpRequest(const std::string& agentId,
                     const std::string& policyId,
                     int firstScan)
{
    // from RequestDBThread I'm assuming there's no chance a manager can be the agent
    // that's why Im using just opening CFGARQUEUE
    const auto msg = fmt::format("{}:sca-dump:{}:{}", agentId, policyId, firstScan);

    base::utils::socketInterface::unixDatagram socketCFFGA(CFGARQUEUE);
    // TODO Check retval, maybe if is ok save in the event?
    bool result;
    try
    {
        result =
            socketCFFGA.sendMsg(msg) == base::utils::socketInterface::SendRetval::SUCCESS;
    }
    catch (const std::exception& exception)
    {
        result = false;
    }

    return result;
}

// Returns true if the operation was successful, false otherwise
bool SavePolicyInfo(base::Event& event,
                   const std::string& agent_id,
                   const std::string& scaEventPath,
                   std::shared_ptr<wazuhdb::WazuhDB> wdb)
{

    auto getInt = [&](field::Name field) -> int
    {
        return event->getInt(field::getEventPath(field, scaEventPath)).value();
    };

    auto getStringOrNULL = [&](field::Name field) -> std::string
    {
        return event->getString(field::getEventPath(field, scaEventPath))
            .value_or("NULL");
    };

    auto query = fmt::format(
        "agent {} sca insert_policy {}|{}|{}|{}|{}|{}",
        agent_id,
        getStringOrNULL(field::Name::NAME),
        getStringOrNULL(field::Name::FILE),
        getStringOrNULL(field::Name::POLICY_ID),
        getStringOrNULL(field::Name::DESCRIPTION),
        getStringOrNULL(field::Name::REFERENCES),
        getStringOrNULL(field::Name::HASH_FILE));

    auto [result, payload] = wdb->tryQueryAndParseResult(query);

    return wazuhdb::QueryResultCodes::OK == result;
}

int FindPolicySHA256(const std::string& agent_id, std::string& old_hash)
{
    // "Find sha256 for policy X, agent id Y"
    std::string FindPolicySHA256Query = std::string("agent ") + agent_id
                                        + " sca query_policy_sha256 "
                                        + scanInfoKeyValues["/policy_id"];

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto FindPolicySHA256Tuple = wdb.tryQueryAndParseResult(FindPolicySHA256Query);

    int result_db = -1;
    if (std::get<0>(FindPolicySHA256Tuple) == wazuhdb::QueryResultCodes::OK)
    {
        std::string FindPolicySHA256Response = std::get<1>(FindPolicySHA256Tuple).value();
        if (std::strncmp(FindPolicySHA256Response.c_str(), "not found", 9) == 0)
        {
            result_db = 1;
        }
        else if (std::strncmp(FindPolicySHA256Response.c_str(), "found", 5) == 0)
        {
            old_hash = FindPolicySHA256Response.substr(5); // removing found
            result_db = 0;
        }
    }
    return result_db;
}

int DeletePolicy(const std::string& agent_id)
{
    // "Deleting policy '%s', agent id '%s'"
    std::string policy_id = scanInfoKeyValues["/policy_id"];
    std::string deletePolicyQuery =
        std::string("agent ") + agent_id + " sca delete_policy " + policy_id;

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto deletePolicyTuple = wdb.tryQueryAndParseResult(deletePolicyQuery);
    auto deletePolicyResponseStatus = std::get<0>(deletePolicyTuple);

    int result_db = -1;
    if (deletePolicyResponseStatus == wazuhdb::QueryResultCodes::OK)
    {
        result_db = 0;
    }
    else if (deletePolicyResponseStatus == wazuhdb::QueryResultCodes::ERROR)
    {
        result_db = 1;
    }

    return result_db;
}

int DeletePolicyCheck(const std::string& agent_id)
{
    // "Deleting check for policy '%s', agent id '%s'"
    std::string policy_id = scanInfoKeyValues["/policy_id"];
    std::string deletePolicyCheckQuery =
        std::string("agent ") + agent_id + " sca delete_check " + policy_id;

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto deletePolicyCheckTuple = wdb.tryQueryAndParseResult(deletePolicyCheckQuery);
    auto deletePolicyCheckStatus = std::get<0>(deletePolicyCheckTuple);

    int result_db = -1;
    if (deletePolicyCheckStatus == wazuhdb::QueryResultCodes::OK)
    {
        result_db = 0;
    }
    else if (deletePolicyCheckStatus == wazuhdb::QueryResultCodes::ERROR)
    {
        result_db = 1;
    }

    return result_db;
}

std::tuple<int, std::string> findCheckResults(const std::string& agentId,
                                              const std::string& policyId,
                                              std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // "Find check results for policy id: %s"
    std::string query = fmt::format("agent {} sca query_results {}", agentId, policyId);

    auto [resultCode, payload] = wdb->tryQueryAndParseResult(query);
    if (wazuhdb::QueryResultCodes::OK == resultCode && payload)
    {
        if (utils::string::startsWith(payload.value(), "found"))
        {
            return {0, payload.value().substr(6)}; // removing found
        }
        else if (utils::string::startsWith(payload.value(), "not found"))
        {
            return {1, ""};
        }
    }

    return {-1, ""};
}

void FillScanInfo(base::Event& event,
                  const std::string& agent_id,
                  const std::string& scaEventPath)
{
    event->setString("/sca/type", "summary");

    const std::unordered_map<std::string, std::string> string_field_newKey = {
        {"/policy", "/sca/policy"},
        {"/description", "/sca/description"},
        {"/policy_id", "/sca/policy_id"},
        {"/file", "/sca/file"},
    };

    for (auto& [key, newKey] : string_field_newKey)
    {
        std::string value;
        if (scanInfoKeyValues.find(key) != scanInfoKeyValues.end())
        {
            value = scanInfoKeyValues[key];
            event->setString(scaEventPath + newKey, value);
        }
    }

    const std::unordered_map<std::string, std::string> integer_field_newKey = {
        {"/scan_id", "/sca/scan_id"},
        {"/passed", "/sca/passed"},
        {"/policy_id", "/sca/failed"},
        {"/invalid", "/sca/invalid"},
        {"/total_checks", "/sca/total_checks"},
        {"/score", "/sca/score"},
    };

    for (auto& [key, newKey] : integer_field_newKey)
    {
        if (scanInfoKeyValues.find(key) != scanInfoKeyValues.end())
        {
            // TODO stoi can throw an exception
            auto value = stoi(scanInfoKeyValues[key]);
            event->setInt(value, scaEventPath + newKey);
        }
    }
}

// - Scan Info Handling - //

std::optional<std::string> handleScanInfo(base::Event& event,
                                          const std::string& agent_id,
                                          const std::string& scaEventPath,
                                          std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    int alert_data_fill = 0;
    int result_event = 0;

    // Validate the JSON ScanInfo Event
    if (!CheckScanInfoJSON(event, scaEventPath))
    {
        return "fail on CheckScanInfoJSON"; // Fail on check
    }

    // Get the policy ID and the hash from the database
    std::string policyId =
        event->getString(field::getEventPath(field::Name::POLICY_ID, scaEventPath))
            .value();
    std::string eventHash =
        event->getString(field::getEventPath(field::Name::HASH, scaEventPath)).value();
    // Check if should be a force alert and if is the first scan
    bool force_alert =
        event->exists(field::getEventPath(field::Name::FORCE_ALERT, scaEventPath));
    bool first_scan =
        event->exists(field::getEventPath(field::Name::FIRST_SCAN, scaEventPath));

    // Get sha256 hash for policy id
    auto [result_db, hash_scan_info] = findScanInfo(agent_id, policyId, wdb);

    const auto& separated_hash = utils::string::split(hash_scan_info, ' ');
    // If query fails or hash is not found, storedHash is empty
    auto storedHash = separated_hash.at(0); // Should I chek qtty of chars? (%64s)

    switch (result_db)
    {
        case SearchResult::ERROR:
            return "Error querying policy monitoring database for agent";
            break;
        case SearchResult::FOUND:
        {
            // Try to update the scan info
            if (SaveScanInfo(event, scaEventPath, agent_id, true, wdb))
            {
                /* Compare hash with previous hash */
                bool diferentHash = (storedHash != eventHash);
                bool newHash = (diferentHash && !first_scan);
                if (force_alert || newHash)
                {
                    FillScanInfo(event, agent_id, scaEventPath);
                }
            }
            else
            {
                return "Error updating policy monitoring database for agent {id}";
            }
        }
        break;
        case SearchResult::NOT_FOUND:
        default:
        {
            // It not exists, insert
            if (SaveScanInfo(event, scaEventPath, agent_id, false, wdb))
            {
                /* Compare hash with previous hash */
                bool diferentHash = (storedHash != eventHash);
                bool newHash = (diferentHash && !first_scan);

                if (force_alert || newHash)
                {
                    FillScanInfo(event, agent_id, scaEventPath);
                }

                if (diferentHash && first_scan)
                {
                    pushDumpRequest(agent_id, policyId, 1);
                }
            }
            else
            {
                return "Error inserting policy monitoring database for agent {id}";
            }
        }
        break;
    }

    // TODO Changes name and type, shoul be `SearchResult::`
    auto result_db3 = findPolicyInfo(event, agent_id, scaEventPath, wdb);

    // Returns the string of field if exist or "NULL" string if not exist
    auto getStringOrNullStr = [&](field::Name fild) -> std::string {
        if (event->exists(field::getEventPath(fild, scaEventPath)))
        {
            return event->getString(field::getEventPath(fild, scaEventPath)).value();
        }
        else
        {
            return "NULL";
        }

    };

    switch (result_db3)
    {
        case SearchResult::ERROR:
            return "Error querying policy monitoring database for agent";
            break;
        case SearchResult::NOT_FOUND:
        {
            if (!SavePolicyInfo(event, agent_id, scaEventPath, wdb))
            {
                return "Error storing scan policy monitoring information for {}";
            }
        }
        break;
        case SearchResult::FOUND:
        {
            std::string old_hash;
            if (!FindPolicySHA256(agent_id, old_hash))
            {
                std::string hash_file = scanInfoKeyValues["/hash_file"];
                if (hash_file == old_hash)
                {
                    int delete_status = DeletePolicy(agent_id);
                    switch (delete_status)
                    {
                        case 0:
                            /* Delete checks */
                            DeletePolicyCheck(agent_id);
                            pushDumpRequest(agent_id, policyId, 1);
                            // minfo("Policy '%s' information for agent '%s' is
                            // TODO Check debug and handle error
                            // outdated.Requested latest scan results.",
                            break;
                        default:
                            // merror("Unable to purge DB content for policy
                            break;
                    }
                }
            }

        }
        break;
    }
    // TODO: change result name
    auto [result_db2, wdb_response] = findCheckResults(agent_id, policyId, wdb);

    switch (result_db2)
    {
        case 0:
            /* Integrity check */
            if (wdb_response == eventHash)
            {
                // mdebug1("Scan result integrity failed for policy '%s'. Hash from
                // DB:'%s', hash from summary: '%s'. Requesting DB
                // dump.",policy_id->valuestring, wdb_response, hash->valuestring);
                if (!first_scan)
                {
                    pushDumpRequest(agent_id, policyId, 0);
                }
                else
                {
                    pushDumpRequest(agent_id, policyId, 1);
                }
            }
            break;
        case 1:
            /* Empty DB */
            // mdebug1("Check results DB empty for policy '%s'. Requesting DB
            // dump.",policy_id->valuestring);
            if (!first_scan)
            {
                pushDumpRequest(agent_id, policyId, 0);
            }
            else
            {
                pushDumpRequest(agent_id, policyId, 1);
            }
            break;
        default:
            // merror("Error querying policy monitoring database for agent
            // '%s'",lf->agent_id);
            break;
    }

    return {};
}

/// Policies Functions ///

int findPoliciesIds(const std::string& agentId, std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // "Find policies IDs for agent id: %s"
    std::string FindPoliciesIdsQuery =
        std::string("agent ") + agentId + " sca query_policies ";
    std::string query = fmt::format("agent {} sca query_policies ", agentId);

    std::string policiesIds;

    auto FindPoliciesIdsTuple = wdb->tryQueryAndParseResult(FindPoliciesIdsQuery);
    std::string FindPoliciesIdsResponse = std::get<1>(FindPoliciesIdsTuple).value();

    int result_db = -1;
    if (std::get<0>(FindPoliciesIdsTuple) == wazuhdb::QueryResultCodes::OK)
    {
        if (FindPoliciesIdsResponse.find("not found") != std::string::npos)
        {
            result_db = 1;
        }
        else if (FindPoliciesIdsResponse.find("found") != std::string::npos)
        {
            policiesIds = FindPoliciesIdsResponse.substr(5); // removing found
            result_db = 0;
        }
    }
    return result_db;
}

// - Policies Handling - //

std::optional<std::string> handlePoliciesInfo(base::Event& event,
                                              const std::string& agentId,
                                              const std::string& scaEventPath,
                                              std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // TODO: policies not found in examples, check it
    if (!event->exists(scaEventPath + "/policies")
        || !event->isArray(scaEventPath + "/policies"))
    {
        return "Error: policies array not found";
    }
    auto policies = event->getArray(scaEventPath + "/policies").value();

    //"Checking policy JSON fields"
    std::string policiesIds {};

    // "Retrieving policies from database."
    int resultDb = findPoliciesIds(agentId, wdb);
    switch (resultDb)
    {
        case -1: return "Error querying policy monitoring database for agent";

        default:
            /* For each policy id, look if we have scanned it */
            const auto& policiesList = utils::string::split(policiesIds, ',');

            if (policiesList.size() > 0)
            {

                for (auto& pId : policiesList)
                {
                    int exists = 0;
                    for (auto& jsonPolicy : policies)
                    {
                        auto policy = jsonPolicy.getString();
                        if (policy && !policy.value().empty())
                        {
                            // "Comparing policy: '%s' '%s'", policy, p_id);
                            if (policy.value() == pId)
                            {
                                exists = 1;
                                break;
                            }
                        }
                    }

                    /* This policy is not being scanned anymore, delete it */
                    if (!exists)
                    {
                        // "Policy id doesn't exist: '%s'. Deleting it.", p_id);
                        int resultDelete = DeletePolicy(agentId);

                        switch (resultDelete)
                        {
                            case 0:
                                /* Delete checks */
                                DeletePolicyCheck(agentId);
                                break;

                            default:
                                // "Unable to purge DB content for policy '%s'", p_id
                                return "Error: Unable to purge DB content for policy";
                        }
                    }
                }
            }
            break;
    }

    return std::nullopt;
}

/// Dump Functions ///

std::tuple<std::optional<std::string>, std::string, std::string>
checkDumpJSON(const base::Event& event, const std::string& scaEventPath)
{

    std::string policyId {};
    std::string scanId {};

    if (!event->exists(scaEventPath + "/elements_sent")
        || !event->isInt(scaEventPath + "/elements_sent"))
    {
        return {"Error: elements_sent not found", policyId, scanId};
    }

    if (!event->exists(scaEventPath + "/policy_id")
        || !event->isString(scaEventPath + "/policy_id"))
    {
        return {"Error: policy_id not found", policyId, scanId};
    }
    policyId = event->getString(scaEventPath + "/policy_id").value();

    if (!event->exists(scaEventPath + "/scan_id")
        || !event->isString(scaEventPath + "/scan_id"))
    {
        return {"Error: scan_id not found", policyId, scanId};
    }
    scanId = event->getString(scaEventPath + "/scan_id").value();

    return {std::nullopt, policyId, scanId};
}

bool deletePolicyCheckDistinct(const std::string& agentId,
                               const std::string& policyId,
                               const std::string& scanId,
                               std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    // "Deleting check distinct policy id , agent id "
    auto query = fmt::format(
        "agent {} sca delete_check_distinct {}|{}", agentId, policyId, scanId);

    auto [resultCode, payload] = wdb->tryQueryAndParseResult(query);
    switch (resultCode)
    {
        // If deleted or error we return true
        case wazuhdb::QueryResultCodes::OK:
        case wazuhdb::QueryResultCodes::ERROR: return true;
        // If other result we return false why?
        default: return false;
    }
}

// - Dump Handling - //

// Dump event received (type = dump), if is well formed we proceed to perform
// deletePolicyCheckDistinct and we compare policy hashes
// TODO: When this operations fails ??
std::optional<std::string> handleDumpEvent(base::Event& event,
                                           const std::string& agentId,
                                           const std::string& scaEventPath,
                                           std::shared_ptr<wazuhdb::WazuhDB> wdb)
{
    std::optional<std::string> error;

    // Check dump event JSON fields
    // If all the fields are ok continue, if not do nothing
    auto [checkError, policyId, scanId] = checkDumpJSON(event, scaEventPath);
    if (!checkError)
    {
        // "Deleting check distinct policy id , agent id "
        // Continue always, if rare error log error
        if (!deletePolicyCheckDistinct(agentId, policyId, scanId, wdb))
        {
            // DUE,    ///< Command processed successfully with pending data
            // IGNORE, ///< Command ignored
            // UNKNOWN ///< Unknown status / Unknown protocol
            // Abort

            // In the c code it logs the error and continues
            // return "Error: unknown, due or ignored error when deleting policy check "
            //        "distint wdb";
        }

        // OK,     ///< Command processed successfully
        // ERROR,  ///< An error occurred
        // Deleted succesfully or not, we dont know here so we try to find checks in wdb

        // Retreive hash from db
        auto [resultCode, hashCheckResults] = findCheckResults(agentId, policyId, wdb);
        if (0 == resultCode)
        {
            // Retreive hash from summary
            auto [scanResultCode, hashScanInfo] = findScanInfo(agentId, policyId, wdb);
            if (SearchResult::FOUND == scanResultCode && hashScanInfo.size() == 64)
            {
                if (hashCheckResults != hashScanInfo)
                {
                    // C Here logs error
                    //                     mdebug1("Scan result integrity failed for
                    //                     policy '%s'. Hash from DB: '%s' hash from
                    //                     summary: '%s'. Requesting DB dump.",
                    pushDumpRequest(agentId, policyId, 0);
                    return fmt::format(
                        "Scan result integrity failed for policy '{}'. Hash from DB: "
                        "'{}' hash from summary: '{}'. Requesting DB dump.",
                        policyId,
                        hashCheckResults,
                        hashScanInfo);
                }
            }
        }
    }

    // If error do nothing
    return std::nullopt;
}

} // namespace sca

// - Helper - //

base::Expression opBuilderSCAdecoder(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    // Parameter type check
    helper::base::checkParameterType(parameters[0],
                                     helper::base::Parameter::Type::REFERENCE);
    helper::base::checkParameterType(parameters[1],
                                     helper::base::Parameter::Type::REFERENCE);

    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {fmt::format(
        "[{}] -> Failure: [{}] is empty or is not an object", name, targetField)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure: ", name)};

    // TODO: we are not doing nothing on buildtime, wazuhdb initializer has 11 refs...
    // EventPaths and mappedPaths can be set in buildtime
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         name = std::string {name},
         targetField = std::move(targetField),
         scaEventPath = parameters[0].m_value,
         agentId = parameters[1].m_value,
         wdb = std::move(wdb)](base::Event event) -> base::result::Result<base::Event>
        {
            std::optional<std::string> error;

            // TODO: this should be checked in the decoder
            if (event->exists(scaEventPath))
            {
                // TODO: Field type is mandatory and should be checked in the decoder
                auto type = event->getString(scaEventPath + "/type");
                if (!type)
                {
                    // TODO: Change trace message
                    error = failureTrace1;
                }
                // Proccess event with the appropriate handler
                else if (sca::TYPE_CHECK == type.value())
                {
                    error = sca::HandleCheckEvent(event, agentId, scaEventPath);
                }
                else if (sca::TYPE_SUMMARY == type.value())
                {
                    error = sca::handleScanInfo(event, agentId, scaEventPath, wdb);
                }
                else if (sca::TYPE_POLICIES == type.value())
                {
                    error = sca::handlePoliciesInfo(event, agentId, scaEventPath, wdb);
                }
                else if (sca::TYPE_DUMP_END == type.value())
                {
                    error = sca::handleDumpEvent(event, agentId, scaEventPath, wdb);
                }
                // Unknown type value
                else
                {
                    // TODO: Change trace message
                    error = failureTrace2;
                }
            }
            else
            {
                error = failureTrace1;
            }

            // Event is processed, return base::Result accordingly
            // Error is nullopt if no error occurred, otherwise it contains the error
            // message
            // TODO: Is realy needed to set targetField bool? makes more sense that
            // targetField is the sca field, that is where we are mapping the fields
            if (error)
            {
                event->setBool(false, targetField);
                return base::result::makeFailure(event, error.value());
            }
            else
            {
                event->setBool(true, targetField);
                return base::result::makeSuccess(event, successTrace);
            }
        });
}

} // namespace builder::internals::builders
