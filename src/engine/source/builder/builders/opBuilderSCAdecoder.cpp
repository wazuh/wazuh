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
} // namespace sca
// SCA event json fields
namespace sca_field
{

enum class Name
{
    ID,
    POLICY,
    POLICY_ID,
    CHECK,
    CHECK_ID,
    CHECK_TITLE,
    CHECK_DESCRIPTION,
    CHECK_RATIONALE,
    CHECK_REMEDIATION,
    CHECK_REFERENCES,
    CHECK_COMPLIANCE,
    CHECK_CONDITION,
    CHECK_DIRECTORY,
    CHECK_PROCESS,
    CHECK_REGISTRY,
    CHECK_COMMAND,
    CHECK_RULES,
    CHECK_STATUS,
    CHECK_REASON,
    CHECK_RESULT,
    CHECK_FILE,
    // Aditional types
    TYPE,
    CHECK_PREVIOUS_RESULT
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
        case Name::POLICY: return "/policy";
        case Name::POLICY_ID: return "/policy_id";
        case Name::CHECK: return "/check";
        case Name::CHECK_ID: return "/check_id";
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
        // Aditional fields
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

} // namespace sca_field

namespace sca
{

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

enum class DbOperation
{
    ERROR = -1,
    INSERT,
    UPDATE

};

/********************************************
                Event info
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

    // Check types and mandatory fields if is necessary. Return false on fail.
    auto checkType =
        [&event](sca_field::Type type, const std::string& path, bool mandatory)
    {
        if (event->exists(path))
        {
            switch (type)
            {
                case sca_field::Type::STRING: return event->isString(path);
                case sca_field::Type::INT: return event->isInt(path);
                case sca_field::Type::BOOL: return event->isBool(path);
                case sca_field::Type::ARRAY: return event->isArray(path);
                case sca_field::Type::OBJECT: return event->isObject(path);
                default: return false; // TODO Logic error?
            }
        }
        else if (mandatory)
        {
            return false;
        }
        return true;
    };

    // Valid ONLY CheckEventJSON
    std::tuple<sca_field::Name, sca_field::Type, bool> listFieldConditions[] = {
        {sca_field::Name::ID, sca_field::Type::INT, true},
        {sca_field::Name::POLICY, sca_field::Type::STRING, true},
        {sca_field::Name::POLICY_ID, sca_field::Type::STRING, true},
        {sca_field::Name::CHECK, sca_field::Type::OBJECT, true},
        {sca_field::Name::CHECK_ID, sca_field::Type::INT, true},
        {sca_field::Name::CHECK_TITLE, sca_field::Type::STRING, true},
        {sca_field::Name::CHECK_DESCRIPTION, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_RATIONALE, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_REMEDIATION, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_REFERENCES, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_COMPLIANCE, sca_field::Type::OBJECT, false},
        {sca_field::Name::CHECK_RULES, sca_field::Type::ARRAY, false},
        {sca_field::Name::CHECK_CONDITION, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_DIRECTORY, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_PROCESS, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_REGISTRY, sca_field::Type::STRING, false},
        {sca_field::Name::CHECK_COMMAND, sca_field::Type::STRING, false}
        //"/check/compliance", -> ??? // TODO Check this
        //"/check/rules", -> ???
    };

    for (const auto& fieldInfo : listFieldConditions)
    {
        const auto& field = std::get<0>(fieldInfo);
        const auto& type = std::get<1>(fieldInfo);
        const auto& mandatory = std::get<2>(fieldInfo);

        const auto path = sca_field::getEventPath(field, scaEventPath);
        if (!checkType(type, path, mandatory))
        {
            return false;
        }
    }

    // If /CHECK_RESULT exist status then, shoud exists /CHECK/REASON
    if (event->exists(
            sca_field::getEventPath(sca_field::Name::CHECK_RESULT, scaEventPath)))
    {
        bool validResult = event->isString(
            sca_field::getEventPath(sca_field::Name::CHECK_RESULT, scaEventPath));
        if (!validResult)
        {
            return false;
        }
    }
    else if (event->exists(
                 sca_field::getEventPath(sca_field::Name::CHECK_STATUS, scaEventPath)))
    {
        // If the result doesn't exist, the state shouldn't either.
        return false;
    }

    return true;
}
// Simpre se llama en handle check event
void FillCheckEventInfo(base::Event& event,
                        const std::string& response,
                        const std::string& scaEventPath)
{

    event->setString("check", sca_field::getSCAPath(sca_field::Name::TYPE));

    // Save the previous result
    if (!response.empty())
    {
        event->setString(response.c_str(),
                         sca_field::getSCAPath(sca_field::Name::CHECK_PREVIOUS_RESULT));
    }

    // Copy if exist from event to sca
    auto copyIfExist = [&event, &scaEventPath](sca_field::Name field)
    {
        event->set(sca_field::getEventPath(field, scaEventPath),
                   sca_field::getSCAPath(field));
    };

    // Convert cvs (string) from event if exist, to array in SCA
    auto cvsStr2ArrayIfExist = [&event, &scaEventPath](sca_field::Name field)
    {
        if (event->exists(sca_field::getEventPath(field, scaEventPath)))
        {
            auto cvs = event->getString(sca_field::getEventPath(field, scaEventPath));
            if (cvs)
            {
                const auto scaArrayPath = sca_field::getSCAPath(field);
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

    copyIfExist(sca_field::Name::ID);
    copyIfExist(sca_field::Name::POLICY);
    copyIfExist(sca_field::Name::POLICY_ID);

    copyIfExist(sca_field::Name::CHECK_ID);
    copyIfExist(sca_field::Name::CHECK_TITLE);
    copyIfExist(sca_field::Name::CHECK_DESCRIPTION);
    copyIfExist(sca_field::Name::CHECK_RATIONALE);
    copyIfExist(sca_field::Name::CHECK_REMEDIATION);
    copyIfExist(sca_field::Name::CHECK_COMPLIANCE);
    copyIfExist(sca_field::Name::CHECK_REFERENCES);
    // copyIfExist(sca_field::Name::CHECK_RULES);  TODO: Why not copy this?

    // Optional fields with cvs
    cvsStr2ArrayIfExist(sca_field::Name::CHECK_FILE);
    cvsStr2ArrayIfExist(sca_field::Name::CHECK_DIRECTORY);
    cvsStr2ArrayIfExist(sca_field::Name::CHECK_REGISTRY);
    cvsStr2ArrayIfExist(sca_field::Name::CHECK_PROCESS);
    cvsStr2ArrayIfExist(sca_field::Name::CHECK_COMMAND);

    if (event->exists(
            sca_field::getEventPath(sca_field::Name::CHECK_RESULT, scaEventPath)))
    {
        event->set(sca_field::getEventPath(sca_field::Name::CHECK_RESULT, scaEventPath),
                   sca_field::getSCAPath(sca_field::Name::CHECK_RESULT));
    }
    else
    {
        copyIfExist(sca_field::Name::CHECK_STATUS);
        copyIfExist(sca_field::Name::CHECK_REASON);
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
    const auto scanID =
        event->getInt(sca_field::getEventPath(sca_field::Name::ID, scaEventPath));
    const auto scaQuery = fmt::format("agent {} sca query {}", agent_id, scanID.value());

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
        event->getInt(sca_field::getEventPath(sca_field::Name::CHECK_ID, scaEventPath));
    auto checkID = std::to_string(checkIDint.value());

    // Return empty string if not found
    auto getStringIfExist = [&event, &scaEventPath](sca_field::Name field)
    {
        std::string value {};
        if (event->exists(sca_field::getEventPath(field, scaEventPath)))
        {
            auto optVal = event->getString(sca_field::getEventPath(field, scaEventPath));
            if (optVal.has_value())
            {
                value = std::move(optVal.value());
            }
        }
        return value;
    };

    auto result = getStringIfExist(sca_field::Name::CHECK_RESULT);
    auto status = getStringIfExist(sca_field::Name::CHECK_STATUS);
    auto reason = getStringIfExist(sca_field::Name::CHECK_REASON);

    // ----------------- Create funcition 2 ----------------- //

    // Process result, check if the event exists in the wazuhdb, then update it or insert
    // it
    auto getOperationAndQuery = [&event,
                                 &agent_id,
                                 checkIDint,
                                 scanID,
                                 &wdb_response,
                                 &result,
                                 &status,
                                 &reason]()
    {
        auto operation = DbOperation::ERROR;
        std::string query {};

        if (std::strncmp(wdb_response.c_str(), "not found", 9) == 0)
        {
            // It exists, update (SaveEventcheck)
            operation = DbOperation::UPDATE;

            query = fmt::format("agent {} sca update {}|{}|{}|{}|{}",
                                agent_id,
                                checkIDint.value(),
                                result,
                                status,
                                reason,
                                scanID.value());
        }
        else if (std::strncmp(wdb_response.c_str(), "found", 5) == 0)
        {
            // It not exists, insert
            operation = DbOperation::INSERT;

            // TODO CHANGE THIS, IT IS NOT THE RIGHT WAY TO DO IT
            auto event_original = event->getString("/event/original");

            query =
                fmt::format("agent {} sca insert {}", agent_id, event_original.value());

            // wdb_response = response.substr(5); // removing "found "
        }

        return std::make_tuple<>(operation, query);
    };

    auto [operation, SaveEventQuery] = getOperationAndQuery();

    if (DbOperation::ERROR == operation)
    {
        return "Error querying policy monitoring database";
    }
    // TODO Delete this, it is not the right way to do it
    if (DbOperation::UPDATE == operation)
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
        case DbOperation::UPDATE:
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

        case DbOperation::INSERT:
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
                sca_field::getEventPath(sca_field::Name::CHECK_COMPLIANCE, scaEventPath);
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
            auto rulesPath =
                sca_field::getEventPath(sca_field::Name::CHECK_RULES, scaEventPath);
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

/// Scan Info Functions ///

bool CheckScanInfoJSON(base::Event& event, const std::string& scaEventPath)
{
    if (!event->isObject(scaEventPath))
    {
        return false;
    }

    for (const auto& [key, _val] : scanInfoKeyValues)
    {

        const auto value = event->getString(scaEventPath + key);
        // TODO Remnove this, why isObject trow exception, should be false  to avoid
        // double search (exists+isObject)?
        if (value)
        {
            scanInfoKeyValues[key] = value.value();
        }
        else
        {
            return false;
        }
    }

    auto scanId = event->getInt("/scan_id");
    if (scanId.has_value())
    {
        //    // TODO: make it varaiant in order to avoid double casting
        // afterwars it will be used as string on query, double check this!
        scanInfoKeyValues["/scan_id"] = std::to_string(scanId.value());
    }
    else
    {
        return false;
    }

    // Check and get fields
    std::vector<std::string> mandatoryFields = {"/start_time",
                                                "/end_time",
                                                "/passed",
                                                "/failed",
                                                "/invalid",
                                                "/total_checks",
                                                "/score"};

    for (const auto& key : mandatoryFields)
    {
        const auto value = event->getString(scaEventPath + key);
        if (value)
        {
            scanInfoKeyValues.insert({key, value.value()});
        }
        else
        {
            return false;
        }
    }

    // TODO: maybe not neccesary! Get other fields
    std::vector<std::string> notMandatoryFields = {
        "/first_scan", "/force_alert", "/description", "/references"};

    for (const auto& key : notMandatoryFields)
    {
        const auto value = event->getString(scaEventPath + key);
        if (value)
        {
            scanInfoKeyValues.insert({key, value.value()});
        }
    }

    return true;
}

// TODO: Change, No use parameter as output, returno tuple with optional
std::tuple<int, std::string> findScanInfo(const std::string& agentId,
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
            return {0, payload.value().substr(6)}; // removing found
        }
        else if (utils::string::startsWith(payload.value(), "not found"))
        {
            return {1, ""};
        }
    }
    return {-1, ""};
}

int SaveScanInfo(base::Event& event, const std::string& agent_id, int update)
{
    // "Retrieving sha256 hash for policy id: policy_id"
    std::string SaveScanInfoQuery {};

    // TODO Avoid copy, use auto&, std::string_view or other technique
    std::string pm_start_scan = scanInfoKeyValues["/start_time"];
    std::string pm_end_scan = scanInfoKeyValues["/end_time"];
    std::string scan_id = scanInfoKeyValues["/id"];
    std::string policy_id = scanInfoKeyValues["/policy_id"];
    std::string pass = scanInfoKeyValues["/passed"];
    std::string failed = scanInfoKeyValues["/failed"];
    std::string invalid = scanInfoKeyValues["/invalid"];
    std::string total_checks = scanInfoKeyValues["/total_checks"];
    std::string score = scanInfoKeyValues["/score"];
    std::string hash = scanInfoKeyValues["/hash"];
    // TODO This is a int
    if (!update)
    {
        SaveScanInfoQuery = std::string("agent ") + agent_id + " sca insert_scan_info "
                            + pm_start_scan + "|" + pm_end_scan + "|" + scan_id + "|"
                            + policy_id + "|" + pass + "|" + failed + "|" + invalid + "|"
                            + total_checks + "|" + score + "|" + hash;
    }
    else
    {
        SaveScanInfoQuery =
            std::string("agent ") + agent_id + " sca update_scan_info_start " + policy_id
            + "|" + pm_start_scan + "|" + pm_end_scan + "|" + scan_id + "|" + pass + "|"
            + failed + "|" + invalid + "|" + total_checks + "|" + score + "|" + hash;
    }

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto SaveScanInfoTuple = wdb.tryQueryAndParseResult(SaveScanInfoQuery);

    int result_db = -1;
    if (std::get<0>(SaveScanInfoTuple) == wazuhdb::QueryResultCodes::OK)
    {
        result_db = 0;
    }
    return result_db;
}

int FindPolicyInfo(base::Event& event, const std::string& agent_id)
{
    // "Find policies IDs for policy '%s', agent id '%s'"
    const auto FindPolicyInfoQuery = std::string("agent ") + agent_id
                                     + " sca query_policy "
                                     + scanInfoKeyValues["/policy_id"];

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto FindPolicyInfoTuple = wdb.tryQueryAndParseResult(FindPolicyInfoQuery);

    int result_db = -1;
    if (std::get<0>(FindPolicyInfoTuple) == wazuhdb::QueryResultCodes::OK
        && std::get<1>(FindPolicyInfoTuple).has_value())
    {
        const auto& FindPolicyInfoResponse = std::get<1>(FindPolicyInfoTuple).value();
        if (std::strncmp(FindPolicyInfoResponse.c_str(), "not found", 9) == 0)
        {
            result_db = 1;
        }
        else if (std::strncmp(FindPolicyInfoResponse.c_str(), "found", 5) == 0)
        {
            result_db = 0;
        }
    }
    return result_db;
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

int SavePolicyInfo(const std::string& agent_id,
                   std::string& description_db,
                   std::string& references_db)
{
    // "Saving policy info for policy id '%s', agent id '%s'"
    std::string policy_id = scanInfoKeyValues["/policy_id"];
    std::string name = scanInfoKeyValues["/policy"];
    std::string file = scanInfoKeyValues["/file"];
    std::string hash_file = scanInfoKeyValues["/hash_file"];
    std::string desc = description_db.empty() ? "NULL" : description_db;
    std::string ref = references_db.empty() ? "NULL" : references_db;
    std::string SavePolicyInfoTupleQuery =
        std::string("agent ") + agent_id + " sca insert_policy " + name + "|" + file + "|"
        + policy_id + "|" + desc + "|" + ref + "|" + hash_file;

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto SavePolicyInfoTuple = wdb.tryQueryAndParseResult(SavePolicyInfoTupleQuery);

    int result_db = -1;
    if (std::get<0>(SavePolicyInfoTuple) == wazuhdb::QueryResultCodes::OK)
    {
        result_db = 0;
    }
    return result_db;
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
    if (!CheckScanInfoJSON(event, scaEventPath))
    {
        return "fail on CheckScanInfoJSON"; // Fail on check
    }

    int result_event = 0;
    std::string policyId; // TODO: Get policyId
    auto [result_db, hash_scan_info] = findScanInfo(agent_id, policyId, wdb);

    const auto& separated_hash = utils::string::split(hash_scan_info, ' ');

    if (separated_hash.size() < 2)
    {
        // TODO: Whats is this?, why is commented?
        // mdebug1("Retrieving sha256 hash for policy: '%s'", policy_id->valuestring);
    }
    // TODO, capture exception, stoi can throw exception (Also, at method)
    auto scan_id_old = stoi(separated_hash.at(1));
    auto hash_sha256 = separated_hash.at(0); // Should I chek qtty of chars? (%64s)

    std::string hash = scanInfoKeyValues["/hash"];
    std::string first_scan;
    std::string force_alert;

    if (scanInfoKeyValues.find("/first_scan") != scanInfoKeyValues.end())
    {
        first_scan = scanInfoKeyValues["/first_scan"];
    }
    if (scanInfoKeyValues.find("/force_alert") != scanInfoKeyValues.end())
    {
        force_alert = scanInfoKeyValues["/force_alert"];
    }

    switch (result_db)
    {
        case -1:
            // merror("Error querying policy monitoring database for agent
            break;
        case 0:
            // It exists, update
            result_event = SaveScanInfo(event, agent_id, 1);
            if (result_event < 0)
            {
                // TODO, why is commented?, what should be do?
                // merror("Error updating scan policy monitoring database for agent
            }
            else
            {
                /* Compare hash with previous hash */
                // TODO Can be only 1 condition for fillscaninfo
                if (hash_sha256 == hash)
                {
                    if (first_scan.empty())
                    {
                        FillScanInfo(event, agent_id, scaEventPath);
                        alert_data_fill = 1;
                    }
                }

                if (!force_alert.empty() && !alert_data_fill)
                {
                    FillScanInfo(event, agent_id, scaEventPath);
                }
            }
            break;
        case 1:
            // It not exists, insert
            result_event = SaveScanInfo(event, agent_id, 0);
            if (result_event < 0)
            {
                // TODO, why is commented?, what should be do?
                // merror("Error storing scan policy monitoring information for
            }
            else
            {
                /* Compare hash with previous hash */
                if (hash_sha256 == hash)
                {
                    if (first_scan.empty())
                    {
                        FillScanInfo(event, agent_id, scaEventPath);
                        alert_data_fill = 1;
                    }
                    else
                    {
                        /* Request dump */
                        pushDumpRequest(agent_id, policyId, 1);
                    }
                }

                if (!force_alert.empty() && !alert_data_fill)
                {
                    FillScanInfo(event, agent_id, scaEventPath);
                }
            }

            break;
        default: break;
    }

    result_db = FindPolicyInfo(event, agent_id);

    switch (result_db)
    {
        case -1:
            // merror("Error querying policy monitoring database for agent
            break;
        case 1:
        {
            std::string references_db {};
            std::string description_db {};
            // It not exists, insert from event
            if (scanInfoKeyValues.find("/references") != scanInfoKeyValues.end())
            {
                // Double check value type
                references_db = scanInfoKeyValues["/references"];
            }

            if (scanInfoKeyValues.find("/description") != scanInfoKeyValues.end())
            {
                // Double check value type
                description_db = scanInfoKeyValues["/description"];
            }

            result_event = SavePolicyInfo(agent_id, description_db, references_db);
            if (result_event < 0)
            {
                // merror("Error storing scan policy monitoring information for
            }
        }
        break;
        default:
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
            break;
    }
    // TODO: change result name
    auto [result_db2, wdb_response] = findCheckResults(agent_id, policyId, wdb);

    switch (result_db2)
    {
        case 0:
            /* Integrity check */
            if (wdb_response == hash)
            {
                // mdebug1("Scan result integrity failed for policy '%s'. Hash from
                // DB:'%s', hash from summary: '%s'. Requesting DB
                // dump.",policy_id->valuestring, wdb_response, hash->valuestring);
                if (first_scan.empty())
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
            if (first_scan.empty())
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
    std::string policiesIds{};

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
            if (0 == scanResultCode && hashScanInfo.size() == 64)
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
