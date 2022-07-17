/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderSCAdecoder.hpp"

#include <string>

#include <fmt/format.h>

#include "protocolHandler.hpp"
#include "syntax.hpp"
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/stringUtils.hpp>
#include <wdb/wdb.hpp>

namespace builder::internals::builders
{

// TODO: remove when undoing set for testing
constexpr std::string_view STREAM_SOCK_PATH = "/tmp/testStream.socket";

/// Event Info Functions ///

static std::unordered_map<std::string, std::string> eventKeyValues {
    {"/policy", ""},
    {"/policy_id", ""},
    {"/check/title", ""},
};

static bool CheckEventJSON(base::Event& e)
{
    // TODO: check value types should always return false if not matched as espected
    // Check existance and fill all mandatory fields
    const auto& doc = e->getEvent()->get(engineserver::EVENT_LOG);
    for (auto& pairKeyValue : eventKeyValues)
    {
        const std::string key = pairKeyValue.first;
        json::Value::ConstMemberIterator itr = doc.FindMember(key.c_str());
        if (itr != doc.MemberEnd() && itr->value.IsString())
        {
            eventKeyValues[key] = itr->value.GetString();
        }
        else
        {
            return false;
        }
    }

    // scan_id
    json::Value::ConstMemberIterator itr = doc.FindMember("/id");
    if (itr != doc.MemberEnd() && itr->value.IsInt())
    {
        // TODO: make it varaiant in order to avoid double casting
        eventKeyValues["/id"] = std::to_string(itr->value.GetInt());
    }
    else
    {
        return false;
    }

    itr = doc.FindMember("/check/id");
    if (itr != doc.MemberEnd() && itr->value.IsInt())
    {
        // TODO: make it varaiant in order to avoid double casting
        eventKeyValues["/check/id"] = std::to_string(itr->value.GetInt());
    }
    else
    {
        return false;
    }

    // Continue filling all other not mandatory Event fields
    std::vector<std::string> notMandatoryFields {
        "/check/description",
        "/check/rationale",
        "/check/remediation",
        "/check/references",
        "/check/file",
        "/check/condition",
        "/check/directory",
        "/check/process",
        "/check/registry",
        "/check/command",
    };

    for (auto& key : notMandatoryFields)
    {
        json::Value::ConstMemberIterator itr = doc.FindMember(key.c_str());
        if (itr != doc.MemberEnd())
        {
            if (!itr->value.IsString())
            {
                return false;
            }
            eventKeyValues.insert({key, itr->value.GetString()});
        }
    }

    itr = doc.FindMember("/check/status");
    if (itr != doc.MemberEnd())
    {
        json::Value::ConstMemberIterator itrReason = doc.FindMember("/check/reason");
        if (itrReason == doc.MemberEnd() || !itrReason->value.IsString()
            || !itr->value.IsString())
        {
            return false;
        }
        eventKeyValues["/check/reason"] = itrReason->value.GetString();
        eventKeyValues["/check/status"] = itr->value.GetString();
    }

    itr = doc.FindMember("/check/result");
    if ((eventKeyValues.find("/check/status") == eventKeyValues.end()
         && itr != doc.MemberEnd())
        || !itr->value.IsString())
    {
        return false;
    }
    eventKeyValues["/check/result"] = itr->value.GetString();

    return true;
}

static void FillCheckEventInfo(base::Event& e, std::string response)
{
    std::string field = {json::formatJsonPath("sca.type")};
    e->getEvent()->set(field,
                       rapidjson::Value("check", e->getEventDocAllocator()).Move());

    field = json::formatJsonPath("sca.check.previous_result");
    e->getEvent()->set(
        field, rapidjson::Value(response.c_str(), e->getEventDocAllocator()).Move());

    field = {json::formatJsonPath("sca.scan_id")};
    e->getEvent()->set(
        field,
        rapidjson::Value(eventKeyValues["/id"].c_str(), e->getEventDocAllocator())
            .Move());

    field = {json::formatJsonPath("sca.policy")};
    e->getEvent()->set(
        field,
        rapidjson::Value(eventKeyValues["/policy"].c_str(), e->getEventDocAllocator())
            .Move());

    field = {json::formatJsonPath("sca.check.id")};
    e->getEvent()->set(
        field,
        rapidjson::Value(eventKeyValues["/check/id"].c_str(), e->getEventDocAllocator())
            .Move());

    if (!eventKeyValues["/check/title"].empty())
    {
        field = {json::formatJsonPath("sca.check.title")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/title"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/description"].empty())
    {
        field = {json::formatJsonPath("sca.check.description")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/description"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/rationale"].empty())
    {
        field = {json::formatJsonPath("sca.check.rationale")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/rationale"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/remediation"].empty())
    {
        field = {json::formatJsonPath("sca.check.remediation")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/remediation"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    const auto& compliance = e->getEvent()->get("/event/original/check/compliance");
    for (rapidjson::Value::ConstMemberIterator itr = compliance.MemberBegin();
         itr != compliance.MemberEnd();
         ++itr)
    {
        const std::string& key = itr->name.GetString();
        field = {json::formatJsonPath(std::string("sca.check.compliance.") + key)};
        if (itr->value.IsInt())
        {
            const int& value = itr->value.GetInt();
            e->getEvent()->set(field, rapidjson::Value(value));
        }
        else if (itr->value.IsDouble())
        {
            const double& value = itr->value.GetDouble();
            e->getEvent()->set(field, rapidjson::Value(value));
        }
        else
        {
            const std::string& value = itr->value.GetString();
            e->getEvent()->set(
                field, rapidjson::Value(value.c_str(), e->getEventDocAllocator()).Move());
        }
    }

    if (!eventKeyValues["/check/references"].empty())
    {
        field = {json::formatJsonPath("sca.check.references")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/references"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/file"].empty())
    {
        field = {json::formatJsonPath("sca.check.file")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/file"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/directory"].empty())
    {
        field = {json::formatJsonPath("sca.check.directory")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/directory"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/registry"].empty())
    {
        field = {json::formatJsonPath("sca.check.registry")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/registry"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/process"].empty())
    {
        field = {json::formatJsonPath("sca.check.process")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/process"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/command"].empty())
    {
        field = {json::formatJsonPath("sca.check.command")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/command"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }

    if (!eventKeyValues["/check/result"].empty())
    {
        field = {json::formatJsonPath("sca.check.result")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/result"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
    }
    else
    {
        field = {json::formatJsonPath("sca.check.status")};
        e->getEvent()->set(field,
                           rapidjson::Value(eventKeyValues["/check/status"].c_str(),
                                            e->getEventDocAllocator())
                               .Move());
        if (!eventKeyValues["/check/reason"].empty())
        {
            field = {json::formatJsonPath("sca.check.reason")};
            e->getEvent()->set(field,
                               rapidjson::Value(eventKeyValues["/check/reason"].c_str(),
                                                e->getEventDocAllocator())
                                   .Move());
        }
    }
}

// - Event Info Handling - //

static bool HandleCheckEvent(base::Event& e, types::TracerFn tr)
{
    std::string failureTrace = fmt::format("HandleCheckEvent sca_decode Failure");

    if (!CheckEventJSON(e))
    {
        // exit error
        tr(failureTrace);
        return false;
    }

    // TODO: delete sock_path!
    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    const auto& agent_id = e->getEvent()->get("/agent/id");
    const auto& pm_id = e->getEvent()->get("/event/original/id");

    // FindEventcheck wdb_response
    const std::string scaQuery =
        std::string("agent ") + agent_id.GetString() + " sca query " + pm_id.GetString();
    auto tupleScaResponse = wdb.tryQueryAndParseResult(scaQuery);
    auto resultCode = std::get<0>(tupleScaResponse);
    std::string wdb_response;

    if (resultCode != wazuhdb::QueryResultCodes::OK)
    {
        tr(failureTrace);
        return false;
    }

    std::string SaveEventQuery;
    wdb_response = std::get<1>(tupleScaResponse).value();
    int result_db = -1;
    std::string scan_id = eventKeyValues["/id"]; // scan_id if not vailable = -1
    std::string id = eventKeyValues["/check/id"];
    std::string result = eventKeyValues["/check/result"];
    std::string status = eventKeyValues["/check/status"];
    std::string reason = eventKeyValues["/check/reason"];

    if (wdb_response.find("not found") != std::string::npos)
    {
        // It exists, update
        result_db = 1;
        SaveEventQuery = std::string("agent ") + agent_id.GetString() + " sca update "
                         + id + "|" + result + "|" + status + "|" + reason + "|"
                         + scan_id;
    }
    else if (wdb_response.find("found") != std::string::npos)
    {
        // It not exists, insert
        result_db = 0;
        wdb_response = wdb_response.substr(5); // removing "found"
        SaveEventQuery = std::string("agent ") + agent_id.GetString() + " sca insert "
                         + e->getEvent()->get("/event/original").GetString();
    }

    auto saveEventTuple = wdb.tryQueryAndParseResult(SaveEventQuery);
    std::string saveEventResponse = std::get<1>(saveEventTuple).value();
    const auto result_event =
        (std::get<0>(saveEventTuple) == wazuhdb::QueryResultCodes::OK) ? 0 : 1;
    bool functionResult = true;
    switch (result_db)
    {
        case -1:
            // Error querying policy monitoring database for agent
            tr(failureTrace);
            functionResult = false;
            break;
        case 0:
            if (!result.empty() && (wdb_response == result))
            {
                FillCheckEventInfo(e, wdb_response);
            }
            else if (result.empty() && !status.empty() && (wdb_response == status))
            {
                FillCheckEventInfo(e, wdb_response);
            }

            if (result_event < 0)
            {
                // Error updating policy monitoring database for agent
                tr(failureTrace);
                functionResult = false;
            }
            break;
        case 1:
            if (!result.empty() && (wdb_response == result))
            {
                FillCheckEventInfo(e, wdb_response);
            }
            else if (result.empty() && !status.empty() && (wdb_response == status))
            {
                FillCheckEventInfo(e, wdb_response);
            }

            if (result_event < 0)
            {
                // Error storing policy monitoring information for agent
                tr(failureTrace);
                functionResult = false;
            }
            else
            {
                // Saving compliance fields to database for event id
                const auto& compliance =
                    e->getEvent()->get("/event/original/check/compliance");

                for (rapidjson::Value::ConstMemberIterator itr = compliance.MemberBegin();
                     itr != compliance.MemberEnd();
                     ++itr)
                {
                    const std::string& key = itr->name.GetString();
                    const std::string& value = itr->value.GetString();
                    // TODO: check types id should be an integer -> does it change the
                    // query?
                    std::string saveComplianceQuery =
                        std::string("agent ") + agent_id.GetString()
                        + " sca insert_compliance " + id + "|" + key + "|" + value;
                    wdb.tryQueryAndParseResult(saveComplianceQuery);
                    // Should I warn if ResultCode isn't ok ?
                }

                // Save rules
                const auto& rules = e->getEvent()->get("/event/original/check/rules");
                for (auto const& rule : rules.GetArray())
                {
                    if (rule.IsString())
                    {
                        char flag = rule.GetString()[0];
                        std::string type;
                        switch (flag)
                        {
                            case 'f': type = "file"; break;
                            case 'd': type = "directory"; break;
                            case 'r': type = "registry"; break;
                            case 'c': type = "command"; break;
                            case 'p': type = "process"; break;
                            case 'n': type = "numeric"; break;
                            default:
                                // Invalid type: flag
                                continue;
                        }
                        std::string saveRulesQuery = std::string("agent ")
                                                     + agent_id.GetString()
                                                     + " sca insert_rules " + id + "|"
                                                     + type + "|" + rule.GetString();
                        wdb.tryQueryAndParseResult(saveRulesQuery);
                    }
                }
            }
            break;

        default: functionResult = false; break;
    }
    return functionResult;
}

/// Scan Info Functions ///
/* Security configuration assessment remoted queue */
constexpr const char* CFGARQUEUE {"/tmp/cfgar.sock"}; //"queue/alerts/cfgarq"

// Map where needed json fields will be stored
static std::unordered_map<std::string, std::string> scanInfoKeyValues {{"/policy_id", ""},
                                                                       {"/hash", ""},
                                                                       {"/hash_file", ""},
                                                                       {"/file", ""},
                                                                       {"/policy", ""}};

static bool CheckScanInfoJSON(base::Event& e)
{
    // Check and get fields with string type checking
    const auto& doc = e->getEvent()->get(engineserver::EVENT_LOG);
    for (auto& pairKeyValue : scanInfoKeyValues)
    {
        const std::string key = pairKeyValue.first;
        json::Value::ConstMemberIterator itr = doc.FindMember(key.c_str());
        if (itr != doc.MemberEnd() && itr->value.IsString())
        {
            scanInfoKeyValues[key] = itr->value.GetString();
        }
        else
        {
            return false;
        }
    }

    // scan_id
    json::Value::ConstMemberIterator itr = doc.FindMember("/scan_id");
    if (itr != doc.MemberEnd() && itr->value.IsInt())
    {
        // TODO: make it variant in order to avoid double casting
        // afterwars it will be used as string on query, double check this!
        scanInfoKeyValues["/scan_id"] = std::to_string(itr->value.GetInt());
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

    for (auto& key : mandatoryFields)
    {
        json::Value::ConstMemberIterator itr = doc.FindMember(key.c_str());
        if (itr != doc.MemberEnd())
        {
            scanInfoKeyValues.insert({key, itr->value.GetString()});
        }
        else
        {
            return false;
        }
    }

    // Not mandatory fields
    std::vector<std::string> notMandatoryFields = {
        "/first_scan", "/force_alert", "/description", "/references"};

    for (auto& key : notMandatoryFields)
    {
        json::Value::ConstMemberIterator itr = doc.FindMember(key.c_str());
        if (itr != doc.MemberEnd())
        {
            scanInfoKeyValues.insert({key, itr->value.GetString()});
        }
    }

    return true;
}

static int FindScanInfo(base::Event& e, std::string& hash_scan_info)
{
    // "Retrieving sha256 hash for policy id: policy_id"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string FindScanInfoQuery = std::string("agent ") + agent_id + " sca query_scan "
                                    + scanInfoKeyValues["/policy_id"];

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto FindScanInfoTuple = wdb.tryQueryAndParseResult(FindScanInfoQuery);
    std::string FindScanInfoResponse = std::get<1>(FindScanInfoTuple).value();

    int result_db = -1;
    if (std::get<0>(FindScanInfoTuple) == wazuhdb::QueryResultCodes::OK)
    {
        if (FindScanInfoResponse.find("not found") != std::string::npos)
        {
            result_db = 1;
        }
        else if (FindScanInfoResponse.find("found") != std::string::npos)
        {
            hash_scan_info = FindScanInfoResponse.substr(5); // removing found
            result_db = 0;
        }
    }
    return result_db;
}

static int SaveScanInfo(base::Event& e, int update)
{
    // "Retrieving sha256 hash for policy id: policy_id"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string SaveScanInfoQuery;

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

static int FindPolicyInfo(base::Event& e)
{
    // "Find policies IDs for policy  agent id "
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string FindPolicyInfoQuery = std::string("agent ") + agent_id
                                      + " sca query_policy "
                                      + scanInfoKeyValues["/policy_id"];

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto FindPolicyInfoTuple = wdb.tryQueryAndParseResult(FindPolicyInfoQuery);
    std::string FindPolicyInfoResponse = std::get<1>(FindPolicyInfoTuple).value();

    int result_db = -1;
    if (std::get<0>(FindPolicyInfoTuple) == wazuhdb::QueryResultCodes::OK)
    {
        if (FindPolicyInfoResponse.find("not found") != std::string::npos)
        {
            result_db = 1;
        }
        else if (FindPolicyInfoResponse.find("found") != std::string::npos)
        {
            result_db = 0;
        }
    }
    return result_db;
}

static void PushDumpRequest(base::Event& e, int first_scan)
{
    // from RequestDBThread I'm assuming there's no chance a manager can be the agent
    // that's why Im using just opening CFGARQUEUE
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string policy_id = scanInfoKeyValues["/policy_id"];
    std::string msg =
        agent_id + ":sca-dump:" + policy_id + ":" + std::to_string(first_scan);

    base::utils::socketInterface::unixDatagram socketCFFGA(CFGARQUEUE);

    socketCFFGA.sendMsg(msg); // should check SendRetval::SUCCESS
}

static int
SavePolicyInfo(base::Event& e, std::string& description_db, std::string& references_db)
{
    // "Saving policy info for policy id agent id"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
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

static int FindPolicySHA256(base::Event& e, std::string& old_hash)
{
    // "Find sha256 for policy X, agent id Y"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string FindPolicySHA256Query = std::string("agent ") + agent_id
                                        + " sca query_policy_sha256 "
                                        + scanInfoKeyValues["/policy_id"];

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto FindPolicySHA256Tuple = wdb.tryQueryAndParseResult(FindPolicySHA256Query);
    std::string FindPolicySHA256Response = std::get<1>(FindPolicySHA256Tuple).value();

    int result_db = -1;
    if (std::get<0>(FindPolicySHA256Tuple) == wazuhdb::QueryResultCodes::OK)
    {
        if (FindPolicySHA256Response.find("not found") != std::string::npos)
        {
            result_db = 1;
        }
        else if (FindPolicySHA256Response.find("found") != std::string::npos)
        {
            old_hash = FindPolicySHA256Response.substr(5); // removing found
            result_db = 0;
        }
    }
    return result_db;
}

static int DeletePolicy(base::Event& e)
{
    // "Deleting policy"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
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

static int DeletePolicyCheck(base::Event& e)
{
    // "Deleting check for policy agent id "
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
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

static int FindCheckResults(base::Event& e, std::string& wdb_response)
{
    // "Find check results for policy id"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string findCheckResultsQuery = std::string("agent ") + agent_id
                                        + " sca query_results "
                                        + scanInfoKeyValues["/policy_id"];

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto findCheckResultsTuple = wdb.tryQueryAndParseResult(findCheckResultsQuery);
    std::string findCheckResultsResponse = std::get<1>(findCheckResultsTuple).value();

    int result_db = -1;
    if (std::get<0>(findCheckResultsTuple) == wazuhdb::QueryResultCodes::OK)
    {
        if (findCheckResultsResponse.find("not found") != std::string::npos)
        {
            result_db = 1;
        }
        else if (findCheckResultsResponse.find("found") != std::string::npos)
        {
            wdb_response = findCheckResultsResponse.substr(5); // removing found
            result_db = 0;
        }
    }
    return result_db;
}

static void FillScanInfo(base::Event& e)
{
    std::string field = {json::formatJsonPath("sca.type")};
    e->getEvent()->set(field,
                       rapidjson::Value("summary", e->getEventDocAllocator()).Move());

    const std::unordered_map<std::string, std::string> string_field_newKey = {
        {"/policy", "sca.policy"},
        {"/description", "sca.description"},
        {"/policy_id", "sca.policy_id"},
        {"/file", "sca.file"},
    };

    for (auto& [key, newKey] : string_field_newKey)
    {
        std::string value;
        if (scanInfoKeyValues.find(key) != scanInfoKeyValues.end())
        {
            value = scanInfoKeyValues[key];
        }
        std::string field = {json::formatJsonPath(newKey)};
        e->getEvent()->set(
            field, rapidjson::Value(value.c_str(), e->getEventDocAllocator()).Move());
    }

    const std::unordered_map<std::string, std::string> integer_field_newKey = {
        {"/scan_id", "sca.scan_id"},
        {"/passed", "sca.passed"},
        {"/policy_id", "sca.failed"},
        {"/invalid", "sca.invalid"},
        {"/total_checks", "sca.total_checks"},
        {"/score", "sca.score"},
    };

    for (auto& [key, newKey] : integer_field_newKey)
    {
        int value;
        if (scanInfoKeyValues.find(key) != scanInfoKeyValues.end())
        {
            value = stoi(scanInfoKeyValues[key]);
        }
        std::string field = {json::formatJsonPath(newKey)};

        e->getEvent()->set(field, rapidjson::Value(value));
    }
}

// - Scan Info Handling - //

static bool HandleScanInfo(base::Event& e, types::TracerFn tr)
{
    std::string failureTrace = fmt::format("HandleScanInfo sca_decode Failure");

    int alert_data_fill = 0;
    if (!CheckScanInfoJSON(e))
    {
        tr(failureTrace);
        return false;
    }

    int result_event = 0;
    std::string hash_scan_info;
    int result_db = FindScanInfo(e, hash_scan_info);

    const auto& separated_hash = utils::string::split(hash_scan_info, ' ');

    if (separated_hash.size() < 2)
    {
        // "Retrieving sha256 hash for policy: '%s'"
        tr(failureTrace);
        return false;
    }
    int scan_id_old = stoi(separated_hash.at(1));
    std::string hash_sha256 = separated_hash.at(0); // Should I chek qtty of chars? (%64s)

    std::string hash = scanInfoKeyValues["/hash"];
    std::string first_scan;
    std::string force_alert;
    bool result = true;
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
            // "Error querying policy monitoring database for agent
            tr(failureTrace);
            result = false;
            break;
        case 0:
            // It exists, update
            result_event = SaveScanInfo(e, 1);
            if (result_event < 0)
            {
                // "Error updating scan policy monitoring database for agent
                tr(failureTrace);
                result = false;
            }
            else
            {
                /* Compare hash with previous hash */
                if (hash_sha256 == hash)
                {
                    if (first_scan.empty())
                    {
                        FillScanInfo(e);
                        alert_data_fill = 1;
                    }
                }

                if (!force_alert.empty() && !alert_data_fill)
                {
                    FillScanInfo(e);
                }
            }
            break;
        case 1:
            // It not exists, insert
            result_event = SaveScanInfo(e, 0);
            if (result_event < 0)
            {
                // "Error storing scan policy monitoring information for
                tr(failureTrace);
                result = false;
            }
            else
            {
                /* Compare hash with previous hash */
                if (hash_sha256 == hash)
                {
                    if (first_scan.empty())
                    {
                        FillScanInfo(e);
                        alert_data_fill = 1;
                    }
                    else
                    {
                        /* Request dump */
                        PushDumpRequest(e, 1);
                    }
                }

                if (!force_alert.empty() && !alert_data_fill)
                {
                    FillScanInfo(e);
                }
            }

            break;
        default: result = false; break;
    }

    std::string references_db;
    std::string description_db;
    std::string old_hash;
    result_db = FindPolicyInfo(e);

    switch (result_db)
    {
        case -1:
            // "Error querying policy monitoring database for agent
            tr(failureTrace);
            result = false;
            break;
        case 1:
            // It not exists, insert from event
            if (scanInfoKeyValues.find("/references") != scanInfoKeyValues.end())
            {
                // TODO: Double check value type
                references_db = scanInfoKeyValues["/references"];
            }

            if (scanInfoKeyValues.find("/description") != scanInfoKeyValues.end())
            {
                // TODO: Double check value type
                description_db = scanInfoKeyValues["/description"];
            }

            result_event = SavePolicyInfo(e, description_db, references_db);
            if (result_event < 0)
            {
                // "Error storing scan policy monitoring information for
                tr(failureTrace);
                result = false;
            }
            break;
        default:
            std::string old_hash;
            if (!FindPolicySHA256(e, old_hash))
            {
                std::string hash_file = scanInfoKeyValues["/hash_file"];
                if (hash_file == old_hash)
                {
                    int delete_status = DeletePolicy(e);
                    switch (delete_status)
                    {
                        case 0:
                            /* Delete checks */
                            DeletePolicyCheck(e);
                            PushDumpRequest(e, 1);
                            // "Policy '%s' information for agent '%s' is
                            // outdated.Requested latest scan results.",
                            break;
                        default:
                            // "Unable to purge DB content for policy
                            result = false;
                            break;
                    }
                }
            }
            break;
    }

    std::string wdb_response;
    result_db = FindCheckResults(e, wdb_response);

    switch (result_db)
    {
        case 0:
            /* Integrity check */
            if (wdb_response == hash)
            {
                // "Scan result integrity failed for policy '%s'. Hash from
                // DB:'%s', hash from summary: '%s'. Requesting DB dump."
                if (first_scan.empty())
                {
                    PushDumpRequest(e, 0);
                }
                else
                {
                    PushDumpRequest(e, 1);
                }
            }
            break;
        case 1:
            /* Empty DB */
            // "Check results DB empty for policy '%s'. Requesting DB dump."
            if (first_scan.empty())
            {
                PushDumpRequest(e, 0);
            }
            else
            {
                PushDumpRequest(e, 1);
            }
            break;
        default:
            // "Error querying policy monitoring database for agent
            tr(failureTrace);
            result = false;
            break;
    }

    //TODO: If it fails on any check it will resturn false
    return result;
}

/// Policies Functions ///

static int FindPoliciesIds(base::Event& e, std::string& policies_ids)
{
    // "Find policies IDs for agent id: %s"
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string FindPoliciesIdsQuery =
        std::string("agent ") + agent_id + " sca query_policies ";

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto FindPoliciesIdsTuple = wdb.tryQueryAndParseResult(FindPoliciesIdsQuery);
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
            policies_ids = FindPoliciesIdsResponse.substr(5); // removing found
            result_db = 0;
        }
    }
    return result_db;
}

// - Policies Handling - //

static bool HandlePoliciesInfo(base::Event& e, types::TracerFn tr)
{
    std::string failureTrace = fmt::format("HandlePoliciesInfo sca_decode Failure");

    const auto& doc = e->getEvent()->get(engineserver::EVENT_LOG);

    json::Value::ConstMemberIterator itr = doc.FindMember("/policies");
    if (itr == doc.MemberEnd())
    {
        // TODO: should I check? assert(policies.IsArray());
        tr(failureTrace);
        return false;
    }
    const auto& policies = itr->value;

    //"Checking policy JSON fields"
    std::string policies_ids;

    // "Retrieving policies from database."
    int result_db = FindPoliciesIds(e, policies_ids);
    bool result = true;
    switch (result_db)
    {
        case -1:
            // "Error querying policy monitoring database for agent"
            tr(failureTrace);
            result = false;
            break;

        default:
            /* For each policy id, look if we have scanned it */
            const auto& policies_list = utils::string::split(policies_ids, ',');

            if (policies_list.size() > 0)
            {

                for (auto& p_id : policies_ids)
                {
                    int exists = 0;
                    for (auto& policy : policies.GetArray())
                    {
                        std::string s_policy = policy.GetString();
                        if (!s_policy.empty())
                        {
                            // "Comparing policy
                            if (policy == p_id)
                            {
                                exists = 1;
                                break;
                            }
                        }
                    }

                    /* This policy is not being scanned anymore, delete it */
                    if (!exists)
                    {
                        // "Policy id doesn't exist: '%s'. Deleting it."
                        int result_delete = DeletePolicy(e);

                        switch (result_delete)
                        {
                            case 0:
                                /* Delete checks */
                                DeletePolicyCheck(e);
                                break;

                            default:
                                // "Unable to purge DB content for policy
                                tr(failureTrace);
                                result = false;
                                break;
                        }
                    }
                }
            }
            break;
    }
    return result;
}

/// Dump Functions ///

static bool CheckDumpJSON(base::Event& e,
                          std::string& elements_sent,
                          std::string& policy_id,
                          std::string& scan_id)
{
    try
    {
        // engineserver::EVENT_LOG
        const auto& doc = e->getEvent()->get("/event/original/message");
        json::Value::ConstMemberIterator itr = doc.FindMember("/elements_sent");
        if (itr != doc.MemberEnd())
        {
            elements_sent = itr->value.GetInt(); // Check value type
        }
        else
        {
            return false;
        }

        itr = doc.FindMember("/policy_id");
        if (itr != doc.MemberEnd())
        {
            policy_id = itr->value.GetString();
        }
        else
        {
            return false;
        }

        itr = doc.FindMember("/scan_id");
        if (itr != doc.MemberEnd())
        {
            scan_id = itr->value.GetInt();
        }
        else
        {
            return false;
        }
    }
    catch (const std::exception& e)
    {
        return false;
    }

    return true;
}

static int
DeletePolicyCheckDistinct(base::Event& e, std::string& policy_id, std::string& scan_id)
{
    // "Deleting check distinct policy id '%s', agent id '%s'", policy_id, lf->agent_id
    std::string agent_id = e->getEvent()->get("/agent/id").GetString();
    std::string DeletePolicyCheckDistinctQuery = std::string("agent ") + agent_id
                                                 + " sca delete_check_distinct "
                                                 + policy_id + "|" + scan_id;

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);
    auto DeletePolicyCheckDistinctTuple =
        wdb.tryQueryAndParseResult(DeletePolicyCheckDistinctQuery);
    auto DeletePolicyCheckDistinctStatus = std::get<0>(DeletePolicyCheckDistinctTuple);

    int result_db = -1;
    if (DeletePolicyCheckDistinctStatus == wazuhdb::QueryResultCodes::OK)
    {
        result_db = 0;
    }
    else if (DeletePolicyCheckDistinctStatus == wazuhdb::QueryResultCodes::ERROR)
    {
        result_db = 1;
    }

    return result_db;
}

// - Dump Handling - //

static bool HandleDumpEvent(base::Event& e, types::TracerFn tr)
{
    std::string failureTrace = fmt::format("HandleDumpEvent sca_decode Failure");

    std::string elements_sent;
    std::string policy_id;
    std::string scan_id;
    bool result = true;

    // "Checking dump event JSON fields"
    if (CheckDumpJSON(e, elements_sent, policy_id, scan_id))
    {

        int result_db = DeletePolicyCheckDistinct(e, policy_id, scan_id);

        switch (result_db)
        {
            case -1:
                //  "Error querying policy monitoring database for agent"
                tr(failureTrace);
                result = false;
                break;
            default: break;
        }

        /* Check the new sha256 */
        std::string wdb_response;
        ;

        result_db = FindCheckResults(e, wdb_response);
        if (!result_db)
        {
            std::string hash_scan_info;
            int result_db_hash = FindScanInfo(e, hash_scan_info);

            if (hash_scan_info.empty())
            { // TODO: check if it's ok "%s64"
                // "Retrieving sha256 hash while handling dump for policy"
                tr(failureTrace);
                result = false;
            }

            if (!result_db_hash)
            {
                /* Integrity check */
                if (wdb_response == hash_scan_info)
                { // TODO: double check
                    //"Scan result integrity failed for policy ''. Hash from DB: '%s'
                    // hash from summary: '%s'. Requesting DB dump."
                    PushDumpRequest(e, 0);
                }
            }
        }
    }
    else
    {
        result = false;
    }
    return result;
}

// - Helper - //

base::Lifter opBuilderSCAdecoder(const base::DocumentValue& def, types::TracerFn tr)
{
    const std::string decode_result_status {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("Invalid parameter type for sca_decode "
                                 "operator (str expected)");
    }

    // Parse parameter
    auto parametersArr {utils::string::split(def.MemberBegin()->value.GetString(), '/')};
    if (parametersArr.size() != 1)
    {
        throw std::runtime_error("Invalid number of parameters for sca_decode operator");
    }

    base::Document doc {def};
    std::string successTrace = fmt::format("{} sca_decode Success", doc.str());
    std::string failureTrace = fmt::format("{} sca_decode Failure", doc.str());

    // Return Lifter
    return [=, tr = std::move(tr)](base::Observable o) {
        // Append rxcpp operation
        return o.map([=, tr = std::move(tr)](base::Event e) {
            bool proccessResult = false;
            try
            {
                // Get Type value
                const std::string& type =
                    e->getEvent()->get("/event/original/message/type").GetString();
                if (type == "check")
                {
                    proccessResult = HandleCheckEvent(e, tr);
                }
                else if (type == "summary")
                {
                    proccessResult = HandleScanInfo(e, tr);
                }
                else if (type == "policies")
                {
                    proccessResult = HandlePoliciesInfo(e, tr);
                }
                else if (type == "dump_end")
                {
                    proccessResult = HandleDumpEvent(e, tr);
                }
                else
                {
                    throw std::invalid_argument("wrong type for SCA decoder");
                }
                proccessResult ? tr(successTrace) : tr(failureTrace);
            }
            catch (const std::invalid_argument& e)
            {
                // TODO: for now hanlde all the same, later on will fill the gaps
                tr(failureTrace + ": " + e.what());
            }
            catch (const std::exception& e)
            {
                tr(failureTrace + ": " + e.what());
            }
            catch (...)
            {
                tr(failureTrace);
            }

            try
            {
                e->getEvent()->set(decode_result_status, rapidjson::Value(proccessResult));
            }
            catch(const std::exception& e)
            {
                tr(failureTrace);
            }

            return e;
        });
    };
}

} // namespace builder::internals::builders
