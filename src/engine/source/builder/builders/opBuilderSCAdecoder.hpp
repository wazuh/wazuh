/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_SCA_DECODER_H
#define _OP_BUILDER_SCA_DECODER_H

#include <any>
#include <memory>

#include <wdb/wdb.hpp>

#include "base/baseTypes.hpp"
#include "expression.hpp"

namespace builder::internals::builders
{

// /* Security configuration assessment remoted queue */

// TODO: remove when undoing set for testing
constexpr std::string_view STREAM_SOCK_PATH = "/tmp/testStream.socket";
/* Security configuration assessment remoted queue */
constexpr const char* CFGARQUEUE {"/tmp/cfgar.sock"}; //"queue/alerts/cfgarq"

namespace sca
{

namespace field
{

enum class Name
{
    A_BEGIN,                 ///< Not a field, only for iterate purposes
    CHECK_COMMAND = A_BEGIN, ///< checkEvent
    CHECK_COMPLIANCE,        ///< checkEvent
    CHECK_CONDITION,         ///< checkEvent
    CHECK_DESCRIPTION,       ///< checkEvent
    CHECK_DIRECTORY,         ///< checkEvent
    CHECK_FILE,              ///< checkEvent
    CHECK_ID,                ///< checkEvent
    CHECK_PREVIOUS_RESULT,   ///< checkEvent
    CHECK_PROCESS,           ///< checkEvent
    CHECK_RATIONALE,         ///< checkEvent
    CHECK_REASON,            ///< checkEvent
    CHECK_REFERENCES,        ///< checkEvent
    CHECK_REGISTRY,          ///< checkEvent
    CHECK_REMEDIATION,       ///< checkEvent
    CHECK_RESULT,            ///< checkEvent
    CHECK_RULES,             ///< checkEvent
    CHECK_STATUS,            ///< checkEvent
    CHECK_TITLE,             ///< checkEvent
    CHECK,                   ///< checkEvent
    DESCRIPTION,             ///< scaninfo
    END_TIME,                ///< scaninfo
    ELEMENTS_SENT,           ///< DumpEvent
    FAILED,                  ///< scaninfo
    FILE,                    ///< scaninfo
    FIRST_SCAN,              ///< scaninfo
    FORCE_ALERT,             ///< scaninfo
    HASH_FILE,               ///< scaninfo
    HASH,                    ///< scaninfo
    ID,                      ///< checkEvent
    INVALID,                 ///< scaninfo
    NAME,                    ///< scaninfo
    PASSED,                  ///< scaninfo
    POLICY_ID,               ///< scaninfo, checkEvent
    POLICY,                  ///< checkEvent
    POLICIES,                ///< Policies
    REFERENCES,              ///< scaninfo
    SCAN_ID,                 ///< scaninfo
    SCORE,                   ///< scaninfo
    START_TIME,              ///< scaninfo
    TOTAL_CHECKS,            ///< scaninfo
    TYPE,                    ///< checkEvent
    A_END                   ///< Not a field, only for iterate purposes
};
} // namespace field

/**
 * @brief Value for a SCA Find Query Operation
 */
enum class SearchResult
{
    ERROR = -1, ///< Error on wdb or unexpected result
    NOT_FOUND,  ///< Not found
    FOUND       ///< Found
};

/**
 * @brief Store all decoder information for processing the SCA Event
 */
struct InfoEventDecode
{
    // TODO Changes names
    base::Event& event;              ///< Event to be processed
    const std::string& agentID;      ///< Agent ID of the agent that generated the event
    const std::string& sourceSCApath; ///< Path to the SCA Event in the incoming event
    std::shared_ptr<wazuhdb::WazuhDB> wdb; ///< WazuhDB instance
    const std::unordered_map<sca::field::Name, std::string>& fieldSource;
    const std::unordered_map<sca::field::Name, std::string>& fieldDest;

    std::optional<int> getIntFromSrc(sca::field::Name field) const
    {
        return event->getInt(fieldSource.at(field));
    };
    std::optional<std::string> getStrFromSrc(sca::field::Name field) const
    {
        return event->getString(fieldSource.at(field));
    };
};
/****************************************************************************************
                                 Check Event
*****************************************************************************************/

/**
 * @brief Check if the event is a valid check event type
 *
 * @param event The event to check
 * @param sourceSCApath The path to sca incomming event (in event)
 * @return true If the event is a valid check event type
 * @return false If the event is not a valid check event type
 */
bool isValidCheckEvent(const InfoEventDecode& infoDec);

/**
 * @brief Fill the /sca object with the check event info
 *
 * @param event The event to get the info from
 * @param previousResult The previous result of scan
 * @param sourceSCApath The path to sca incomming event (in event)
 */
void fillCheckEvent(const InfoEventDecode& infoDec, const std::string& previousResult);

/****************************************************************************************
                                  Scan Event
*****************************************************************************************/

bool CheckScanInfoJSON(base::Event& event, const std::string& sourceSCApath);

std::tuple<SearchResult, std::string> findScanInfo(const std::string& agentId,
                                                   const std::string& policyId,
                                                   std::shared_ptr<wazuhdb::WazuhDB> wdb);

int SaveScanInfo(base::Event& event, const std::string& agent_id, int update);

SearchResult findPolicyInfo(base::Event& event,
                            const std::string& agent_id,
                            const std::string& sourceSCApath,
                            std::shared_ptr<wazuhdb::WazuhDB> wdb);

bool pushDumpRequest(const std::string& agentId,
                     const std::string& policyId,
                     int firstScan);

bool SavePolicyInfo(base::Event& event,
                    const std::string& agent_id,
                    const std::string& sourceSCApath,
                    std::shared_ptr<wazuhdb::WazuhDB> wdb);

int FindPolicySHA256(const std::string& agent_id, std::string& old_hash);

int deletePolicy(const std::string& agent_id,
                 const std::string& policyId,
                 std::shared_ptr<wazuhdb::WazuhDB> wdb);

int deletePolicyCheck(const std::string& agent_id,
                      const std::string& policyId,
                      std::shared_ptr<wazuhdb::WazuhDB> wdb);

std::tuple<SearchResult, std::string> findCheckResults(const std::string& agentId,
                                              const std::string& policyId,
                                              std::shared_ptr<wazuhdb::WazuhDB> wdb);

std::tuple<SearchResult, std::string> findPoliciesIds(const std::string& agentId,
                                             std::shared_ptr<wazuhdb::WazuhDB> wdb);

std::tuple<std::optional<std::string>, std::string, std::string>
checkDumpJSON(const base::Event& event, const std::string& sourceSCApath);

bool deletePolicyCheckDistinct(const std::string& agentId,
                               const std::string& policyId,
                               const std::string& scanId,
                               std::shared_ptr<wazuhdb::WazuhDB> wdb);

std::optional<std::string> handleCheckEvent(const InfoEventDecode& infoDec);

std::optional<std::string> handleScanInfo(const InfoEventDecode& infoDec);

std::optional<std::string> handlePoliciesInfo(base::Event& event,
                                              const std::string& agentId,
                                              const std::string& sourceSCApath,
                                              std::shared_ptr<wazuhdb::WazuhDB> wdb);

std::optional<std::string> handleDumpEvent(const InfoEventDecode& infoDec);

} // namespace sca

/**
 * @brief Executes query on WDB returning status ok or not ok.
 * @param def Json Doc
 * @param tr Tracer
 * @return base::Lifter true when executes without any problem, false otherwise.
 */
base::Expression opBuilderSCAdecoder(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_SCA_DECODER_H
