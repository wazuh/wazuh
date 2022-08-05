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

static std::unordered_map<std::string, std::string> scanInfoKeyValues {{"/policy_id", ""},
                                                                       {"/hash", ""},
                                                                       {"/hash_file", ""},
                                                                       {"/file", ""},
                                                                       {"/policy", ""}};

bool CheckEventJSON(base::Event& event, const std::string& scaEventPath);

void FillCheckEventInfo(base::Event& event,
                        const std::string& response,
                        const std::string& scaEventPath);

bool CheckScanInfoJSON(base::Event& event, const std::string& scaEventPath);

int FindScanInfo(base::Event& event,
                 const std::string& agentId,
                 const std::string& scaEventPath,
                 std::string& hashScanInfo);

int SaveScanInfo(base::Event& event, const std::string& agent_id, int update);

int FindPolicyInfo(base::Event& event, const std::string& agent_id);

bool PushDumpRequest(base::Event& event, const std::string& agentId, int firstScan);

int SavePolicyInfo(const std::string& agent_id,
                   std::string& description_db,
                   std::string& references_db);

int FindPolicySHA256(const std::string& agent_id, std::string& old_hash);

int DeletePolicy(const std::string& agent_id);

int DeletePolicyCheck(const std::string& agent_id);

int FindCheckResults(const std::string& agentId, std::string& wdbResponse);

int FindPoliciesIds(const std::string& agentId, std::string& policiesIds);

std::optional<std::string> CheckDumpJSON(base::Event event,
                                         std::string& elementsSent,
                                         std::string& policyId,
                                         std::string& scanId,
                                         const std::string& scaEventPath);

int DeletePolicyCheckDistinct(const std::string& agentId,
                              const std::string& policyId,
                              const std::string& scanId);

std::optional<std::string> HandleCheckEvent(base::Event& event,
                                            const std::string& agent_id,
                                            const std::string& scaEventPath);

std::optional<std::string> HandleScanInfo(base::Event& event,
                                          const std::string& agent_id,
                                          const std::string& scaEventPath);

std::optional<std::string> HandlePoliciesInfo(base::Event& event,
                                              const std::string& agentId,
                                              const std::string& scaEventPath);

std::optional<std::string> HandleDumpEvent(base::Event& event,
                                           const std::string& agentId,
                                           const std::string& scaEventPath);
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
