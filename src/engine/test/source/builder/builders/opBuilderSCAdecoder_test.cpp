/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include <logging/logging.hpp>
#include <wdb/wdb.hpp>

#include "opBuilderSCAdecoder.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace wazuhdb;
using namespace builder::internals::builders;

const std::string targetField {"/wdb/result"};
const std::string helperFunctionName {"sca_decoder"};
const std::vector<std::string> commonArguments {"$event.original", "$agent.id"};

TEST(opBuilderSCAdecoder, BuildSimplest)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    ASSERT_NO_THROW(opBuilderSCAdecoder(tuple));
}

TEST(opBuilderSCAdecoder, checkWrongQttyParams)
{
    const std::vector<std::string> arguments {"$event.original"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderSCAdecoder(tuple), std::runtime_error);
}

TEST(opBuilderSCAdecoder, checkNoParams)
{
    const std::vector<std::string> arguments {};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderSCAdecoder(tuple), std::runtime_error);
}

TEST(opBuilderSCAdecoder, gettingEmptyReference)
{
    GTEST_SKIP();

    const std::vector<std::string> arguments {"$_event_json", "$agent.id"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(R"({"_event_json": ""})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));
}

TEST(opBuilderSCAdecoder, gettingNonExistingReference)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(R"({"$_not_event_json": "event"})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, unexpectedType)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "unexpected_type"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

/* ************************************************************************************ */
//  Type: "check"
/* ************************************************************************************ */

// Missing event parameters checks

TEST(opBuilderSCAdecoder, checkTypeFieldOnly)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "check"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoPolicyField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoPolicyIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoCheckField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoCheckIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoCheckTitleField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeNoCheckResultNorStatusField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, checkTypeFindEventcheckUnexpectedAnswer)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, FindEventcheckOkFoundWithoutComplianceNorRules)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok found what_does_go_in_here"); // XXX
        close(clientRemoteFD);

        // SaveEventcheck update (exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca update 911|Some Result|||69");
        testSendMsg(clientRemoteFD, "This answer is ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(opBuilderSCAdecoder, FindEventcheckOkNotFoundWithoutComplianceNorRules)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // SaveEventcheck update (exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        // FIXME
        // std::string insertQuery{std::string {"agent 007 sca insert "} +
        // event->prettyStr().replace("\n", "").replace(" ", "")};
        // ASSERT_STREQ(clientMessage.data(), insertQuery.data());
        testSendMsg(clientRemoteFD, "This answer is ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

// TODO: add tests with rules, compliance and both (SaveCompliance() and SaveRules())

/* ************************************************************************************ */
//  Type: "summary"
/* ************************************************************************************ */

TEST(opBuilderSCAdecoder, summaryTypeFieldOnly)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoPolicyIdField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoScanIdField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoStartTimeField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoEndTimeField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoPassedField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoFailedField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoInvalidField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "name": "Some name",
                    "file": "Some file",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoTotalChecksField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoScoreField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoHashField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoHashFileField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "file": "Some file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoFileField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "name": "Some name",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeNoNameField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "file": "Some file",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, summaryTypeFindScanInfoUnexpectedAnswer)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "name": "Some name",
                    "file": "Some file",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder,
     summaryTypeFindScanInfoFindPolicyInfoFindCheckResultsUnexpectedAnswers)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "name": "Some name",
                    "file": "Some file",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(opBuilderSCAdecoder,
     summaryTypeFindScanInfoOkFoundFindPolicyInfoUAFindCheckResultsUA)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "name": "Some name",
                    "file": "Some file",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_sha256 some_scan_id_old");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca update_scan_info_start "
                     "some_policy_id|19920710|20220808|404|314|42|8|420|4|some_hash");
        testSendMsg(clientRemoteFD, "This answer is ignored.");
        close(clientRemoteFD);

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(opBuilderSCAdecoder,
     summaryTypeFindScanInfoOkNotFoundFindPolicyInfoUAFindCheckResultsUA)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "Some hash_file",
                    "name": "Some name",
                    "file": "Some file",
                    "first_scan": "Some first_scan",
                    "force_alert": "Some force_alert"
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_scan_info "
                     "19920710|20220808|404|some_policy_id|314|42|8|420|4|some_hash");
        testSendMsg(clientRemoteFD, "This answer is ignored.");
        close(clientRemoteFD);

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

/* ************************************************************************************ */
//  Type: "policies"
/* ************************************************************************************ */

TEST(opBuilderSCAdecoder, policiesTypeFieldOnly)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "policies"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

/* ************************************************************************************ */
//  Type: "dump_end"
/* ************************************************************************************ */

TEST(opBuilderSCAdecoder, dumpendTypeFieldOnly)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, dumpendTypeNoElementsSentField)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "policy_id": "some_policy_id",
                    "scan_id": 404
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, dumpendTypeNoPolicyIdField)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": "Some elements_sent",
                    "scan_id": 404
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, dumpendTypeNoScanIdField)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": "Some elements_sent",
                    "policy_id": "some_policy_id"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, handleDumpFailingCheckResultFinding)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type":"dump_end",
                    "elements_sent":2,
                    "policy_id":"cis_centos8_linux",
                    "scan_id":4602802
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Check Distinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "err payload");
        close(clientRemoteFD);

        // Check Result
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, handleDumpHashMissmatch)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": 2,
                    "policy_id": "cis_centos8_linux",
                    "scan_id": 4602802
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Check Distinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload");
        close(clientRemoteFD);

        // Check Result
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found RandomHash");
        close(clientRemoteFD);

        // Scan Info
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found NotRandomHash");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    // TODO: it returns "false" but it should be "true". Is the condition
    // opBuilderSCAdecoder.cpp::1288 right?
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleDumpHashEmpty)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": 2,
                    "policy_id": "cis_centos8_linux",
                    "scan_id": 4602802
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Check Distinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload");
        close(clientRemoteFD);

        // Check Result
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_GT(clientRemoteFD, 0);
        testSendMsg(clientRemoteFD, "ok found RandomHash");
        close(clientRemoteFD);

        // Scan Info
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_GT(clientRemoteFD, 0);
        testSendMsg(clientRemoteFD, "ok found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_FALSE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, correctHashDump)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": 2,
                    "policy_id": "cis_centos8_linux",
                    "scan_id": 4602802
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Check Distinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload");
        close(clientRemoteFD);

        // Check Result
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found hash");
        close(clientRemoteFD);

        // Scan Info
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found hash");
        close(clientRemoteFD);
    });

    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_STREQ(testRecvString(clientDgramFD, SOCK_DGRAM).c_str(),
                 "007:sca-dump:cis_centos8_linux:0");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleCheckResultNotFoundEvent)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 1858775963,
                    "policy": "CIS Benchmark for CentOS Linux 8",
                    "policy_id": "cis_centos8_linux",
                    "check":
                    {
                        "id": 6529,
                        "title": "Ensure bootloader password is set",
                        "description": "Setting the boot loader password .",
                        "rationale": "Requiring a boot password upon execution",
                        "compliance":
                        {
                            "cis": "1.5.2",
                            "tsc": "CC5.2"
                        },
                        "rules": [ "f:/boot/grub2/user.cfg ->r:^GRUB2_PASSWORD\\s*=\\.+" ],
                        "condition": "all",
                        "file": "/boot/grub2/user.cfg",
                        "status": "Not applicable",
                        "reason": "Could not open file '/boot/grub2/user.cfg'"
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Find event
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // Save event
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // Save compliance
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload1");
        close(clientRemoteFD);

        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload2");
        close(clientRemoteFD);

        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload3");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleEventInfo)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 1858775963,
                    "name": "CIS Benchmark for CentOS Linux 8",
                    "policy_id": "cis_centos8_linux",
                    "file": "cis_centos8_linux.yml",
                    "description": "This document provides prescriptive guidance",
                    "references": "https://www.cisecurity.org/cis-benchmarks/",
                    "passed": 89,
                    "failed": 95,
                    "invalid": 2,
                    "total_checks": 186,
                    "score": 48.369564056396484,
                    "start_time": 1654518796,
                    "end_time": 1654518800,
                    "hash": "eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4",
                    "hash_file": "2dd71c1696661dba6f1c6a409dc9e4a303028ba9d20c0e13b962ffe435490988",
                    "force_alert": "1"
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(
            clientRemoteFD,
            "ok found eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4 "
            "eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d0");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found");
        close(clientRemoteFD);

        // FindPolicySHA
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(
            clientRemoteFD,
            "ok found 2dd71c1696661dba6f1c6a409dc9e4a303028ba9d20c0e13b962ffe435490988");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckRes
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(
            clientRemoteFD,
            "ok found eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4");
        close(clientRemoteFD);
    });

    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleCheckResult)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "message":
                    {
                        "type": "check",
                        "id": 634609468,
                        "policy": "CIS Benchmark for CentOS Linux 8",
                        "policy_id": "cis_centos8_linux",
                        "check":
                        {
                            "id": 6663,
                            "title": "Ensure password reuse is limited",
                            "description": "The /etc/security/opasswd file stores",
                            "compliance":
                            {
                                "cis": "5.4.3",
                                "cis_csc": "16",
                                "pci_dss": "8.2.5",
                                "tsc": "CC6.1"
                            },
                            "rules": [ "f:/etc/pam.d/system-auth -> r:^\\s*password\\.+requisite\\.+pam_pwquality\\.so\\.+ && n:remember=(\\d+) compare >= 5","f:/etc/pam.d/system-auth -> r:^\\s*password\\.+sufficient\\.+pam_unix\\.so\\.+ && n:remember=(\\d+) compare >= 5" ],
                            "condition": "all",
                            "file": "/etc/pam.d/system-auth",
                            "result": "failed"
                        }
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEvent
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found");
        close(clientRemoteFD);

        // SaveEvent
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found_failed");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handlePolicies)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "a", "b", "c", "cis_centos8_linux" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD,
                    "ok found cis_centos8,cis_centos7_linux,cis_centos8_linux");
        close(clientRemoteFD);

        // Delete_0
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeleteCheck_0
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // Delete_1
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeleteCheck_1
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}
