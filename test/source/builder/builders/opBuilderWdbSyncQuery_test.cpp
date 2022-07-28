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

#include "opBuilderWdbSync.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace wazuhdb;
namespace bld = builder::internals::builders;
namespace unixStream = base::utils::socketInterface;

// Build ok
TEST(opBuilderWdbSyncQuery, BuildSimplest)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {"agent 007 syscheck integrity_clear ...."})};

    ASSERT_NO_THROW(bld::opBuilderWdbSyncQuery(tuple));
}

// TODO: the / of the path inside the json should be escaped!
TEST(opBuilderWdbSyncQuery, BuildsWithJson)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {
            "agent 007 syscheck integrity_clear {\"tail\": \"tail\", "
            "\"checksum\":\"checksum\", \"begin\": \"/a/path\", \"end\": \"/z/path\"}"})};

    ASSERT_NO_THROW(bld::opBuilderWdbSyncQuery(tuple));
}

TEST(opBuilderWdbSyncQuery, BuildsWithQueryRef)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};

    ASSERT_NO_THROW(bld::opBuilderWdbSyncQuery(tuple));
}

TEST(opBuilderWdbSyncQuery, checkWrongQttyParams)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {"$wdb.query_parameter", "more params"})};

    ASSERT_THROW(bld::opBuilderWdbSyncQuery(tuple), std::runtime_error);
}

TEST(opBuilderWdbSyncQuery, checkNoParams)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {})};

    ASSERT_THROW(bld::opBuilderWdbSyncQuery(tuple), std::runtime_error);
}

TEST(opBuilderWdbSyncQuery, gettingEmptyReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};

    auto op {bld::opBuilderWdbSyncQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": ""}
    })")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/wdb/result"));
}

TEST(opBuilderWdbSyncQuery, gettingNonExistingReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};

    auto op {bld::opBuilderWdbSyncQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "not_query_parameters_": "query"}
    })")};

    result::Result<Event> result1 {op(event1)};

    ASSERT_FALSE(result1);
}

TEST(opBuilderWdbSyncQuery, completeFunctioningWithtDBresponseNotOk)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbSyncQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "NotOk");
        close(clientRemote);
    });

    // Disable error logs for this test
    const auto logLevel {fmtlog::getLogLevel()};
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));

    result::Result<Event> result {op(event)};

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level

    ASSERT_FALSE(result);
    // TODO Should be null or inexistant??
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderWdbSyncQuery, completeFunctioningWithtDBresponseWithPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbSyncQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok payload");
        close(clientRemote);
    });

    result::Result<Event> result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_TRUE(result.payload().get()->isString("/wdb/result"));
    ASSERT_EQ(result.payload().get()->getString("/wdb/result"), "payload");

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderWdbSyncQuery, QueryResultCodeOkPayloadEmpty)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbSyncQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok ");
        close(clientRemote);
    });

    result::Result<Event> result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_TRUE(result.payload().get()->isString("/wdb/result"));
    ASSERT_EQ(result.payload().get()->getString("/wdb/result"), "");

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderWdbSyncQuery, QueryResultCodeOkNotPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbSyncQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);
    });

    result::Result<Event> result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_TRUE(result.payload().get()->isString("/wdb/result"));
    ASSERT_EQ(result.payload().get()->getString("/wdb/result"), "");

    t.join();
    close(serverSocketFD);
}
