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

#include <logging/logging.hpp>
#include <wdb/wdb.hpp>

#include "opBuilderWdb.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace wazuhdb;
namespace bld = builder::internals::builders;
namespace unixStream = base::utils::socketInterface;

class opBuilderWdbQuery : public ::testing::Test
{

protected:
    virtual void SetUp()
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = spdlog::level::off;
        logConfig.filePath = logging::DEFAULT_TESTS_LOG_PATH;
        logging::loggingInit(logConfig);
    }

    virtual void TearDown() {}
};

// Build ok
TEST_F(opBuilderWdbQuery, BuildSimplest)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {"agent 007 syscheck integrity_clear ...."})};

    ASSERT_NO_THROW(bld::opBuilderWdbQuery(tuple));
}

// TODO: the / of the path inside the json should be escaped!
TEST_F(opBuilderWdbQuery, BuildsWithJson)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {
            "agent 007 syscheck integrity_clear {\"tail\": \"tail\", "
            "\"checksum\":\"checksum\", \"begin\": \"/a/path\", \"end\": \"/z/path\"}"})};

    ASSERT_NO_THROW(bld::opBuilderWdbQuery(tuple));
}

TEST_F(opBuilderWdbQuery, BuildsWithQueryRef)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};

    ASSERT_NO_THROW(bld::opBuilderWdbQuery(tuple));
}

TEST_F(opBuilderWdbQuery, checkWrongQttyParams)
{
    auto tuple {std::make_tuple(
        std::string {"/wdb/result"},
        std::string {"wdb_query"},
        std::vector<std::string> {"$wdb.query_parameter", "more params"})};

    ASSERT_THROW(bld::opBuilderWdbQuery(tuple), std::runtime_error);
}

TEST_F(opBuilderWdbQuery, checkNoParams)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {})};

    ASSERT_THROW(bld::opBuilderWdbQuery(tuple), std::runtime_error);
}

TEST_F(opBuilderWdbQuery, gettingEmptyReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};

    auto op {bld::opBuilderWdbQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": ""}
    })")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/wdb/result"));
}

TEST_F(opBuilderWdbQuery, gettingNonExistingReference)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};

    auto op {bld::opBuilderWdbQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"wdb": {
        "not_query_parameters_": "query"}
    })")};

    result::Result<Event> result1 {op(event1)};

    ASSERT_FALSE(result1);
}

TEST_F(opBuilderWdbQuery, completeFunctioningWithtDBresponseNotOk)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "NotOk");
        close(clientRemote);
    });

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    // TODO Should be null or inexistant??
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));

    t.join();
    close(serverSocketFD);
}

TEST_F(opBuilderWdbQuery, completeFunctioningWithtDBresponseWithPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
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

TEST_F(opBuilderWdbQuery, QueryResultCodeOkPayloadEmpty)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
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

TEST_F(opBuilderWdbQuery, QueryResultCodeOkNotPayload)
{
    auto tuple {std::make_tuple(std::string {"/wdb/result"},
                                std::string {"wdb_query"},
                                std::vector<std::string> {"$wdb.query_parameters"})};
    auto op {bld::opBuilderWdbQuery(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })")};

    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
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
