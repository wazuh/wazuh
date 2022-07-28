/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <vector>
#include <thread>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>
#include <wdb/wdb.hpp>

#include "opBuilderWdbSync.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace wazuhdb;
namespace bld = builder::internals::builders;
namespace unixStream = base::utils::socketInterface;

// Build ok
TEST(opBuilderWdbSyncUpdate, Build)
{

    auto tuple = std::make_tuple(
        std::string {"/sourceField"},
        std::string {"wdb_update"},
        std::vector<std::string> {"agent 007 syscheck integrity_clear ...."});

    ASSERT_NO_THROW(bld::opBuilderWdbSyncUpdate(tuple));
}

// TODO: the "/" of the path inside the json should be escaped.
TEST(opBuilderWdbSyncUpdate, BuildsWithJson)
{
    // GTEST_SKIP();

    auto tuple = std::make_tuple(
        std::string {"/sourceField"},
        std::string {"wdb_update"},
        std::vector<std::string> {
            "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\":\"checksum\", \"begin\": \"/a/path\", \"end\": \"/z/path\"}"});

    ASSERT_NO_THROW(bld::opBuilderWdbSyncUpdate(tuple));
}

TEST(opBuilderWdbSyncUpdate, BuildsWithQueryRef)
{

    auto tuple = std::make_tuple(std::string {"/wdb/result"},
                                 std::string {"wdb_update"},
                                 std::vector<std::string> {"$wdb.query_parameters"});

    ASSERT_NO_THROW(bld::opBuilderWdbSyncUpdate(tuple));
}

TEST(opBuilderWdbSyncUpdate, checkWrongQttyParams)
{

    auto tuple =
        std::make_tuple(std::string {"/wdb/result"},
                        std::string {"wdb_update"},
                        std::vector<std::string> {"$wdb.query_parameters", "param2"});

    ASSERT_THROW(bld::opBuilderWdbSyncUpdate(tuple), std::runtime_error);
}

TEST(opBuilderWdbSyncUpdate, gettingEmptyReference)
{
    auto tuple = std::make_tuple(std::string {"/wdb/result"},
                                 std::string {"wdb_update"},
                                 std::vector<std::string> {"$wdb.query_parameters"});

    auto op = bld::opBuilderWdbSyncUpdate(tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event1 = std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": ""}
    })");

    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);

}

TEST(opBuilderWdbSyncUpdate, gettingNonExistingReference)
{
    auto tuple = std::make_tuple(std::string {"/wdb/result"},
                                 std::string {"wdb_update"},
                                 std::vector<std::string> {"$wdb.query_parameters"});

    auto op = bld::opBuilderWdbSyncUpdate(tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event1 = std::make_shared<json::Json>(R"({"wdb": {
        "not_query_parameters": "something"}
    })");

    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);
}

TEST(opBuilderWdbSyncUpdate, completeFunctioningWithBadResponse)
{

    auto tuple = std::make_tuple(std::string {"/wdb/result"},
                                 std::string {"wdb_update"},
                                 std::vector<std::string> {"$wdb.query_parameters"});

    auto op = bld::opBuilderWdbSyncUpdate(tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event1 = std::make_shared<json::Json>(R"({"wdb": {
        "query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"}
    })");

    // Create the endpoint for test

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "NotOk");
        close(clientRemote);
    });

    // Test
    result::Result<Event> result1 = op(event1);
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload()->exists("/wdb/result"));
    auto a123 = result1.payload()->isNull("/wdb/result");
    auto res = result1.payload()->getString("/wdb/result").value();

    t.join();
    close(serverSocketFD);

}

/*
TEST_F(opBuilderWdbSyncUpdate, completeFunctioningWithtDB)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "wdb.query_parameters": "+s_concat/agent /007 /syscheck /integrity_clear /{\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"
                }
            },
            {
                "check":
                [
                    {"wdb.query_parameters": "+exists"}
                ],
                "map":
                {
                    "wdbresult": "+wdb_update/$wdb.query_parameters"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok payload");
        close(clientRemote);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"FieldB": "something"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/wdbresult").GetBool());
}

TEST_F(opBuilderWdbSyncUpdate, QueryResultCodeNotOkWithPayload)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "wdb.query_parameters": "+s_concat/agent /007 /syscheck /integrity_clear /{\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"
                }
            },
            {
                "check":
                [
                    {"wdb.query_parameters": "+exists"}
                ],
                "map":
                {
                    "wdbresult": "+wdb_update/$wdb.query_parameters"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "anythingElse WithPayload ");
        close(clientRemote);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"FieldB": "something"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_FALSE(expected[0]->getEvent()->get("/wdbresult").GetBool());
}


TEST_F(opBuilderWdbSyncUpdate, QueryResultCodeOkPayloadEmpty)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "wdb.query_parameters": "+s_concat/agent /007 /syscheck /integrity_clear /{\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"
                }
            },
            {
                "check":
                [
                    {"wdb.query_parameters": "+exists"}
                ],
                "map":
                {
                    "wdbresult": "+wdb_update/$wdb.query_parameters"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok ");
        close(clientRemote);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"FieldB": "something"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/wdbresult").GetBool());
}

*/
