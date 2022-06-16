/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <vector>
#include <thread>

#include <gtest/gtest.h>
#include <utils/socketInterface/unixSecureStream.hpp>
#include <utils/socketInterface/unixDatagram.hpp>

#include "testUtils.hpp"
#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"
#include "opBuilderHelperMap.hpp"
#include "opBuilderMapValue.hpp"
#include "opBuilderWdbSync.hpp"
#include "socketAuxiliarFunctions.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "wdb/wdb.hpp"


namespace
{

using namespace base;
using namespace wazuhdb;
namespace bld = builder::internals::builders;
namespace unixStream = base::utils::socketInterface;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

class opBuilderWdbSyncUpdate : public ::testing::Test  //delete
{

protected:
  // Per-test-suite set-up.
  // Called before the first test in this test suite.
  static void SetUpTestSuite() {

    Registry::registerBuilder("helper.s_concat", builder::internals::builders::opBuilderHelperStringConcat);
    Registry::registerBuilder("check", builder::internals::builders::stageBuilderCheck);
    Registry::registerBuilder("condition", builder::internals::builders::opBuilderCondition);
    Registry::registerBuilder("middle.condition", builder::internals::builders::middleBuilderCondition);
    Registry::registerBuilder("middle.helper.exists", builder::internals::builders::opBuilderHelperExists);
    Registry::registerBuilder("combinator.chain", builder::internals::builders::combinatorBuilderChain);
    Registry::registerBuilder("map.value", builder::internals::builders::opBuilderMapValue);
    Registry::registerBuilder("helper.wdb_update", builders::opBuilderWdbSyncUpdate);
  }

  // Per-test-suite tear-down.
  // Called after the last test in this test suite.
  static void TearDownTestSuite() {
      return;
  }
};

// Build ok
TEST_F(opBuilderWdbSyncUpdate, BuildSimplest)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "wdb.result": "+wdb_update/agent 007 syscheck integrity_clear algo"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::opBuilderWdbSyncUpdate(doc.get("/normalize/0/map"), tr));
}

// TODO: the / of the path inside the json should be escaped!
TEST_F(opBuilderWdbSyncUpdate, BuildsWithJson)
{
    GTEST_SKIP();
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "wdb.result": "+wdb_update/agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"\/a\/path\", \"end\": \"\/z\/path\"}"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::opBuilderWdbSyncUpdate(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderWdbSyncUpdate, BuildsWithQueryRef)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "wdb.query_parameters": "agent 007 syscheck integrity_clear {\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"
                }
            },
            {
                "check":
                [
                    {"wdb.query_parameters": "+exists"}
                ],
                "map":
                {
                    "wdb.result": "+wdb_update/$wdb.query_parameters"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST_F(opBuilderWdbSyncUpdate, BuildsWithQueryRefByConcat)
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
                    "wdb.result": "+wdb_update/$wdb.query_parameters"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST_F(opBuilderWdbSyncUpdate, checkWrongQttyParams)
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
                    "wdbresult": "+wdb_update/$wdb.query_parameters/Another"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::stageBuilderNormalize(doc.get("/normalize"), tr),std::runtime_error);
}

TEST_F(opBuilderWdbSyncUpdate, gettingEmptyReference)
{
     Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "wdb.query_parameters": ""
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

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"FieldB": "something"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_THROW(expected[0]->getEvent()->get("/wdbresult"), std::invalid_argument);
}

TEST_F(opBuilderWdbSyncUpdate, gettingNonExistingReference)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "wdb.query_AnotherName": "+s_concat/agent /007 /syscheck /integrity_clear /{\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"path\", \"end\": \"path\"}"
                }
            },
            {
                "check":
                [
                    {"wdb.query_AnotherName": "+exists"}
                ],
                "map":
                {
                    "wdbresult": "+wdb_update/$wdb.query_parameters"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"FieldB": "something"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_THROW(expected[0]->getEvent()->get("/wdbresult"), std::invalid_argument);
}

TEST_F(opBuilderWdbSyncUpdate, completeFunctioningWithBadResponse)
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

    std::thread t(
        [&]()
        {
            const int clientRemote = testAcceptConnection(serverSocketFD);
            testRecvString(clientRemote);
            testSendMsg(clientRemote, "NotOk");
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

    std::thread t(
        [&]()
        {
            const int clientRemote = testAcceptConnection(serverSocketFD);
            testRecvString(clientRemote);
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

    std::thread t(
        [&]()
        {
            const int clientRemote = testAcceptConnection(serverSocketFD);
            testRecvString(clientRemote);
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

    std::thread t(
        [&]()
        {
            const int clientRemote = testAcceptConnection(serverSocketFD);
            testRecvString(clientRemote);
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

} // namespace
