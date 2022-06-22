/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <utils/socketInterface/unixDatagram.hpp>

#include "combinatorBuilderBroadcast.hpp"
#include "combinatorBuilderChain.hpp"
#include "opBuilderARWrite.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"
#include "opBuilderHelperMap.hpp"
#include "opBuilderMapValue.hpp"
#include "opBuilderWdbSync.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"

#include "socketAuxiliarFunctions.hpp"
#include "testUtils.hpp"

using namespace base;
using namespace builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

class opBuilderARWriteTestSuite : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        Registry::registerBuilder("helper.ar_write", opBuilderARWrite);
        // "map" operation
        Registry::registerBuilder("map.value", opBuilderMapValue);
        // "check" operations
        Registry::registerBuilder("check", stageBuilderCheck);
        Registry::registerBuilder("condition", opBuilderCondition);
        Registry::registerBuilder("middle.condition", middleBuilderCondition);
        Registry::registerBuilder("middle.helper.exists", opBuilderHelperExists);
        // combinators
        Registry::registerBuilder("combinator.chain", combinatorBuilderChain);
        Registry::registerBuilder("combinator.broadcast", combinatorBuilderBroadcast);
    }

    static void TearDownTestSuite() { return; }
};

TEST_F(opBuilderARWriteTestSuite, BuilderNoParameterError)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "ar_write.result": "+ar_write/"
                }
            }
        ]
    })"};

    ASSERT_THROW(opBuilderARWrite(doc.get("/normalize/0/map"), tr), std::runtime_error);
}

TEST_F(opBuilderARWriteTestSuite, Builder)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "ar_write.result": "+ar_write/test"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(opBuilderARWrite(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderARWriteTestSuite, NormalizeBuilder)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "ar_write.result": "+ar_write/test"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST_F(opBuilderARWriteTestSuite, Send)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "ar_write.result": "+ar_write/test\n"
                }
            }
        ]
    })"};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"DummyField": "DummyValue"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "test\n");

    // Check send command to the AR's queue result
    ASSERT_NO_THROW(
        ASSERT_STREQ(expected[0]->getEventValue("/ar_write/result").GetString(), "ok"));

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}

TEST_F(opBuilderARWriteTestSuite, SendFromReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "variable": "test\n",
                    "ar_write.result": "+ar_write/$variable"
                }
            }
        ]
    })"};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"DummyField": "DummyValue"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "test\n");

    // Check send command to the AR's queue result
    ASSERT_NO_THROW(
        ASSERT_STREQ(expected[0]->getEventValue("/ar_write/result").GetString(), "ok"));

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}

TEST_F(opBuilderARWriteTestSuite, SendEmptyReferenceError)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "ar_write.result": "+ar_write/$"
                }
            }
        ]
    })"};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"DummyField": "DummyValue"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);

    // Check send command to the AR's queue result

    string arWriteResult;
    ASSERT_NO_THROW(arWriteResult =
                        expected[0]->getEventValue("/ar_write/result").GetString());

    ASSERT_STREQ(arWriteResult.data(), AR_INVALID_REFERENCE_MSG);

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}

TEST_F(opBuilderARWriteTestSuite, SendWrongReferenceError)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "ar_write.result": "+ar_write/$dummy"
                }
            }
        ]
    })"};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"DummyField": "DummyValue"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);

    // Check send command to the AR's queue result

    string arWriteResult;
    ASSERT_NO_THROW(arWriteResult =
                        expected[0]->getEventValue("/ar_write/result").GetString());

    ASSERT_STREQ(arWriteResult.data(),
                 "Write AR operator exception: Error, field not found: /dummy");

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}

TEST_F(opBuilderARWriteTestSuite, SendFromReferenceWithConditionalMapping)
{
    Document doc {R"({
        "normalize":
        [
            {
                "check":
                [
                    {"query_result": "+exists"}
                ],
                "map":
                {
                    "ar_write.result": "+ar_write/$query_result"
                }
            }
        ]
    })"};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(R"({"query_result": "test\n"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "test\n");

    // Check send command to the AR's queue result
    ASSERT_NO_THROW(
        ASSERT_STREQ(expected[0]->getEventValue("/ar_write/result").GetString(), "ok"));

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}
