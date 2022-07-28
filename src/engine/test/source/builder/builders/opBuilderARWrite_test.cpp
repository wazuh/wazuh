/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include <logging/logging.hpp>

#include "opBuilderARWrite.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderARWriteTestSuite, Builder)
{
    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {"query params"})};

    ASSERT_NO_THROW(bld::opBuilderARWrite(tuple));
}

TEST(opBuilderARWriteTestSuite, BuilderNoParameterError)
{
    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {})};

    ASSERT_THROW(bld::opBuilderARWrite(tuple), std::runtime_error);
}

TEST(opBuilderARWriteTestSuite, Send)
{
    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {"test\n123"})};
    auto op {bld::opBuilderARWrite(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(bld::AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"agent_id": "007"})")};
    auto result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool("/ar_write/result"));
    ASSERT_TRUE(result.payload()->getBool("/ar_write/result"));

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "test\n123");

    close(serverSocketFD);
    unlink(bld::AR_QUEUE_PATH);
}

TEST(opBuilderARWriteTestSuite, SendFromReference)
{

    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {"$wdb.query_params"})};
    auto op {bld::opBuilderARWrite(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(bld::AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {
        std::make_shared<json::Json>(R"({"wdb": {"query_params": "reference_test"}})")};
    auto result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool("/ar_write/result"));
    ASSERT_TRUE(result.payload()->getBool("/ar_write/result"));

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "reference_test");

    close(serverSocketFD);
    unlink(bld::AR_QUEUE_PATH);
}

TEST(opBuilderARWriteTestSuite, SendEmptyReferencedValueError)
{
    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {"$wdb.query_params"})};
    auto op {bld::opBuilderARWrite(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {"query_params": ""}})")};
    auto result {op(event)};
    // TODO: Should be true?
    ASSERT_FALSE(result);
    // ASSERT_TRUE(result.payload()->isBool("/ar_write/result"));
    // ASSERT_FALSE(result.payload()->getBool("/ar_write/result"));
}

TEST(opBuilderARWriteTestSuite, SendEmptyReferenceError)
{
    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {"$wdb.query_params"})};
    auto op {bld::opBuilderARWrite(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"wdb": {"NO_query_params": "123"}})")};
    auto result {op(event)};
    // TODO: Should be true?
    ASSERT_FALSE(result);
    // ASSERT_TRUE(result.payload()->isBool("/ar_write/result"));
    // ASSERT_FALSE(result.payload()->getBool("/ar_write/result"));
}

TEST(opBuilderARWriteTestSuite, SendWrongReferenceError)
{
    auto tuple {std::make_tuple(std::string {"/ar_write/result"},
                                std::string {"ar_write"},
                                std::vector<std::string> {"$wdb.query_params"})};
    auto op {bld::opBuilderARWrite(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    ASSERT_FALSE(op(std::make_shared<json::Json>(R"({"wdb": {"query_params": 123}})")));
    ASSERT_FALSE(
        op(std::make_shared<json::Json>(R"({"wdb": {"query_params": ["123"]}})")));
    ASSERT_FALSE(op(std::make_shared<json::Json>(R"({"wdb": {"query_params": null}})")));
    ASSERT_FALSE(op(std::make_shared<json::Json>(R"({"wdb": {"query_params": false}})")));
}
