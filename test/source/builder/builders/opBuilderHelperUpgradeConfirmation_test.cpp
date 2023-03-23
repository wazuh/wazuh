/* Copyright (C) 2015-2023, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include "opBuilderHelperUpgradeConfirmation.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace builder::internals::builders;

const std::string targetField {"/result"};
const std::string arSendHFName {"upgrade_confirmation_send"};


TEST(opBuilderUpgradeConfirmationTestSuite, Builds)
{
    auto tuple {std::make_tuple(targetField, arSendHFName, std::vector<std::string> {"query params"})};

    ASSERT_NO_THROW(opBuilderHelperSendUpgradeConfirmation(tuple));
}

TEST(opBuilderUpgradeConfirmationTestSuite, BuildsNoParameterError)
{
    auto tuple {std::make_tuple(targetField, arSendHFName, std::vector<std::string> {})};

    ASSERT_THROW(opBuilderHelperSendUpgradeConfirmation(tuple), std::runtime_error);
}

TEST(opBuilderUpgradeConfirmationTestSuite, Send)
{
    // auto tuple {std::make_tuple(targetField, arSendHFName, std::vector<std::string> {"test\n123"})};
    // auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    // auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    // ASSERT_GT(serverSocketFD, 0);

    // auto event {make_shared<json::Json>(R"({"agent_id": "007"})")};
    // auto result {op(event)};
    // ASSERT_TRUE(result);
    // ASSERT_TRUE(result.payload()->isBool(targetField));
    // ASSERT_TRUE(result.payload()->getBool(targetField));

    // // Check received command on the AR's queue
    // ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "test\n123");

    // close(serverSocketFD);
    // unlink(AR_QUEUE_PATH);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendFromReference)
{
    // auto tuple {
    //     std::make_tuple(targetField, arSendHFName, std::vector<std::string> {"$wdb.query_params"})};
    // auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    // auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    // ASSERT_GT(serverSocketFD, 0);

    // auto event {
    //     make_shared<json::Json>(R"({"wdb": {"query_params": "reference_test"}})")};
    // auto result {op(event)};
    // ASSERT_TRUE(result);
    // ASSERT_TRUE(result.payload()->isBool(targetField));
    // ASSERT_TRUE(result.payload()->getBool(targetField));

    // // Check received command on the AR's queue
    // ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "reference_test");

    // close(serverSocketFD);
    // unlink(AR_QUEUE_PATH);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendEmptyReferencedValueError)
{
    // auto tuple {
    //     std::make_tuple(targetField, arSendHFName, std::vector<std::string> {"$wdb.query_params"})};
    // auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    // auto event {make_shared<json::Json>(R"({"wdb": {"query_params": ""}})")};
    // auto result {op(event)};
    // ASSERT_FALSE(result);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendEmptyReferenceError)
{
    // auto tuple {
    //     std::make_tuple(targetField, arSendHFName, std::vector<std::string> {"$wdb.query_params"})};
    // auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    // auto event {make_shared<json::Json>(R"({"wdb": {"NO_query_params": "123"}})")};
    // auto result {op(event)};
    // ASSERT_FALSE(result);
}
