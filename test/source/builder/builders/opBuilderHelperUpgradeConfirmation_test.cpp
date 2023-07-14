/* Copyright (C) 2015-2023, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>

#include "opBuilderHelperUpgradeConfirmation.hpp"
#include <testsCommon.hpp>

using namespace base;
using namespace builder::internals::builders;
using namespace sockiface::mocks;

const std::string targetField {"/result"};
const std::string upgradeConfirmationHelperName {"send_upgrade_confirmation"};
const std::string testMessage {"{\"fieldReference\":\"test String Sent\"}"};
const std::string messageReferenceString {"$fieldReference"};
const std::string messageReferenceObject {"$fieldReferenceObject"};

class opBuilderUpgradeConfirmationTestSuite : public ::testing::Test
{
protected:
    std::shared_ptr<MockSockFactory> sockFactory;
    std::shared_ptr<MockSockHandler> sockHandler;

    void SetUp() override
    {
        initLogging();

        sockFactory = std::make_shared<MockSockFactory>();
        sockHandler = std::make_shared<MockSockHandler>();

        ON_CALL(*sockFactory, getHandler(testing::_, testing::_)).WillByDefault(testing::Return(sockHandler));
    }

    void TearDown() override {}
};

TEST_F(opBuilderUpgradeConfirmationTestSuite, Build)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    ASSERT_NO_THROW(std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple));
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, ErrorBuildWithoutParameters)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple), std::runtime_error);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, ErrorBuildWithMoreParameters)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {"First", "Seccond", "Third"},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple), std::runtime_error);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, ErrorBuildMessageNotReference)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {testMessage},
                                std::make_shared<defs::mocks::FailDef>())};
    ASSERT_THROW(std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple), std::runtime_error);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendFromReferenceString)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceString},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    auto op {
        std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"fieldReference": "test String Sent"})")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendFromReferenceObject)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    auto op {
        std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    EXPECT_CALL(*sockHandler, sendMsg(testing::StrEq(R"({"fieldReference":"test String Sent"})")))
        .WillOnce(testing::Return(successSendMsgRes()));

    auto event {std::make_shared<json::Json>(R"({"fieldReferenceObject" : {"fieldReference": "test String Sent"}})")};
    auto result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool(targetField));
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendEmptyReferencedValueError)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    auto op {
        std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"fieldReference": {}})")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendWrongReferenceError)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {"$NonExistentReference"},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    auto op {
        std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"fieldReference": "test String Sent"})")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, EmptyObjectSent)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    auto op {
        std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {std::make_shared<json::Json>(R"({"fieldReferenceObject":{}})")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, UnsuccesfullSentMessage)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};

    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    auto op {
        std::apply(getBuilderHelperSendUpgradeConfirmation(sockFactory), tuple)->getPtr<Term<EngineOp>>()->getFn()};

    EXPECT_CALL(*sockHandler, sendMsg(testing::_)).WillOnce(testing::Return(socketErrorSendMsgRes()));

    auto event {std::make_shared<json::Json>(R"({"fieldReferenceObject":{"key":"val"}})")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}
