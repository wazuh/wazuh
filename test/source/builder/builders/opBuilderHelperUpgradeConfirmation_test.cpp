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
#include <utils/socketInterface/unixSecureStream.hpp>

#include "opBuilderHelperUpgradeConfirmation.hpp"
#include "socketAuxiliarFunctions.hpp"
#include <testsCommon.hpp>

using namespace base;
using namespace builder::internals::builders;

const std::string targetField {"/result"};
const std::string upgradeConfirmationHelperName {"send_upgrade_confirmation"};
const std::string testMessage {"{\"fieldReference\":\"test String Sent\"}"};
const std::string messageReferenceString {"$fieldReference"};
const std::string messageReferenceObject {"$fieldReferenceObject"};

class opBuilderUpgradeConfirmationTestSuite : public ::testing::Test
{
    void SetUp() override { initLogging(); }

    void TearDown() override {}
};

TEST_F(opBuilderUpgradeConfirmationTestSuite, Build)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_NO_THROW(std::apply(opBuilderHelperSendUpgradeConfirmation, tuple));
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, ErrorBuildWithoutParameters)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(opBuilderHelperSendUpgradeConfirmation, tuple), std::runtime_error);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, ErrorBuildWithMoreParameters)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {"First", "Seccond", "Third"},
                                std::make_shared<defs::mocks::FailDef>())};

    ASSERT_THROW(std::apply(opBuilderHelperSendUpgradeConfirmation, tuple), std::runtime_error);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, ErrorBuildMessageNotReference)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {testMessage},
                                std::make_shared<defs::mocks::FailDef>())};
    ASSERT_THROW(std::apply(opBuilderHelperSendUpgradeConfirmation, tuple), std::runtime_error);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendFromReferenceString)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceString},
                                std::make_shared<defs::mocks::FailDef>())};
    auto op {std::apply(opBuilderHelperSendUpgradeConfirmation, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"fieldReference": "test String Sent"})")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendFromReferenceObject)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};
    auto op {std::apply(opBuilderHelperSendUpgradeConfirmation, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t(
        [&]()
        {
            int clientRemoteFD {testAcceptConnection(serverSocketFD)};
            ASSERT_GT(clientRemoteFD, 0);

            // Check received message
            std::string messageReveicved;
            ASSERT_NO_THROW(messageReveicved = testRecvString(clientRemoteFD, SOCK_STREAM));
            ASSERT_STREQ(messageReveicved.c_str(), R"({"fieldReference":"test String Sent"})");

            close(clientRemoteFD);
        });

    auto event {std::make_shared<json::Json>(R"({"fieldReferenceObject" : {"fieldReference": "test String Sent"}})")};
    auto result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool(targetField));

    t.join();
    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendEmptyReferencedValueError)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};
    auto op {std::apply(opBuilderHelperSendUpgradeConfirmation, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"fieldReference": {}})")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, SendWrongReferenceError)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {"$NonExistentReference"},
                                std::make_shared<defs::mocks::FailDef>())};
    auto op {std::apply(opBuilderHelperSendUpgradeConfirmation, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"fieldReference": "test String Sent"})")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, EmptyObjectSent)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};
    auto op {std::apply(opBuilderHelperSendUpgradeConfirmation, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"fieldReferenceObject":{}})")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST_F(opBuilderUpgradeConfirmationTestSuite, UnsuccesfullSentMessage)
{
    auto tuple {std::make_tuple(targetField,
                                upgradeConfirmationHelperName,
                                std::vector<std::string> {messageReferenceObject},
                                std::make_shared<defs::mocks::FailDef>())};
    auto op {std::apply(opBuilderHelperSendUpgradeConfirmation, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    unlink(WM_UPGRADE_SOCK);

    auto event {std::make_shared<json::Json>(R"({"fieldReferenceObject":{"key":"val"}})")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}
