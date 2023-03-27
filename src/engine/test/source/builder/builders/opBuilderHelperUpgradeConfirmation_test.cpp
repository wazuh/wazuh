/* Copyright (C) 2015-2023, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include "opBuilderHelperUpgradeConfirmation.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace builder::internals::builders;

const std::string targetField {"/result"};
const std::string upgradeConfirmationHelperName {"upgrade_confirmation_send"};
const std::string testMessage {"test String Sent"};
const std::string messageReference {"$fieldReference"};

TEST(opBuilderUpgradeConfirmationTestSuite, Build)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {"query params"})};

    ASSERT_NO_THROW(opBuilderHelperSendUpgradeConfirmation(tuple));
}

TEST(opBuilderUpgradeConfirmationTestSuite, ErrorBuildWithoutParameters)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {})};

    ASSERT_THROW(opBuilderHelperSendUpgradeConfirmation(tuple), std::runtime_error);
}

TEST(opBuilderUpgradeConfirmationTestSuite, ErrorBuildWithMoreParameters)
{
    auto tuple {std::make_tuple(
        targetField, upgradeConfirmationHelperName, std::vector<std::string> {"First", "Seccond", "Third"})};

    ASSERT_THROW(opBuilderHelperSendUpgradeConfirmation(tuple), std::runtime_error);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendAndReceivedMessage)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {testMessage})};
    auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
            ASSERT_STREQ(messageReveicved.c_str(), testMessage.c_str());

            close(clientRemoteFD);
        });

    auto event {std::make_shared<json::Json>("{}")};
    auto result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool(targetField));

    t.join();
    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendFromReference)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {messageReference})};
    auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
            ASSERT_STREQ(messageReveicved.c_str(), testMessage.c_str());

            close(clientRemoteFD);
        });

    auto event {std::make_shared<json::Json>(R"({"fieldReference": "test String Sent"})")};
    auto result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool(targetField));

    t.join();
    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendEmptyReferencedValueError)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {messageReference})};
    auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"fieldReference": ""})")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST(opBuilderUpgradeConfirmationTestSuite, SendWrongReferenceError)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {"$NonExistentReference"})};
    auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>(R"({"fieldReference": "test String Sent"})")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST(opBuilderUpgradeConfirmationTestSuite, EmptyMessageSent)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {""})};
    auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(WM_UPGRADE_SOCK, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {std::make_shared<json::Json>("{}")};
    auto result {op(event)};

    ASSERT_FALSE(result);

    close(serverSocketFD);
    unlink(WM_UPGRADE_SOCK);
}

TEST(opBuilderUpgradeConfirmationTestSuite, UnsuccesfullSentMessage)
{
    auto tuple {std::make_tuple(targetField, upgradeConfirmationHelperName, std::vector<std::string> {testMessage})};
    auto op {opBuilderHelperSendUpgradeConfirmation(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    unlink(WM_UPGRADE_SOCK);

    auto event {std::make_shared<json::Json>("{}")};
    auto result {op(event)};

    ASSERT_FALSE(result);
}
