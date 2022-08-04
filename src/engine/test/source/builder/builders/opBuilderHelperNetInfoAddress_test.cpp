/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderHelperNetInfoAddress.hpp"

#include <any>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include <baseTypes.hpp>
#include <wdb/wdb.hpp>


#include "socketAuxiliarFunctions.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperNetInfoTest, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperSaveNetInfoIPv4(tuple));
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_with_event)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv4":{"address":["192.168.10.15","192.168.11.16"],"netmask":["255.255.255.0","255.255.255.0"],"broadcast":["192.168.10.255","192.168.11.255"]}}}}})");

    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_with_single_address_event)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv4":{"address":["192.168.10.15"],"netmask":["255.255.255.0"],"broadcast":["192.168.10.255"]}}}}})");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_with_seccond_failed_event)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv4":{"address":["192.168.10.15","192.168.11.16"],"netmask":["255.255.255.0","255.255.255.0"],"broadcast":["192.168.10.255","192.168.11.255"]}}}}})");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(SecondclientRemote, "err");
        close(SecondclientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result);

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_with_signle_address_ipv6_event)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv6"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv6":{"address":["192.168.10.15"],"netmask":["255.255.255.0"],"broadcast":["192.168.10.255"]}}}}})");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv6(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, Failed_execution_with_parameter)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv6"},
                                 std::vector<std::string> {"parameter"});

    ASSERT_THROW(bld::opBuilderHelperSaveNetInfoIPv6(tuple), std::runtime_error);
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_with_various_addres_none_others)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv4":{"address":["192.168.10.15","192.168.11.16","192.168.100.16"],"netmask":[],"broadcast":[]}}}}})");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);

        const int ThirdclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(ThirdclientRemote, "ok");
        close(ThirdclientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_with_various_addres_others_wrong_type)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv4":{"address":["192.168.10.15","192.168.11.16","192.168.100.16"],"netmask":[],"broadcast":[1,2,3]}}}}})");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);

        const int ThirdclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(ThirdclientRemote, "ok");
        close(ThirdclientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, Correct_execution_without_broadcast_netmask)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv4"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv4":{"address":["192.168.10.15","192.168.11.16","192.168.100.16"]}}}}})");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        testRecvString(clientRemote, SOCK_STREAM);
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);

        const int ThirdclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(ThirdclientRemote, "ok");
        close(ThirdclientRemote);
    });

    auto op = bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderHelperNetInfoTest, False_result_when_no_address)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"saveNetInfoIPv6"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(
        R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"name":"iface_name","IPv6":{"netmask":[],"broadcast":[]}}}}})");

    auto op = bld::opBuilderHelperSaveNetInfoIPv6(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result);

}
