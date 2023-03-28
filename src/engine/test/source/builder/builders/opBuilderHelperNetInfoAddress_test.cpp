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
#include <logging/logging.hpp>

#include "socketAuxiliarFunctions.hpp"

using namespace base;
namespace bld = builder::internals::builders;

class opBuilderHelperNetInfoTest : public ::testing::Test
{

protected:
    virtual void SetUp()
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = logging::DEFAULT_TESTS_LOG_PATH;
        logging::loggingInit(logConfig);
    }

    virtual void TearDown() {}
};

TEST_F(opBuilderHelperNetInfoTest, Builds)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {"$agentID", "$scanId", "$name", "$array"});

    ASSERT_NO_THROW(bld::opBuilderHelperSaveNetInfoIPv4(tuple));
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_with_parameter_just_values)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv6"},
        std::vector<std::string> {"parameter", "agentID", "scanId", "name"});

    ASSERT_THROW(bld::opBuilderHelperSaveNetInfoIPv6(tuple), std::runtime_error);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_with_parameter_one_not_reference)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv6"},
        std::vector<std::string> {"$agentID", "$scanId", "$name", "array"});

    ASSERT_THROW(bld::opBuilderHelperSaveNetInfoIPv6(tuple), std::runtime_error);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_with_parameters_wrong_quantity)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv6"},
        std::vector<std::string> {"$agentID", "$scanId", "$name", "$array", "$array2"});

    ASSERT_THROW(bld::opBuilderHelperSaveNetInfoIPv6(tuple), std::runtime_error);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_name_not_string)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": 123,
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15"
                            ],
                            "netmask":
                            [
                                "255.255.255.0"
                            ],
                            "broadcast":
                            [
                                "192.168.10.255"
                            ]
                        }
                    }
                }
            }
        })");

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_agentid_not_present)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "iface":
                    {
                        "name": 123,
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15"
                            ],
                            "netmask":
                            [
                                "255.255.255.0"
                            ],
                            "broadcast":
                            [
                                "192.168.10.255"
                            ]
                        }
                    }
                }
            }
        })");

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_not_base_object)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name"
                    }
                }
            }
        })");

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_event)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15",
                                "192.168.11.16"
                            ],
                            "netmask":
                            [
                                "255.255.255.0",
                                "255.255.255.0"
                            ],
                            "broadcast":
                            [
                                "192.168.10.255",
                                "192.168.11.255"
                            ]
                        }
                    }
                }
            }
        })");

    // Create server
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(testRecvString(clientRemote, SOCK_STREAM).c_str(),
                     "agent 021 netaddr save "
                     "123456|iface_name|0|192.168.10.15|255.255.255.0|192.168.10.255");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(testRecvString(SecondclientRemote, SOCK_STREAM).c_str(),
                     "agent 021 netaddr save "
                     "123456|iface_name|0|192.168.11.16|255.255.255.0|192.168.11.255");
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_single_address_event)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15"
                            ],
                            "netmask":
                            [
                                "255.255.255.0"
                            ],
                            "broadcast":
                            [
                                "192.168.10.255"
                            ]
                        }
                    }
                }
            }
        })");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(testRecvString(clientRemote, SOCK_STREAM).c_str(),
                     "agent 021 netaddr save "
                     "123456|iface_name|0|192.168.10.15|255.255.255.0|192.168.10.255");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_seccond_failed_event)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15",
                                "192.168.11.16"
                            ],
                            "netmask":
                            [
                                "255.255.255.0",
                                "255.255.255.0"
                            ],
                            "broadcast":
                            [
                                "192.168.10.255",
                                "192.168.11.255"
                            ]
                        }
                    }
                }
            }
        })");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(testRecvString(clientRemote, SOCK_STREAM).c_str(),
                     "agent 021 netaddr save "
                     "123456|iface_name|0|192.168.10.15|255.255.255.0|192.168.10.255");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        testSendMsg(SecondclientRemote, "err");
        close(SecondclientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    t.join();
    close(serverSocketFD);

    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_signle_address_ipv6_event)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv6"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv6"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv6":
                        {
                            "address":
                            [
                                "192.168.10.15"
                            ],
                            "netmask":
                            [
                                "255.255.255.0"
                            ],
                            "broadcast":
                            [
                                "192.168.10.255"
                            ]
                        }
                    }
                }
            }
        })");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(testRecvString(clientRemote, SOCK_STREAM).c_str(),
                     "agent 021 netaddr save "
                     "123456|iface_name|1|192.168.10.15|255.255.255.0|192.168.10.255");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv6(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_various_addres_none_others)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15",
                                "192.168.11.16",
                                "192.168.100.16"
                            ],
                            "netmask":
                            [],
                            "broadcast":
                            []
                        }
                    }
                }
            }
        })");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(clientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.10.15|NULL|NULL");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(SecondclientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.11.16|NULL|NULL");
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);

        const int ThirdclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(ThirdclientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.100.16|NULL|NULL");
        testSendMsg(ThirdclientRemote, "ok");
        close(ThirdclientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_various_addres_others_wrong_type)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15",
                                "192.168.11.16",
                                "192.168.100.16"
                            ],
                            "netmask":
                            [],
                            "broadcast":
                            [
                                1,
                                2,
                                3
                            ]
                        }
                    }
                }
            }
        })");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(clientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.10.15|NULL|NULL");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(SecondclientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.11.16|NULL|NULL");
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);

        const int ThirdclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(ThirdclientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.100.16|NULL|NULL");
        testSendMsg(ThirdclientRemote, "ok");
        close(ThirdclientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_without_broadcast_netmask)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv4"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv4"});

    const auto event1 = std::make_shared<json::Json>(
        R"(
        {
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv4":
                        {
                            "address":
                            [
                                "192.168.10.15",
                                "192.168.11.16",
                                "192.168.100.16"
                            ]
                        }
                    }
                }
            }
        })");

    // Create the endpoint for test
    const int serverSocketFD {testBindUnixSocket(wazuhdb::WDB_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(clientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.10.15|NULL|NULL");
        testSendMsg(clientRemote, "ok");
        close(clientRemote);

        const int SecondclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(SecondclientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.11.16|NULL|NULL");
        testSendMsg(SecondclientRemote, "ok");
        close(SecondclientRemote);

        const int ThirdclientRemote {testAcceptConnection(serverSocketFD)};
        ASSERT_STREQ(
            testRecvString(ThirdclientRemote, SOCK_STREAM).c_str(),
            "agent 021 netaddr save 123456|iface_name|0|192.168.100.16|NULL|NULL");
        testSendMsg(ThirdclientRemote, "ok");
        close(ThirdclientRemote);
    });

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv4(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST_F(opBuilderHelperNetInfoTest, False_result_when_no_address)
{
    const auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sysc_ni_save_ipv6"},
                        std::vector<std::string> {"$agent.id",
                                                  "$event.original.ID",
                                                  "$event.original.iface.name",
                                                  "$event.original.iface.IPv6"});

    const auto event1 = std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "021"
            },
            "event":
            {
                "original":
                {
                    "ID": 123456,
                    "iface":
                    {
                        "name": "iface_name",
                        "IPv6":
                        {
                            "netmask":
                            [],
                            "broadcast":
                            []
                        }
                    }
                }
            }
        })");

    auto op =
        bld::opBuilderHelperSaveNetInfoIPv6(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result);
}
