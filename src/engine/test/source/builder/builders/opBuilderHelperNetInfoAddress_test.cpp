
#include "opBuilderHelperNetInfoAddress.hpp"

#include <any>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <testsCommon.hpp>
#include <wdb/mockWdbHandler.hpp>
#include <wdb/mockWdbManager.hpp>

using namespace base;
using namespace wazuhdb::mocks;
namespace bld = builder::internals::builders;

class opBuilderHelperNetInfoTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbManager> wdbManager {};
    std::shared_ptr<MockWdbHandler> wdbHandler {};

    void SetUp() override
    {
        initLogging();

        wdbManager = std::make_shared<MockWdbManager>();
        wdbHandler = std::make_shared<MockWdbHandler>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdbHandler));
    }

    void TearDown() override {}
};

TEST_F(opBuilderHelperNetInfoTest, Builds)
{
    const auto tuple = std::make_tuple(std::string {"/field"},
                                       std::string {"sysc_ni_save_ipv4"},
                                       std::vector<std::string> {"$agentID", "$scanId", "$name", "$array"},
                                       std::make_shared<defs::mocks::FailDef>());

    EXPECT_CALL(*wdbManager, connection());

    ASSERT_NO_THROW(std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple));
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_with_parameter_just_values)
{
    const auto tuple = std::make_tuple(std::string {"/field"},
                                       std::string {"sysc_ni_save_ipv6"},
                                       std::vector<std::string> {"parameter", "agentID", "scanId", "name"},
                                       std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getBuilderSaveNetInfoIPv6(wdbManager), tuple), std::runtime_error);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_with_parameter_one_not_reference)
{
    const auto tuple = std::make_tuple(std::string {"/field"},
                                       std::string {"sysc_ni_save_ipv6"},
                                       std::vector<std::string> {"$agentID", "$scanId", "$name", "array"},
                                       std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getBuilderSaveNetInfoIPv6(wdbManager), tuple), std::runtime_error);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_with_parameters_wrong_quantity)
{
    const auto tuple = std::make_tuple(std::string {"/field"},
                                       std::string {"sysc_ni_save_ipv6"},
                                       std::vector<std::string> {"$agentID", "$scanId", "$name", "$array", "$array2"},
                                       std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getBuilderSaveNetInfoIPv6(wdbManager), tuple), std::runtime_error);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_name_not_string)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_agentid_not_present)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Failed_execution_not_base_object)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};
    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_event)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(testing::StrEq("agent 021 netaddr save "
                                                      "123456|iface_name|1|192.168.10.15|255.255.255.0|192.168.10.255"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(testing::StrEq("agent 021 netaddr save "
                                                      "123456|iface_name|1|192.168.11.16|255.255.255.0|192.168.11.255"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result {op(event1)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_single_address_event)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(testing::StrEq("agent 021 netaddr save "
                                                      "123456|iface_name|1|192.168.10.15|255.255.255.0|192.168.10.255"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_seccond_failed_event)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(testing::StrEq("agent 021 netaddr save "
                                                      "123456|iface_name|1|192.168.10.15|255.255.255.0|192.168.10.255"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(
        *wdbHandler,
        tryQueryAndParseResult(
            testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.11.16|255.255.255.0|192.168.11.255"),
            testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_signle_address_ipv6_event)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv6"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv6"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(testing::StrEq("agent 021 netaddr save "
                                                      "123456|iface_name|1|192.168.10.15|255.255.255.0|192.168.10.255"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv6(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getBool("/field").value());
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_various_addres_none_others)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.10.15|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.11.16|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.100.16|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_with_various_addres_others_wrong_type)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.10.15|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.11.16|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.100.16|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
}

TEST_F(opBuilderHelperNetInfoTest, Correct_execution_without_broadcast_netmask)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv4"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv4"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.10.15|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.11.16|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    EXPECT_CALL(*wdbHandler,
                tryQueryAndParseResult(
                    testing::StrEq("agent 021 netaddr save 123456|iface_name|1|192.168.100.16|NULL|NULL"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv4(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
}

TEST_F(opBuilderHelperNetInfoTest, False_result_when_no_address)
{
    const auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"sysc_ni_save_ipv6"},
        std::vector<std::string> {
            "$agent.id", "$event.original.ID", "$event.original.iface.name", "$event.original.iface.IPv6"},
        std::make_shared<defs::mocks::FailDef>());

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

    EXPECT_CALL(*wdbManager, connection());

    auto op = std::apply(bld::getBuilderSaveNetInfoIPv6(wdbManager), tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result);
}
