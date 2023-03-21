#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperIPVersionFromIPStr, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$test"});

    ASSERT_NO_THROW(bld::opBuilderHelperIPVersionFromIPStr(tuple));
}

TEST(opBuilderHelperIPVersionFromIPStr, Builds_bad_type_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"test"});

    ASSERT_THROW(bld::opBuilderHelperIPVersionFromIPStr(tuple), std::runtime_error);
}

TEST(opBuilderHelperIPVersionFromIPStr, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$TEST", "$test"});

    ASSERT_THROW(bld::opBuilderHelperIPVersionFromIPStr(tuple), std::runtime_error);
}

TEST(opBuilderHelperIPVersionFromIPStr, ipv4_OK)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$srcIP"});
    auto op =
        bld::opBuilderHelperIPVersionFromIPStr(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto events = {
        std::make_shared<json::Json>(R"({"srcIP": "0.0.0.0"})"),
        std::make_shared<json::Json>(R"({"srcIP": "127.0.0.1"})"),
        std::make_shared<json::Json>(R"({"srcIP": "192.168.0.1"})"),
        std::make_shared<json::Json>(R"({"srcIP": "255.255.255.255"})"),
    };

    for (auto event : events)
    {

        result::Result<Event> result = op(event);
        ASSERT_TRUE(result);
        ASSERT_EQ("IPv4", result.payload()->getString("/field2check").value());
    }
}

TEST(opBuilderHelperIPVersionFromIPStr, ipv4_NOT_OK)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$srcIP"});

    auto event1 = std::make_shared<json::Json>(R"({"srcIP": "192.168.0.257"})");

    auto op =
        bld::opBuilderHelperIPVersionFromIPStr(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);

    ASSERT_FALSE(result.payload()->getString("/field2check").has_value());
}

TEST(opBuilderHelperIPVersionFromIPStr, ipv6_OK)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$srcIP"});
    auto op =
        bld::opBuilderHelperIPVersionFromIPStr(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto events = {
        std::make_shared<json::Json>(R"({"srcIP": "0:0:0:0:0:0:0:0"})"),
        std::make_shared<json::Json>(R"({"srcIP": "::1"})"),
        std::make_shared<json::Json>(R"({"srcIP": "1:1:1:1:1:1:1:1"})"),
        std::make_shared<json::Json>(R"({"srcIP": "::255.255.255.255"})"),
        std::make_shared<json::Json>(R"({"srcIP": "::"})"),
        std::make_shared<json::Json>(R"({"srcIP": "::FFFF:204.152.189.116"})"),
        std::make_shared<json::Json>(R"({"srcIP": "59FB::1005:CC57:6571"})"),
        std::make_shared<json::Json>(
            R"({"srcIP": "21E5:69AA:FFFF:1:E100:B691:1285:F56E"})"),
        std::make_shared<json::Json>(
            R"({"srcIP": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"})"),
        std::make_shared<json::Json>(R"({"srcIP": "2001:db8:85a3:0:0:8a2e:370:7334"})"),
    };

    for (auto event : events)
    {

        result::Result<Event> result = op(event);
        ASSERT_TRUE(result);
        ASSERT_EQ("IPv6", result.payload()->getString("/field2check").value());
    }
}

TEST(opBuilderHelperIPVersionFromIPStr, ipv6_NOT_OK)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$srcIP"});

    auto event1 = std::make_shared<json::Json>(R"({"srcIP": "::G"})");

    auto op =
        bld::opBuilderHelperIPVersionFromIPStr(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);

    ASSERT_FALSE(result.payload()->getString("/field2check").has_value());
}

TEST(opBuilderHelperIPVersionFromIPStr, invalid_field)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_version"},
                                 std::vector<std::string> {"$srcIP"});
    auto op =
        bld::opBuilderHelperIPVersionFromIPStr(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto events = {
        std::make_shared<json::Json>(R"({"srcIP": 123})"),
        std::make_shared<json::Json>(R"({"srcIP": false})"),
        std::make_shared<json::Json>(R"({"srcIP": {}})"),
        std::make_shared<json::Json>(R"({"srcIP": ["192.168.0.257"]})"),
        std::make_shared<json::Json>(R"({"not_srcIP": "192.168.0.256"})"),
        std::make_shared<json::Json>(R"({"srcIP": ["::1"]})"),
        std::make_shared<json::Json>(R"({"not_srcIP": "::1"})"),
    };

    for (auto event : events)
    {
        result::Result<Event> result = op(event);
        ASSERT_FALSE(result);
        ASSERT_FALSE(result.payload()->getString("/field2check").has_value());
    }
}
