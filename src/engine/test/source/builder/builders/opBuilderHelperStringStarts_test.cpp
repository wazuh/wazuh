/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

// Build ok
TEST(opBuilderHelperStringStarts, Build)
{
    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"test_value"});

    ASSERT_NO_THROW(bld::opBuilderHelperStringStarts(tuple));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringStarts, BuildManyParametersError)
{
    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"test_value", "test_value2"});

    ASSERT_THROW(bld::opBuilderHelperStringStarts(tuple), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringStarts, RawString)
{
    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"test_value"});

    auto op = bld::opBuilderHelperStringStarts(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(
        R"({"sourceField":"sample_value"})"); // Shall not pass
    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);

    auto event2 = std::make_shared<json::Json>(
        R"({"sourceField":"sample_value_test_value"})"); // Shall not pass
    result::Result<Event> result2 = op(event2);
    ASSERT_FALSE(result2);

    auto event3 =
        std::make_shared<json::Json>(R"({"sourceField":"test_valu"})"); // Shall not pass
    result::Result<Event> result3 = op(event3);
    ASSERT_FALSE(result3);

    auto event4 = std::make_shared<json::Json>(
        R"({"sourceField":"test_value_extended"})"); // Shall pass
    result::Result<Event> result4 = op(event4);
    ASSERT_TRUE(result4);

    auto event5 =
        std::make_shared<json::Json>(R"({"otherfield":"value"})"); // Shall not pass
    result::Result<Event> result5 = op(event5);
    ASSERT_FALSE(result5);

    auto event6 =
        std::make_shared<json::Json>(R"({"otherfield":"test_"})"); // Shall not pass
    result::Result<Event> result6 = op(event6);
    ASSERT_FALSE(result6);

    auto event7 =
        std::make_shared<json::Json>(R"({"otherfield":"test_value"})"); // Shall not pass
    result::Result<Event> result7 = op(event7);
    ASSERT_FALSE(result7);

    auto event8 = std::make_shared<json::Json>(
        R"({"sourceField":"test_value_extended"})"); // Shall pass
    result::Result<Event> result8 = op(event8);
    ASSERT_TRUE(result8);

    auto event9 =
        std::make_shared<json::Json>(R"({"sourceField":"test_valu"})"); // Shall not pass
    result::Result<Event> result9 = op(event9);
    ASSERT_FALSE(result9);

    auto event10 =
        std::make_shared<json::Json>(R"({"sourceField":""})"); // Shall not pass
    result::Result<Event> result10 = op(event10);
    ASSERT_FALSE(result10);

    auto event11 =
        std::make_shared<json::Json>(R"({"sourceField":"test_value"})"); // Shall pass
    result::Result<Event> result11 = op(event11);
    ASSERT_TRUE(result11);
}

// Test ok: static values
TEST(opBuilderHelperStringStarts, NotStrings)
{

    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"test_value"});

    auto op = bld::opBuilderHelperStringStarts(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(R"({"sourceField":null})");
    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);

    auto event2 = std::make_shared<json::Json>(R"({"sourceField":true})");
    result::Result<Event> result2 = op(event2);
    ASSERT_FALSE(result2);

    auto event3 = std::make_shared<json::Json>(R"({"sourceField":10})");
    result::Result<Event> result3 = op(event3);
    ASSERT_FALSE(result3);

    auto event4 = std::make_shared<json::Json>(R"({"sourceField":{}})");
    result::Result<Event> result4 = op(event4);
    ASSERT_FALSE(result4);

    auto event5 = std::make_shared<json::Json>(R"({"sourceField":[]})");
    result::Result<Event> result5 = op(event5);
    ASSERT_FALSE(result5);

    auto event6 = std::make_shared<json::Json>(R"({"sourceField":["hi", "bye"]})");
    result::Result<Event> result6 = op(event6);
    ASSERT_FALSE(result6);

    auto event7 = std::make_shared<json::Json>(R"({"sourceField":{"test": "value"}})");
    result::Result<Event> result7 = op(event7);
    ASSERT_FALSE(result7);
}

TEST(opBuilderHelperStringStarts, EmptyString)
{
    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"test_value"});

    auto op = bld::opBuilderHelperStringStarts(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(R"({"sourceField":""})");
    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);

    auto event2 = std::make_shared<json::Json>(R"({"sourceField":"test_value"})");
    result::Result<Event> result2 = op(event2);
    ASSERT_TRUE(result2);
}

// TODO: check if this is the expected result
TEST(opBuilderHelperStringStarts, EmptyStartString)
{

    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"$testField"});

    auto op = bld::opBuilderHelperStringStarts(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(R"({"sourceField": "", "testField": ""})");
    result::Result<Event> result1 = op(event1);
    ASSERT_TRUE(result1);

    auto event2 =
        std::make_shared<json::Json>(R"({"sourceField": "test_value", "testField": ""})");
    result::Result<Event> result2 = op(event2);
    ASSERT_TRUE(result2);
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringStarts, ReferencedString)
{

    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"$ref_key"});

    auto op = bld::opBuilderHelperStringStarts(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(R"({
                    "sourceField":"sample_value",
                    "ref_key":"test_value"
                })");

    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);

    auto event2 = std::make_shared<json::Json>(R"({
                    "sourceField":"test_value",
                    "ref_key":"test_value"
                })");
    result::Result<Event> result2 = op(event2);
    ASSERT_TRUE(result2);

    auto event3 = std::make_shared<json::Json>(R"({
                    "otherfield":"value",
                    "ref_key":"test_value"
                })");
    result::Result<Event> result3 = op(event3);
    ASSERT_FALSE(result3);

    auto event4 = std::make_shared<json::Json>(R"({
                    "otherfield":"test_value",
                    "ref_key":"test_value"
                })");
    result::Result<Event> result4 = op(event4);
    ASSERT_FALSE(result4);

    auto event5 = std::make_shared<json::Json>(R"({
                    "sourceField":"test_value_extended",
                    "ref_key":"test_value"
                })");
    result::Result<Event> result5 = op(event5);
    ASSERT_TRUE(result5);

    auto event6 = std::make_shared<json::Json>(R"({
                    "sourceField":"test_value_extra_extended",
                    "ref_key":"test_value"
                })");

    result::Result<Event> result6 = op(event6);
    ASSERT_TRUE(result6);
}

// Test ok: multilevel referenced values (string)
TEST(opBuilderHelperStringStarts, NestedReferencedStrings)
{

    auto tuple = std::make_tuple(
        std::string {"/rootKey1/sourceField"}, // TODO check if this is the expected
                                               // argument with '/'
        std::string {"starts_with"},
        std::vector<std::string> {"$rootKey2.ref_key"});

    auto op = bld::opBuilderHelperStringStarts(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event1 = std::make_shared<json::Json>(R"(
                {
                    "rootKey2": {
                        "sourceField": "test_value",
                        "ref_key": "test_value"
                    },
                    "rootKey1": {
                        "sourceField": "sample_value",
                        "ref_key": "sample_value"
                    }
                }
            )");
    result::Result<Event> result1 = op(event1);
    ASSERT_FALSE(result1);

    auto event2 = std::make_shared<json::Json>(R"(
                {
                    "rootKey2": {
                        "sourceField": "test_value",
                        "ref_key": "sample_value"
                    },
                    "rootKey1": {
                        "sourceField": "sample_value",
                        "ref_key": "test_value"
                    }
                }
            )"); // Shall pass
    result::Result<Event> result2 = op(event2);
    ASSERT_TRUE(result2);

    auto event3 = std::make_shared<json::Json>(R"(
                {
                    "rootKey2": {
                        "sourceField": "test_value_extended",
                        "ref_key": "sample_value"
                    },
                    "rootKey1": {
                        "sourceField": "sample_value",
                        "ref_key": "test_value"
                    }
                }
            )"); // Shall pass
    result::Result<Event> result3 = op(event3);
    ASSERT_TRUE(result3);

    auto event4 = std::make_shared<json::Json>(R"(
                {
                    "rootKey2": {
                        "sourceField": "test_value_extended",
                        "ref_key": "sample_value"
                    },
                    "rootKey1": {
                        "sourceField": "sample_value",
                        "ref_key": "test_value_extra_extended"
                    }
                }
            )"); // Shall pass
    result::Result<Event> result4 = op(event4);
    ASSERT_TRUE(result4);
}
