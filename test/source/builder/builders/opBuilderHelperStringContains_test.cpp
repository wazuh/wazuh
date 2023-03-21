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
TEST(opBuilderHelperStringContains, Build)
{
    auto tuple = std::make_tuple(
        std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {"test_value"});

    ASSERT_NO_THROW(bld::opBuilderHelperStringContains(tuple));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringContains, BuildManyParametersError)
{
    auto tuple = std::make_tuple(std::string {"/sourceField"},
                                 std::string {"contains"},
                                 std::vector<std::string> {"test_value", "test_value2"});

    ASSERT_THROW(bld::opBuilderHelperStringContains(tuple), std::runtime_error);
}

// Failed Empty
TEST(opBuilderHelperStringContains, FailedEmptyStringValueOrReference)
{
    // value
    auto tuple =
        std::make_tuple(std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {""});
    auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event = std::make_shared<json::Json>(
        R"({"sourceField":"sample_test_value",
        "reference":""})");

    result::Result<Event> result = op(event);
    // TODO: should this fail in the building proccess?
    ASSERT_FALSE(result);

    // reference
    tuple = std::make_tuple(
        std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {"$reference"});

    op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result = op(event);
    ASSERT_FALSE(result);
}

// Basic succesfull use with value
TEST(opBuilderHelperStringContains, SuccessAndFailedUsageWithValue)
{
    // basic value usage
    auto tuple =
        std::make_tuple(std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {"test"});

    auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event = std::make_shared<json::Json>(R"({"sourceField":"sample_test_value"})");

    result::Result<Event> result = op(event);
    ASSERT_TRUE(result);
}

// Basic succesfull use with reference
TEST(opBuilderHelperStringContains, SuccessAndFailedUsageWithReference)
{
    // basic reference usage
    auto tuple = std::make_tuple(
        std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {"$test_reference"});

    auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event = std::make_shared<json::Json>(
        R"({"sourceField":"sample_test_value",
        "test_reference":"test"})");

    result::Result<Event> result = op(event);
    ASSERT_TRUE(result);
}

// Check with all possible ascii characters will result successfull
TEST(opBuilderHelperStringContains, SeveralDifferentCasesAsReferencce)
{
    // create a string with all chars in ascci8
    const std::string& allChars {
        R"(!#$%&()*+,-./0123456789:;<=>?@ ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~)"};

    // basic reference
    auto tuple = std::make_tuple(
        std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {"$test_reference"});
    auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

    const std::vector<std::string> textFields = {R"(ABCDEFGHIJKLMNOPQRSTUVWXYZ)",
                                                 R"(abcdefghijklmnopqrstuvwxyz)",
                                                 R"(0123456789)",
                                                 " ",
                                                 R"([]^_`)",
                                                 R"({|}~)",
                                                 R"(!#$%&()*+,-./0123456789:;<=>?@)"};
    for (const auto& baseText : textFields)
    {
        auto event = std::make_shared<json::Json>(
            (fmt::format(R"({{"sourceField":"{}","test_reference":"{}"}})", allChars, baseText)).c_str());

        result::Result<Event> result = op(event);
        ASSERT_TRUE(result);
    }
}

// Check with all possible ascii characters will result successfull
TEST(opBuilderHelperStringContains, SeveralDifferentCasesByValue)
{
    // create a string with all chars in ascci8
    const std::string& allChars {
        R"(!#$%&()*+,-./0123456789:;<=>?@ ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~)"};

    const std::vector<std::string> textFields = {R"(ABCDEFGHIJKLMNOPQRSTUVWXYZ)",
                                                 R"(abcdefghijklmnopqrstuvwxyz)",
                                                 R"(0123456789)",
                                                 " ",
                                                 R"([]^_`)",
                                                 R"({|}~)",
                                                 R"(!#$%&()*+,-./0123456789:;<=>?@)"};
    for (const auto& baseText : textFields)
    {
        // basic reference
        auto tuple = std::make_tuple(
            std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {baseText});
        auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

        auto event = std::make_shared<json::Json>((fmt::format(R"({{"sourceField":"{}"}})", allChars)).c_str());

        result::Result<Event> result = op(event);
        ASSERT_TRUE(result);
    }
}

// Check different characters not found
TEST(opBuilderHelperStringContains, NotFoundVariousCases)
{
    const std::vector<std::string> sourceFields = {R"(ABCDEFGHIJKLMNOPQRSTUVWXYZ)",
                                                   R"(abcdefghijklmnopqrstuvwxyz)",
                                                   R"(0123456789)",
                                                   R"(ABCDEFGHIJKLMNOPQRSTUVWXYZ)",
                                                   " ",
                                                   R"([]^_`)",
                                                   R"({|}~)",
                                                   R"(!#$%&()*+,-./0123456789:;<=>?@)"};

    const std::vector<std::string> containsFields = {R"(abcdefghijklmnopqrstuvwxyz)",       // lower case
                                                     R"(ABCDEFGHIJKLMNOPQRSTUVWXYZ)",       // uppercase
                                                     R"(9876543210)",                       // different order
                                                     R"(ABCDEFGHIJKLMNOPQRSTUVWXYZZ)",      // Different ending
                                                     "  ",                                  // duplicated space
                                                     R"([ ]^_`)",                           // space in between
                                                     R"( {|||}~)",                          // start with space
                                                     R"(!!#$%&()*+,-./0123456789:;<=>?@)"}; // different start

    size_t index = 0;
    for (const auto& baseText : containsFields)
    {
        // basic reference
        auto tuple = std::make_tuple(
            std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {baseText});
        auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

        auto event =
            std::make_shared<json::Json>((fmt::format(R"({{"sourceField":"{}"}})", sourceFields.at(index++))).c_str());

        result::Result<Event> result = op(event);
        ASSERT_FALSE(result);
    }
}

// Nested references and nested sources success
TEST(opBuilderHelperStringContains, NestedReferencedStrings)
{

    auto tuple = std::make_tuple(std::string {"/rootKey1/sourceField"},
                                 std::string {"contains"},
                                 std::vector<std::string> {"$rootKey2.ref_key"});

    auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto event = std::make_shared<json::Json>(R"(
                {
                    "rootKey2": {
                        "sourceField": "test_AAAA_value",
                        "ref_key": "ZZZ"
                    },
                    "rootKey1": {
                        "sourceField": "test_ZZZ_value",
                        "ref_key": "sample_value"
                    }
                }
            )");
    result::Result<Event> result = op(event);
    ASSERT_TRUE(result);

    // Inside Array
    tuple = std::make_tuple(
        std::string {"/rootKey1/sourceField"}, std::string {"contains"}, std::vector<std::string> {"$rootKey2.0.A1"});

    op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();
    event = std::make_shared<json::Json>(R"(
                {
                    "rootKey2":
                    [
                        {
                            "A1": "value",
                            "B1": "another"
                        },
                        {
                            "A1": "val_ZZZ",
                            "B1": "another"
                        }
                    ],
                    "rootKey1":
                    {
                        "sourceField": "sample_value",
                        "ref_key": "test_value"
                    }
                }
            )"); // Shall pass
    result = op(event);
    ASSERT_TRUE(result);

    // nested vs value
    tuple = std::make_tuple(
        std::string {"/root/ObjA/ObjB/Field"}, std::string {"contains"}, std::vector<std::string> {"value"});

    op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();
    event = std::make_shared<json::Json>(R"(
            {
                "root":
                {
                    "ObjA":
                    {
                        "ObjB":
                        {
                            "Field": "test_value_extended"
                        }
                    }
                }
            })"); // Shall pass
    result = op(event);
    ASSERT_TRUE(result);
}

// Check different types not string
TEST(opBuilderHelperStringContains, NotFoundDifferentTypes)
{
    auto tuple = std::make_tuple(
        std::string {"/sourceField"}, std::string {"contains"}, std::vector<std::string> {"$reference"});

    auto op = bld::opBuilderHelperStringContains(tuple)->getPtr<Term<EngineOp>>()->getFn();

    // Bool
    auto event = std::make_shared<json::Json>(
        R"({"sourceField":true,
        "reference":"AAA"})");
    auto result = op(event);
    ASSERT_FALSE(result);

    // Number
    event = std::make_shared<json::Json>(
        R"({"sourceField":1234,
        "reference":"AAA"})");
    result = op(event);
    ASSERT_FALSE(result);

    // Null
    event = std::make_shared<json::Json>(
        R"({"sourceField":null,
        "reference":"AAA"})");
    result = op(event);
    ASSERT_FALSE(result);

    // Array
    event = std::make_shared<json::Json>(
        R"({"sourceField": [
            "valueAAA",
            "valueB"
        ],
        "reference":"AAA"})");
    result = op(event);
    ASSERT_FALSE(result);

    // Object
    event = std::make_shared<json::Json>(
        R"({"sourceField":{
            "name": "AAA"
        },
        "reference":"AAA"})");
    result = op(event);
    ASSERT_FALSE(result);
}
