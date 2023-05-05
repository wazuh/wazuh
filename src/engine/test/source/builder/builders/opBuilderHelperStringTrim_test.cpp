
#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperStringTrim, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"begin", "t"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperStringTrim, tuple));
}

TEST(opBuilderHelperStringTrim, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"begin"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderHelperStringTrim, tuple), std::runtime_error);
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"begin", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": "--test"})");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_begin_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"begin", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "--test"})");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_end_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"end", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "test--"})");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_both_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"both", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "--test--"})");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"begin", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": "--test",
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_begin_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"begin", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "--test",
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_end_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"end", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "test--",
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperStringTrim, Exec_string_trim_both_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"trim"},
                                 std::vector<std::string> {"both", "-"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "--test--",
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperStringTrim, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}
