
#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperRegexExtract, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$_field", "(regex)"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperRegexExtract, tuple));
}

TEST(opBuilderHelperRegexExtract, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderHelperRegexExtract, tuple), std::runtime_error);
}

TEST(opBuilderHelperRegexExtract, Builds_incorrect_parameter_type)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"test", "(regex)"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderHelperRegexExtract, tuple), std::runtime_error);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$fieldcheck", "(test)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": "This is a test."})");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$otherfield", "(test)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": "This is a test."})");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_fail)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$otherfield", "(regex)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This is a test."})");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$otherfield", "(test)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This is a test."})");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_1.fieldcheck", "(test)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": "This is a test.",
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_2/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_1.field2check", "(test)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_fail)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_2.field2check", "(regex)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "This is a test.",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_2.field2check", "(test)"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "This is a test.",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperRegexExtract, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}
