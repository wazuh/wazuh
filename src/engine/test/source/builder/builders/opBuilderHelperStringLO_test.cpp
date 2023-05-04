
#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperStringLO, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperStringLO, tuple));
}

TEST(opBuilderHelperStringLO, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderHelperStringLO, tuple), std::runtime_error);
}

TEST(opBuilderHelperStringLO, Exec_string_LO_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": 10})");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
}

TEST(opBuilderHelperStringLO, Exec_string_LO_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringLO, Exec_string_LO_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"$otherfield"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": 10})");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringLO, Exec_string_LO_ref_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"$otherfield"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "TEST"})");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringLO, Exec_string_LO_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"TEST"},
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

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
}

TEST(opBuilderHelperStringLO, Exec_string_LO_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperStringLO, Exec_string_LO_multilevel_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"$otherfield"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": 10})");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringLO, Exec_string_LO_multilevel_ref_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"downcase"},
                                 std::vector<std::string> {"$parentObjt_2.field2check"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "TEST",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = std::apply(bld::opBuilderHelperStringLO, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}
