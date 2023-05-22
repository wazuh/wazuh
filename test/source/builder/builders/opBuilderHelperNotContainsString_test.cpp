#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperNotContainsString, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_not_contains"},
                                 std::vector<std::string> {"1", "$ref", "3"},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperNotContainsString, tuple));
}

TEST(OpBuilderHelperNotContainsString, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_not_contains"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderHelperNotContainsString, tuple), std::runtime_error);
}

TEST(OpBuilderHelperNotContainsString, Success)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_not_contains"},
                                 std::vector<std::string> {"1", "$ref", "3"},
                                 std::make_shared<defs::mocks::FailDef>());
    auto event1 = std::make_shared<json::Json>(R"({"field": ["0"]})");
    auto event2 = std::make_shared<json::Json>(R"({"field": ["4","5","6"], "ref": "2"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": [2]})");

    auto op = std::apply(bld::opBuilderHelperNotContainsString, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    result = op(event2);
    ASSERT_TRUE(result.success());
    result = op(event3);
    ASSERT_TRUE(result.success());
}

TEST(OpBuilderHelperNotContainsString, FailureParametersNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_not_contains"},
                                 std::vector<std::string> {"1", "$ref", "3"},
                                 std::make_shared<defs::mocks::FailDef>());
    auto event1 = std::make_shared<json::Json>(R"({"field": ["1"]})");
    auto event2 = std::make_shared<json::Json>(R"({"field": ["0","5","2"], "ref": "2"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": ["3"]})");

    auto op = std::apply(bld::opBuilderHelperNotContainsString, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
    result = op(event2);
    ASSERT_FALSE(result.success());
    result = op(event3);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperNotContainsString, FailureTargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_not_contains"},
                                 std::vector<std::string> {"1"},
                                 std::make_shared<defs::mocks::FailDef>());
    auto event = std::make_shared<json::Json>(R"({"Otherfield": ["1"]})");

    auto op = std::apply(bld::opBuilderHelperNotContainsString, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperNotContainsString, FailureTargetNotArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_not_contains"},
                                 std::vector<std::string> {"1"},
                                 std::make_shared<defs::mocks::FailDef>());
    auto event = std::make_shared<json::Json>(R"({"field": "1"})");

    auto op = std::apply(bld::opBuilderHelperNotContainsString, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}
