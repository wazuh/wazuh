#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperNotExists, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"exists"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperNotExists(tuple));
}

TEST(opBuilderHelperNotExists, Exec_not_exists_false)
{
    auto tuple = std::make_tuple(
        std::string {"/fieldcheck"}, std::string {"exists"}, std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": "valid"})");

    auto op = bld::opBuilderHelperNotExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperNotExists, Exec_not_exists_true)
{
    auto tuple = std::make_tuple(
        std::string {"/fieldcheck"}, std::string {"exists"}, std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "valid"})");

    auto op = bld::opBuilderHelperNotExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperNotExists, Exec_multilevel_false)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/fieldcheck"},
                                 std::string {"exists"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": 11,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperNotExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperNotExists, Exec_multilevel_true)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/fieldcheck"},
                                 std::string {"exists"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperNotExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}
