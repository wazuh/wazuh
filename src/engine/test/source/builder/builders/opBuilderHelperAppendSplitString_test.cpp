#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperAppendSplitString, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+split"},
                                 std::vector<std::string> {"$ref", ","});

    ASSERT_NO_THROW(bld::opBuilderHelperAppendSplitString(tuple));
}

TEST(OpBuilderHelperAppendSplitString, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+split"},
                                 std::vector<std::string> {});
    ASSERT_THROW(bld::opBuilderHelperAppendSplitString(tuple), std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+split"},
                            std::vector<std::string> {"$ref"});
    ASSERT_THROW(bld::opBuilderHelperAppendSplitString(tuple), std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+split"},
                            std::vector<std::string> {"$ref", ",", "other"});
    ASSERT_THROW(bld::opBuilderHelperAppendSplitString(tuple), std::runtime_error);
}

TEST(OpBuilderHelperAppendSplitString, NotRefParameter0)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+split"},
                                 std::vector<std::string> {"1", ","});
    ASSERT_THROW(bld::opBuilderHelperAppendSplitString(tuple), std::runtime_error);
}

TEST(OpBuilderHelperAppendSplitString, NotCharParameter1)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+split"},
                                 std::vector<std::string> {"$ref", "tw"});
    ASSERT_THROW(bld::opBuilderHelperAppendSplitString(tuple), std::runtime_error);
}

TEST(OpBuilderHelperAppendSplitString, Exec_append_split)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+split"},
                                 std::vector<std::string> {"$ref", ","});
    auto event1 = std::make_shared<json::Json>(R"({"field": [], "ref": "1,2,3"})");
    auto event2 = std::make_shared<json::Json>(R"({"field": "2", "ref": "1,2,3"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": ["0"], "ref": "1,2,3"})");
    auto op =
        bld::opBuilderHelperAppendSplitString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    std::vector<json::Json> array;
    ASSERT_NO_THROW(array = result.payload()->getArray("/field").value());
    ASSERT_TRUE(array.size() == 3);
    for (auto i = 1; i < 4; i++)
    {
        ASSERT_TRUE(array[i - 1].getString() == std::to_string(i));
    }

    result = op(event2);
    ASSERT_TRUE(result.success());
    ASSERT_NO_THROW(array = result.payload()->getArray("/field").value());
    ASSERT_TRUE(array.size() == 3);
    for (auto i = 1; i < 4; i++)
    {
        ASSERT_TRUE(array[i - 1].getString() == std::to_string(i));
    }

    result = op(event3);
    ASSERT_TRUE(result.success());
    ASSERT_NO_THROW(array = result.payload()->getArray("/field").value());
    ASSERT_TRUE(array.size() == 4);
    for (auto i = 0; i < 4; i++)
    {
        ASSERT_TRUE(array[i].getString() == std::to_string(i));
    }
}

TEST(OpBuilderHelperAppendSplitString, Exec_append_split_fail_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+split"},
                                 std::vector<std::string> {"$ref", ","});
    auto event1 = std::make_shared<json::Json>(R"({"field": [], "ref1": "1,2,3"})");

    auto op =
        bld::opBuilderHelperAppendSplitString(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}
