#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperAppend, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_append"},
                                 std::vector<std::string> {"1", "$ref", "3"});

    ASSERT_NO_THROW(bld::opBuilderHelperAppend(tuple));
}

TEST(OpBuilderHelperAppend, EmptyParameters)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"+array_append"}, std::vector<std::string> {});
    ASSERT_THROW(bld::opBuilderHelperAppend(tuple), std::runtime_error);
}

TEST(OpBuilderHelperAppend, Exec_append_literals)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_append"},
                                 std::vector<std::string> {"1", "2", "3"});
    auto event1 = std::make_shared<json::Json>(R"({"field": []})");
    auto event2 = std::make_shared<json::Json>(R"({"field": "2"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": ["0"]})");
    auto op = bld::opBuilderHelperAppend(tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(OpBuilderHelperAppend, Exec_append_refs)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_append"},
                                 std::vector<std::string> {"$ref1", "$ref2", "$ref3"});
    auto event1 = std::make_shared<json::Json>(
        R"({"field": [], "ref1": "1", "ref2": "2", "ref3": "3"})");
    auto event2 = std::make_shared<json::Json>(
        R"({"field": "2", "ref1": "1", "ref2": "2", "ref3": "3"})");
    auto event3 = std::make_shared<json::Json>(
        R"({"field": ["0"], "ref1": "1", "ref2": "2", "ref3": "3"})");
    auto op = bld::opBuilderHelperAppend(tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(OpBuilderHelperAppend, Exec_append_refs_literals)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_append"},
                                 std::vector<std::string> {"$ref1", "2", "$ref3"});
    auto event1 =
        std::make_shared<json::Json>(R"({"field": [], "ref1": "1", "ref3": "3"})");
    auto event2 =
        std::make_shared<json::Json>(R"({"field": "2", "ref1": "1", "ref3": "3"})");
    auto event3 =
        std::make_shared<json::Json>(R"({"field": ["0"], "ref1": "1", "ref3": "3"})");
    auto op = bld::opBuilderHelperAppend(tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(OpBuilderHelperAppend, Exec_append_fail_refs)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_append"},
                                 std::vector<std::string> {"$ref1", "2", "$ref3"});
    auto event1 =
        std::make_shared<json::Json>(R"({"field": [], "ref11": "1", "ref3": "3"})");
    auto event2 =
        std::make_shared<json::Json>(R"({"field": "2", "$ref1": 1, "ref3": "3"})");

    auto op = bld::opBuilderHelperAppend(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());

    result = op(event2);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperAppend, Exec_append_use_case)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_append"},
                                 std::vector<std::string> {"$ref1", "literal", "$ref2"});
    auto event1 = std::make_shared<json::Json>(R"({"field": [], "ref1": [1], "ref2": {"a": 2}})");

    auto op = bld::opBuilderHelperAppend(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());

    auto field = result.payload()->getArray("/field");
    ASSERT_TRUE(field.has_value());
    ASSERT_TRUE(field.value().size() == 3);
    ASSERT_TRUE(field.value()[0].getArray().value().size() == 1);
    ASSERT_TRUE(field.value()[0].getArray().value()[0].getInt().value() == 1);
    ASSERT_TRUE(field.value()[1].getString().value() == "literal");
    ASSERT_TRUE(field.value()[2].getObject().value().size() == 1);
    ASSERT_TRUE(std::get<0>(field.value()[2].getObject().value()[0]) == "a");
    ASSERT_TRUE(std::get<1>(field.value()[2].getObject().value()[0]).getInt().value() == 2);
}
