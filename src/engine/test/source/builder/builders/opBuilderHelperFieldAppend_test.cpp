#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

TEST(opBuilderHelperFieldAppend, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$ref"});

    ASSERT_NO_THROW(bld::opBuilderHelperFieldAppend(tuple));
}

TEST(opBuilderHelperFieldAppend, WrongSizeParameters)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$ref", "$ref2"});

    ASSERT_THROW(bld::opBuilderHelperFieldAppend(tuple), std::runtime_error);
}

TEST(opBuilderHelperFieldAppend, WrongTypeParameter)
{
    auto tuple = std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"ref"});

    ASSERT_THROW(bld::opBuilderHelperFieldAppend(tuple), std::runtime_error);
}

TEST(opBuilderHelperFieldAppend, AppendObjectsRoot)
{
    auto tuple = std::make_tuple(std::string {""}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field1": "value1",
       "field3": "value3",
       "to_:append": {
          "field1": "new_value1",
          "field2": "value2"
       }
    })");

    json::Json expected {R"({
       "field1": "new_value1",
       "field2": "value2",
       "field3": "value3"
    })"};

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, *result.payload());
}

TEST(opBuilderHelperFieldAppend, AppendObjectsNested)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": {
          "field1": "value1",
          "field3": "value3"
       },
       "to_:append": {
          "field1": "new_value1",
          "field2": "value2"
       }
    })");

    json::Json expected {R"({
       "field": {
          "field1": "new_value1",
          "field2": "value2",
          "field3": "value3"
       }
    })"};

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, *result.payload());
}

TEST(opBuilderHelperFieldAppend, AppendArraysNested)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": [
          "value1",
          "value3"
       ],
       "to_:append": [
          "value1",
          "value2"
       ]
    })");

    json::Json expected {R"({
       "field": [
          "value1",
          "value3",
          "value2"
       ]
    })"};

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(expected, *result.payload());
}

TEST(opBuilderHelperFieldAppend, FailAppendDifferentTypes)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": {
          "key1": "value1",
          "key3": "value3"
       },
       "to_:append": [
          "value1",
          "value2"
       ]
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);

    tuple = std::make_tuple(std::string {"/to_:append"}, std::string {"+ef_:append"}, std::vector<std::string> {"$field"});
    op = bld::opBuilderHelperFieldAppend(tuple);
    result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperFieldAppend, FailTargetNotFound)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "to_:append": {
          "key1": "value1",
          "key3": "value3"
       }
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperFieldAppend, FailReferenceNotFound)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": {
          "key1": "value1",
          "key3": "value3"
       }
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperFieldAppend, FailNotObjNotArray)
{
    auto tuple =
        std::make_tuple(std::string {"/field"}, std::string {"+ef_:append"}, std::vector<std::string> {"$to_:append"});

    auto op = bld::opBuilderHelperFieldAppend(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": "value",
       "to_:append": "value"
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}
