#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperMerge, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$ref"});

    ASSERT_NO_THROW(bld::opBuilderHelperMerge(tuple));
}

TEST(OpBuilderHelperMerge, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$ref", "$ref2"});

    ASSERT_THROW(bld::opBuilderHelperMerge(tuple), std::runtime_error);
}

TEST(OpBuilderHelperMerge, WrongTypeParameter)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"ref"});

    ASSERT_THROW(bld::opBuilderHelperMerge(tuple), std::runtime_error);
}

TEST(OpBuilderHelperMerge, MergeObjectsRoot)
{
    auto tuple = std::make_tuple(std::string {""},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field1": "value1",
       "field3": "value3",
       "to_merge": {
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

TEST(OpBuilderHelperMerge, MergeObjectsNested)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": {
          "field1": "value1",
          "field3": "value3"
       },
       "to_merge": {
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

TEST(OpBuilderHelperMerge, MergeArraysNested)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": [
          "value1",
          "value3"
       ],
       "to_merge": [
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

TEST(OpBuilderHelperMerge, FailMergeDifferentTypes)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": {
          "key1": "value1",
          "key3": "value3"
       },
       "to_merge": [
          "value1",
          "value2"
       ]
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);

    tuple = std::make_tuple(std::string {"/to_merge"},
                            std::string {"+merge"},
                            std::vector<std::string> {"$field"});
    op = bld::opBuilderHelperMerge(tuple);
    result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(OpBuilderHelperMerge, FailTargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "to_merge": {
          "key1": "value1",
          "key3": "value3"
       }
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(OpBuilderHelperMerge, FailReferenceNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": {
          "key1": "value1",
          "key3": "value3"
       }
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST(OpBuilderHelperMerge, FailNotObjNotArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge"},
                                 std::vector<std::string> {"$to_merge"});

    auto op = bld::opBuilderHelperMerge(tuple);
    auto event = std::make_shared<json::Json>(R"({
       "field": "value",
       "to_merge": "value"
    })");

    auto result = op->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}
