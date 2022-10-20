#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/opBuilderLogParser.hpp"

using namespace builder::internals::builders;
using namespace json;
using namespace base;

TEST(OperationBuilderLogParserTest, Builds)
{
    Json doc = Json {R"([
        {"field": "<field>"}
    ])"};
    ASSERT_NO_THROW(opBuilderLogParser(doc));
}

TEST(OperationBuilderLogParserTest, NotJson)
{
    ASSERT_THROW(opBuilderLogParser(true), std::runtime_error);
}

TEST(OperationBuilderLogParserTest, NotArray)
{
    Json doc = Json {R"(
        {"field": "<field>"}
    )"};
    ASSERT_THROW(opBuilderLogParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogParserTest, EmptyArray)
{
    Json doc = Json {R"([])"};
    ASSERT_THROW(opBuilderLogParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogParserTest, ItemNotObject)
{
    Json doc = Json {R"([
        "field"
    ])"};
    ASSERT_THROW(opBuilderLogParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogParserTest, ItemWrongObjectSize)
{
    Json doc = Json {R"([
        {"field": "<field>", "other":1}
    ])"};
    ASSERT_THROW(opBuilderLogParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogParserTest, WrongLogparString)
{
    Json doc = Json {R"([
        {"field": "<field"}
    ])"};
    ASSERT_THROW(opBuilderLogParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogParserTest, BuildsCorrectExpression)
{
    Json doc = Json {R"([
        {"field": "<field>"}
    ])"};

    auto expression = opBuilderLogParser(doc);
    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isOr());
    ASSERT_EQ(expression->getPtr<Operation>()->getOperands().size(), 1);
    ASSERT_TRUE(expression->getPtr<Operation>()->getOperands()[0]->isTerm());
}
