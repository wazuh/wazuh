#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/opBuilderLogqlParser.hpp"

using namespace builder::internals::builders;
using namespace json;
using namespace base;

TEST(OperationBuilderLogqlParserTest, Builds)
{
    Json doc = Json {R"([
        {"field": "<field>"}
    ])"};
    ASSERT_NO_THROW(opBuilderLogqlParser(doc));
}

TEST(OperationBuilderLogqlParserTest, NotJson)
{
    ASSERT_THROW(opBuilderLogqlParser(true), std::runtime_error);
}

TEST(OperationBuilderLogqlParserTest, NotArray)
{
    Json doc = Json {R"(
        {"field": "<field>"}
    )"};
    ASSERT_THROW(opBuilderLogqlParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogqlParserTest, EmptyArray)
{
    Json doc = Json {R"([])"};
    ASSERT_THROW(opBuilderLogqlParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogqlParserTest, ItemNotObject)
{
    Json doc = Json {R"([
        "field"
    ])"};
    ASSERT_THROW(opBuilderLogqlParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogqlParserTest, ItemWrongObjectSize)
{
    Json doc = Json {R"([
        {"field": "<field>", "other":1}
    ])"};
    ASSERT_THROW(opBuilderLogqlParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogqlParserTest, WrongLogqlString)
{
    Json doc = Json {R"([
        {"field": "<field"}
    ])"};
    ASSERT_THROW(opBuilderLogqlParser(doc), std::runtime_error);
}

TEST(OperationBuilderLogqlParserTest, BuildsCorrectExpression)
{
    Json doc = Json {R"([
        {"field": "<field>"}
    ])"};

    auto expression = opBuilderLogqlParser(doc);
    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isOr());
    ASSERT_EQ(expression->getPtr<Operation>()->getOperands().size(), 1);
    ASSERT_TRUE(expression->getPtr<Operation>()->getOperands()[0]->isTerm());
}
