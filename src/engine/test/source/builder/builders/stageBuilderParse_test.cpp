#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/opBuilderLogParser.hpp"
#include "builder/builders/stageBuilderParse.hpp"
#include "builder/registry.hpp"

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;


TEST(StageBuilderParseTest, Builds)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderLogParser, "parser.logpar");
    Json doc = Json {R"({
            "logpar":[
                {"~field": "<~field>"}
            ]
    })"};
    ASSERT_NO_THROW(getStageBuilderParse(registry)(doc));
}

TEST(StageBuilderParseTest, NotJson)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderLogParser, "parser.logpar");

    ASSERT_THROW(getStageBuilderParse(registry)(std::string {}), std::runtime_error);
}

TEST(StageBuilderParseTest, NotObject)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderLogParser, "parser.logpar");
    Json doc = Json {R"([
            {"logpar":[
                {"~field": "<~field>"}
            ]}
    ])"};
    ASSERT_THROW(getStageBuilderParse(registry)(doc), std::runtime_error);
}

TEST(StageBuilderParseTest, BuildsCorrectExpression)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(opBuilderLogParser, "parser.logpar");
    Json doc = Json {R"({
            "logpar":[
                {"~field": "<~field>"}
            ]
    })"};
    auto expression = getStageBuilderParse(registry)(doc);
    ASSERT_TRUE(expression->isOr());
    ASSERT_EQ(expression->getPtr<Operation>()->getOperands().size(), 1);
}
