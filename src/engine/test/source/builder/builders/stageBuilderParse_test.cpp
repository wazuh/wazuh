#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/opBuilderLogParser.hpp"
#include "builder/builders/stageBuilderParse.hpp"
#include "builder/registry.hpp"

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;

class StageBuilderParseTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Registry::registerBuilder(opBuilderLogParser, "parser.logpar");
    }

    void TearDown() override { Registry::clear(); }
};

TEST_F(StageBuilderParseTest, Builds)
{
    Json doc = Json {R"({
            "logpar":[
                {"~field": "<~field>"}
            ]
    })"};
    ASSERT_NO_THROW(stageBuilderParse(doc));
}

TEST_F(StageBuilderParseTest, NotJson)
{
    ASSERT_THROW(stageBuilderParse(std::string {}), std::runtime_error);
}

TEST_F(StageBuilderParseTest, NotObject)
{
    Json doc = Json {R"([
            {"logpar":[
                {"~field": "<~field>"}
            ]}
    ])"};
    ASSERT_THROW(stageBuilderParse(doc), std::runtime_error);
}

TEST_F(StageBuilderParseTest, BuildsCorrectExpression)
{
    Json doc = Json {R"({
            "logpar":[
                {"~field": "<~field>"}
            ]
    })"};
    auto expression = stageBuilderParse(doc);
    ASSERT_TRUE(expression->isOr());
    ASSERT_EQ(expression->getPtr<Operation>()->getOperands().size(), 1);
}
