#include "environment_test.hpp"
#include <gtest/gtest.h>

#include <filesystem>
#include <stdexcept>

#include "builder/builder.hpp"
#include "builder/environment.hpp"
#include "builder/register.hpp"
#include "builder/registry.hpp"

using namespace builder;
using namespace builder::internals;
using namespace base;

class EnvironmentTest : public ::testing::Test
{
    void SetUp() override
    {
        if (std::filesystem::exists(outputPath))
        {
            std::filesystem::remove(outputPath);
        }
    }

    void TearDown() override
    {
        if (std::filesystem::exists(outputPath))
        {
            std::filesystem::remove(outputPath);
        }
    }
};

TEST_F(EnvironmentTest, GetAssetType)
{
    ASSERT_EQ(getAssetType(DECODERS), Asset::Type::DECODER);
    ASSERT_EQ(getAssetType(RULES), Asset::Type::RULE);
    ASSERT_EQ(getAssetType(OUTPUTS), Asset::Type::OUTPUT);
    ASSERT_EQ(getAssetType(FILTERS), Asset::Type::FILTER);
}

TEST_F(EnvironmentTest, DefaultConstructor)
{
    ASSERT_NO_THROW(Environment env);
}

TEST_F(EnvironmentTest, GetName)
{
    Environment env;
    ASSERT_NO_THROW(env.name());
}

TEST_F(EnvironmentTest, GetAssets)
{
    Environment env;
    ASSERT_NO_THROW(auto& assets = env.assets());
    ASSERT_NO_THROW(const auto& assets = env.assets());
}

TEST_F(EnvironmentTest, OneDecoderEnvironment)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson =
        std::get<json::Json>(storeRead->get(base::Name("environment/oneDecEnv/version")));
    ASSERT_NO_THROW(Environment(envJson, storeRead, registry));
    auto env = Environment(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "environment/oneDecEnv/version");
    ASSERT_EQ(env.assets().size(), 1);
    ASSERT_NO_THROW(env.getExpression());
    auto expr = env.getExpression();
    ASSERT_TRUE(expr->isChain());
    ASSERT_EQ(expr->getPtr<Operation>()->getOperands().size(), 1);

    auto decoderGraphExpr = expr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(decoderGraphExpr->isOr());
    ASSERT_EQ(decoderGraphExpr->getPtr<Operation>()->getOperands().size(), 1);

    auto decoderExpr = decoderGraphExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(decoderExpr->isImplication());
    ASSERT_EQ(decoderExpr->getName(), "decoder/decoder1/version");
}

TEST_F(EnvironmentTest, OneRuleEnvironment)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson = std::get<json::Json>(
        storeRead->get(base::Name {"environment/oneRuleEnv/version"}));
    ASSERT_NO_THROW(Environment(envJson, storeRead, registry));
    auto env = Environment(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "environment/oneRuleEnv/version");
    ASSERT_EQ(env.assets().size(), 1);
    ASSERT_NO_THROW(env.getExpression());
    auto expr = env.getExpression();
    ASSERT_TRUE(expr->isChain());
    ASSERT_EQ(expr->getPtr<Operation>()->getOperands().size(), 1);

    auto ruleGraphExpr = expr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(ruleGraphExpr->isBroadcast());
    ASSERT_EQ(ruleGraphExpr->getPtr<Operation>()->getOperands().size(), 1);

    auto ruleExpr = ruleGraphExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(ruleExpr->isImplication());
    ASSERT_EQ(ruleExpr->getName(), "rule/rule1/version");
}

TEST_F(EnvironmentTest, OneOutputEnvironment)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson = std::get<json::Json>(
        storeRead->get(base::Name {"environment/oneOutEnv/version"}));
    ASSERT_NO_THROW(Environment(envJson, storeRead, registry));
    auto env = Environment(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "environment/oneOutEnv/version");
    ASSERT_EQ(env.assets().size(), 1);
    ASSERT_NO_THROW(env.getExpression());
    auto expr = env.getExpression();
    ASSERT_TRUE(expr->isChain());
    ASSERT_EQ(expr->getPtr<Operation>()->getOperands().size(), 1);

    auto outGraphExpr = expr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(outGraphExpr->isBroadcast());
    ASSERT_EQ(outGraphExpr->getPtr<Operation>()->getOperands().size(), 1);

    auto outExpr = outGraphExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(outExpr->isImplication());
    ASSERT_EQ(outExpr->getName(), "output/output1/version");
}

TEST_F(EnvironmentTest, OneFilterEnvironment)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson = std::get<json::Json>(
        storeRead->get(base::Name {"environment/oneFilEnv/version"}));
    ASSERT_THROW(Environment(envJson, storeRead, registry), std::runtime_error);
}

TEST_F(EnvironmentTest, OrphanAsset)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson = std::get<json::Json>(
        storeRead->get(base::Name {"environment/orphanAssetEnv/version"}));
    ASSERT_THROW(Environment(envJson, storeRead, registry), std::runtime_error);
}

TEST_F(EnvironmentTest, OrphanFilter)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson = std::get<json::Json>(
        storeRead->get(base::Name {"environment/orphanFilterEnv/version"}));
    ASSERT_THROW(Environment(envJson, storeRead, registry), std::runtime_error);
}

TEST_F(EnvironmentTest, CompleteEnvironment)
{
    auto registry = std::make_shared<Registry>();
    registerBuilders(registry);
    auto storeRead = std::make_shared<FakeStoreRead>();
    auto envJson = std::get<json::Json>(
        storeRead->get(base::Name {"environment/completeEnv/version"}));
    ASSERT_NO_THROW(Environment(envJson, storeRead, registry));
    auto env = Environment(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "environment/completeEnv/version");
    ASSERT_EQ(env.assets().size(), 11);
    ASSERT_NO_THROW(env.getExpression());
    auto expr = env.getExpression();
    ASSERT_TRUE(expr->isChain());
    ASSERT_EQ(expr->getPtr<Operation>()->getOperands().size(), 3);

    // Decoder graph
    auto decoderGraphExpr = expr->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(decoderGraphExpr->isOr());
    ASSERT_EQ(decoderGraphExpr->getName(), "decodersInput");
    ASSERT_EQ(decoderGraphExpr->getPtr<Operation>()->getOperands().size(), 3);
    // Decoder 1 subgraph
    auto decoder1Pos = std::find_if(
        decoderGraphExpr->getPtr<Operation>()->getOperands().begin(),
        decoderGraphExpr->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder1/versionNode"; });
    ASSERT_FALSE(decoder1Pos
                 == decoderGraphExpr->getPtr<Operation>()->getOperands().end());
    auto assetNodeExpr = *decoder1Pos;
    ASSERT_TRUE(assetNodeExpr->isImplication());
    ASSERT_EQ(assetNodeExpr->getPtr<Operation>()->getOperands().size(), 2);
    auto childrenNode = assetNodeExpr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(childrenNode->isOr());
    ASSERT_EQ(childrenNode->getPtr<Operation>()->getOperands().size(), 1);
    // Decoder 1
    auto assetExpr = assetNodeExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_EQ(assetExpr->getName(), "decoder/decoder1/version");
    // Filter 1
    auto filterExpr = childrenNode->getPtr<Operation>()->getOperands()[0];
    ASSERT_TRUE(filterExpr->isImplication());
    ASSERT_EQ(filterExpr->getName(), "filter/filter1/versionNode");
    ASSERT_EQ(filterExpr->getPtr<Operation>()->getOperands().size(), 2);
    ASSERT_EQ(filterExpr->getPtr<Operation>()->getOperands()[0]->getName(),
              "filter/filter1/version");
    childrenNode = filterExpr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(childrenNode->isOperation());
    ASSERT_EQ(childrenNode->getPtr<Operation>()->getOperands().size(), 2);
    // Decoder 1_1
    auto decoder1_1Pos = std::find_if(
        childrenNode->getPtr<Operation>()->getOperands().begin(),
        childrenNode->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder1_1/version"; });
    ASSERT_FALSE(decoder1_1Pos == childrenNode->getPtr<Operation>()->getOperands().end());
    // Decoder 1_2
    auto decoder1_2Pos = std::find_if(
        childrenNode->getPtr<Operation>()->getOperands().begin(),
        childrenNode->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder1_2/version"; });
    ASSERT_FALSE(decoder1_2Pos == childrenNode->getPtr<Operation>()->getOperands().end());
    // Decoder 2 subgraph
    auto decoder2Pos = std::find_if(
        decoderGraphExpr->getPtr<Operation>()->getOperands().begin(),
        decoderGraphExpr->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder2/versionNode"; });
    ASSERT_FALSE(decoder2Pos
                 == decoderGraphExpr->getPtr<Operation>()->getOperands().end());
    assetNodeExpr = *decoder2Pos;
    ASSERT_TRUE(assetNodeExpr->isImplication());
    ASSERT_EQ(assetNodeExpr->getPtr<Operation>()->getOperands().size(), 2);
    childrenNode = assetNodeExpr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(childrenNode->isOperation());
    ASSERT_EQ(childrenNode->getPtr<Operation>()->getOperands().size(), 1);
    // Decoder 2
    assetExpr = assetNodeExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_EQ(assetExpr->getName(), "decoder/decoder2/version");
    // Decoder 23_1
    auto decoder23_1Pos = std::find_if(
        childrenNode->getPtr<Operation>()->getOperands().begin(),
        childrenNode->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder23_1/version"; });
    ASSERT_FALSE(decoder23_1Pos
                 == childrenNode->getPtr<Operation>()->getOperands().end());
    // Decoder 3 subgraph
    auto decoder3Pos = std::find_if(
        decoderGraphExpr->getPtr<Operation>()->getOperands().begin(),
        decoderGraphExpr->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder3/versionNode"; });
    ASSERT_FALSE(decoder3Pos
                 == decoderGraphExpr->getPtr<Operation>()->getOperands().end());
    assetNodeExpr = *decoder3Pos;
    ASSERT_TRUE(assetNodeExpr->isImplication());
    ASSERT_EQ(assetNodeExpr->getPtr<Operation>()->getOperands().size(), 2);
    childrenNode = assetNodeExpr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(childrenNode->isOperation());
    ASSERT_EQ(childrenNode->getPtr<Operation>()->getOperands().size(), 1);
    // Decoder 3
    assetExpr = assetNodeExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_EQ(assetExpr->getName(), "decoder/decoder3/version");
    // Decoder 23_1
    decoder23_1Pos = std::find_if(
        childrenNode->getPtr<Operation>()->getOperands().begin(),
        childrenNode->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "decoder/decoder23_1/version"; });
    ASSERT_FALSE(decoder23_1Pos
                 == childrenNode->getPtr<Operation>()->getOperands().end());

    // Rule graph
    auto ruleGraphExpr = expr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(ruleGraphExpr->isBroadcast());
    ASSERT_EQ(ruleGraphExpr->getName(), "rulesInput");
    ASSERT_EQ(ruleGraphExpr->getPtr<Operation>()->getOperands().size(), 2);
    // Rule 1 subgraph
    auto rule1Pos = std::find_if(
        ruleGraphExpr->getPtr<Operation>()->getOperands().begin(),
        ruleGraphExpr->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "rule/rule1/versionNode"; });
    ASSERT_FALSE(rule1Pos == ruleGraphExpr->getPtr<Operation>()->getOperands().end());
    assetNodeExpr = *rule1Pos;
    ASSERT_TRUE(assetNodeExpr->isImplication());
    ASSERT_EQ(assetNodeExpr->getPtr<Operation>()->getOperands().size(), 2);
    childrenNode = assetNodeExpr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(childrenNode->isOperation());
    ASSERT_EQ(childrenNode->getPtr<Operation>()->getOperands().size(), 1);
    // Rule 1
    assetExpr = assetNodeExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_EQ(assetExpr->getName(), "rule/rule1/version");
    // Rule 1_1
    assetExpr = childrenNode->getPtr<Operation>()->getOperands()[0];
    ASSERT_EQ(assetExpr->getName(), "rule/rule1_1/version");
    // Rule 2
    auto rule2Pos = std::find_if(
        ruleGraphExpr->getPtr<Operation>()->getOperands().begin(),
        ruleGraphExpr->getPtr<Operation>()->getOperands().end(),
        [](const auto& op) { return op->getName() == "rule/rule2/version"; });
    ASSERT_FALSE(rule2Pos == ruleGraphExpr->getPtr<Operation>()->getOperands().end());

    // Output graph
    auto outputGraphExpr = expr->getPtr<Operation>()->getOperands()[2];
    ASSERT_TRUE(outputGraphExpr->isBroadcast());
    ASSERT_EQ(outputGraphExpr->getName(), "outputsInput");
    ASSERT_EQ(outputGraphExpr->getPtr<Operation>()->getOperands().size(), 1);
    // Output 1 subgraph
    assetExpr = outputGraphExpr->getPtr<Operation>()->getOperands()[0];
    ASSERT_EQ(assetExpr->getName(), "output/output1/version");
}
