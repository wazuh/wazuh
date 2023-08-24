#include "policy_test.hpp"
#include <gtest/gtest.h>

#include <filesystem>
#include <stdexcept>

#include <schemf/emptySchema.hpp>
#include <store/mockStore.hpp>

#include "builder/builder.hpp"
#include "builder/policy.hpp"
#include "builder/register.hpp"
#include "builder/registry.hpp"

using namespace builder;
using namespace builder::internals;
using namespace base;
using namespace store::mocks;

class PolicyTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockStoreRead> storeRead;

    void SetUp() override
    {
        storeRead = std::make_shared<MockStoreRead>();

        EXPECT_CALL(*storeRead, readDoc(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name) -> base::RespOrError<store::Doc>
                {
                    if (name.parts()[0] == "decoder")
                    {
                        return json::Json {decoders[name.fullName()]};
                    }
                    else if (name.parts()[0] == "rule")
                    {
                        return json::Json {rules[name.fullName()]};
                    }
                    else if (name.parts()[0] == "filter")
                    {
                        return json::Json {filters[name.fullName()]};
                    }
                    else if (name.parts()[0] == "output")
                    {
                        return json::Json {outputs[name.fullName()]};
                    }
                    else if (name.parts()[0] == "policy")
                    {
                        return json::Json {policys[name.parts()[1]]};
                    }
                    else
                    {
                        throw std::runtime_error("Unknown asset name.parts()[0]: " + name.parts()[0]);
                    }
                }));
        
        // This is done so any asset does not default to parent integrations
        EXPECT_CALL(*storeRead, getNamespace(testing::_))
            .WillRepeatedly(testing::Return(storeGetNamespaceError()));

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

TEST_F(PolicyTest, GetAssetType)
{
    ASSERT_EQ(getAssetType(DECODERS), Asset::Type::DECODER);
    ASSERT_EQ(getAssetType(RULES), Asset::Type::RULE);
    ASSERT_EQ(getAssetType(OUTPUTS), Asset::Type::OUTPUT);
    ASSERT_EQ(getAssetType(FILTERS), Asset::Type::FILTER);
}

TEST_F(PolicyTest, DefaultConstructor)
{
    ASSERT_NO_THROW(Policy env);
}

TEST_F(PolicyTest, GetName)
{
    Policy env;
    ASSERT_NO_THROW(env.name());
}

TEST_F(PolicyTest, GetAssets)
{
    Policy env;
    ASSERT_NO_THROW(auto& assets = env.assets());
    ASSERT_NO_THROW(const auto& assets = env.assets());
}

TEST_F(PolicyTest, OneDecoderPolicy)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    registerHelperBuilders(helperRegistry);
    builder::internals::dependencies deps {};
    deps.helperRegistry = helperRegistry;
    deps.schema = schemf::mocks::EmptySchema::create();
    registerBuilders(registry, deps);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name("policy/oneDecEnv/version")));
    ASSERT_NO_THROW(Policy(envJson, storeRead, registry));
    auto env = Policy(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "policy/oneDecEnv/version");
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

TEST_F(PolicyTest, OneRulePolicy)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    registerHelperBuilders(helperRegistry);
    builder::internals::dependencies deps {};
    deps.helperRegistry = helperRegistry;
    deps.schema = schemf::mocks::EmptySchema::create();
    registerBuilders(registry, deps);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name {"policy/oneRuleEnv/version"}));
    ASSERT_NO_THROW(Policy(envJson, storeRead, registry));
    auto env = Policy(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "policy/oneRuleEnv/version");
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

TEST_F(PolicyTest, OneOutputPolicy)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    registerHelperBuilders(helperRegistry);
    builder::internals::dependencies deps {};
    deps.helperRegistry = helperRegistry;
    deps.schema = schemf::mocks::EmptySchema::create();
    registerBuilders(registry, deps);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name {"policy/oneOutEnv/version"}));
    ASSERT_NO_THROW(Policy(envJson, storeRead, registry));
    auto env = Policy(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "policy/oneOutEnv/version");
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

TEST_F(PolicyTest, OneFilterPolicy)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    registerHelperBuilders(helperRegistry);
    builder::internals::dependencies deps {};
    deps.helperRegistry = helperRegistry;
    deps.schema = schemf::mocks::EmptySchema::create();
    registerBuilders(registry, deps);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name {"policy/oneFilEnv/version"}));
    ASSERT_THROW(Policy(envJson, storeRead, registry), std::runtime_error);
}

TEST_F(PolicyTest, OrphanAsset)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    registerHelperBuilders(helperRegistry);
    builder::internals::dependencies deps {};
    deps.helperRegistry = helperRegistry;
    deps.schema = schemf::mocks::EmptySchema::create();
    registerBuilders(registry, deps);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name {"policy/orphanAssetEnv/version"}));
    ASSERT_THROW(Policy(envJson, storeRead, registry), std::runtime_error);
}

TEST_F(PolicyTest, OrphanFilter)
{
    GTEST_SKIP();
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    registerBuilders(registry);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name {"policy/orphanFilterEnv/version"}));
    ASSERT_THROW(Policy(envJson, storeRead, registry), std::runtime_error);
}

TEST_F(PolicyTest, CompletePolicy)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    registerHelperBuilders(helperRegistry);
    builder::internals::dependencies deps {};
    deps.helperRegistry = helperRegistry;
    deps.schema = schemf::mocks::EmptySchema::create();
    registerBuilders(registry, deps);

    auto envJson = std::get<json::Json>(storeRead->readDoc(base::Name {"policy/completeEnv/version"}));
    ASSERT_NO_THROW(Policy(envJson, storeRead, registry));
    auto env = Policy(envJson, storeRead, registry);
    ASSERT_EQ(env.name(), "policy/completeEnv/version");
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
    auto decoder1Pos = std::find_if(decoderGraphExpr->getPtr<Operation>()->getOperands().begin(),
                                    decoderGraphExpr->getPtr<Operation>()->getOperands().end(),
                                    [](const auto& op) { return op->getName() == "decoder/decoder1/versionNode"; });
    ASSERT_FALSE(decoder1Pos == decoderGraphExpr->getPtr<Operation>()->getOperands().end());
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
    ASSERT_EQ(filterExpr->getPtr<Operation>()->getOperands()[0]->getName(), "filter/filter1/version");
    childrenNode = filterExpr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(childrenNode->isOperation());
    ASSERT_EQ(childrenNode->getPtr<Operation>()->getOperands().size(), 2);
    // Decoder 1_1
    auto decoder1_1Pos = std::find_if(childrenNode->getPtr<Operation>()->getOperands().begin(),
                                      childrenNode->getPtr<Operation>()->getOperands().end(),
                                      [](const auto& op) { return op->getName() == "decoder/decoder1_1/version"; });
    ASSERT_FALSE(decoder1_1Pos == childrenNode->getPtr<Operation>()->getOperands().end());
    // Decoder 1_2
    auto decoder1_2Pos = std::find_if(childrenNode->getPtr<Operation>()->getOperands().begin(),
                                      childrenNode->getPtr<Operation>()->getOperands().end(),
                                      [](const auto& op) { return op->getName() == "decoder/decoder1_2/version"; });
    ASSERT_FALSE(decoder1_2Pos == childrenNode->getPtr<Operation>()->getOperands().end());
    // Decoder 2 subgraph
    auto decoder2Pos = std::find_if(decoderGraphExpr->getPtr<Operation>()->getOperands().begin(),
                                    decoderGraphExpr->getPtr<Operation>()->getOperands().end(),
                                    [](const auto& op) { return op->getName() == "decoder/decoder2/versionNode"; });
    ASSERT_FALSE(decoder2Pos == decoderGraphExpr->getPtr<Operation>()->getOperands().end());
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
    auto decoder23_1Pos = std::find_if(childrenNode->getPtr<Operation>()->getOperands().begin(),
                                       childrenNode->getPtr<Operation>()->getOperands().end(),
                                       [](const auto& op) { return op->getName() == "decoder/decoder23_1/version"; });
    ASSERT_FALSE(decoder23_1Pos == childrenNode->getPtr<Operation>()->getOperands().end());
    // Decoder 3 subgraph
    auto decoder3Pos = std::find_if(decoderGraphExpr->getPtr<Operation>()->getOperands().begin(),
                                    decoderGraphExpr->getPtr<Operation>()->getOperands().end(),
                                    [](const auto& op) { return op->getName() == "decoder/decoder3/versionNode"; });
    ASSERT_FALSE(decoder3Pos == decoderGraphExpr->getPtr<Operation>()->getOperands().end());
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
    decoder23_1Pos = std::find_if(childrenNode->getPtr<Operation>()->getOperands().begin(),
                                  childrenNode->getPtr<Operation>()->getOperands().end(),
                                  [](const auto& op) { return op->getName() == "decoder/decoder23_1/version"; });
    ASSERT_FALSE(decoder23_1Pos == childrenNode->getPtr<Operation>()->getOperands().end());

    // Rule graph
    auto ruleGraphExpr = expr->getPtr<Operation>()->getOperands()[1];
    ASSERT_TRUE(ruleGraphExpr->isBroadcast());
    ASSERT_EQ(ruleGraphExpr->getName(), "rulesInput");
    ASSERT_EQ(ruleGraphExpr->getPtr<Operation>()->getOperands().size(), 2);
    // Rule 1 subgraph
    auto rule1Pos = std::find_if(ruleGraphExpr->getPtr<Operation>()->getOperands().begin(),
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
    auto rule2Pos = std::find_if(ruleGraphExpr->getPtr<Operation>()->getOperands().begin(),
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
