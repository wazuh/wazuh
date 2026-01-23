#include "builders/baseBuilders_test.hpp"
#include "builders/stage/first_of.hpp"

using namespace builder::builders;

namespace
{
auto dummyCheckBuilder()
{
    return [](const json::Json& def, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return base::And::create("dummy-check", {});
    };
}

auto dummyOutputBuilder()
{
    return [](const json::Json& def, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return base::And::create("dummy-output", {});
    };
}

auto dummyStageBuilderThrow()
{
    return [](const json::Json& def, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        throw std::runtime_error("Dummy builder throw");
    };
}
} // namespace

namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    StageBuilderTest,
    testing::Values(
        // Invalid input types
        StageT(R"({})", firstOfBuilder, FAILURE()),
        StageT(R"(1)", firstOfBuilder, FAILURE()),
        StageT(R"(null)", firstOfBuilder, FAILURE()),
        StageT(R"("a")", firstOfBuilder, FAILURE()),
        // Empty array
        StageT(R"([])", firstOfBuilder, FAILURE()),
        // Invalid item structure - not an object
        StageT(R"([1])", firstOfBuilder, FAILURE()),
        StageT(R"(["string"])", firstOfBuilder, FAILURE()),
        StageT(R"([[]])", firstOfBuilder, FAILURE()),
        // Missing required keys
        StageT(R"([{}])", firstOfBuilder, FAILURE()),
        StageT(R"([{"check": []}])", firstOfBuilder, FAILURE()),
        StageT(R"([{"then": [{"file": []}]}])", firstOfBuilder, FAILURE()),
        // Invalid 'then' structure - not an array
        StageT(R"([{"check": [], "then": 1}])", firstOfBuilder, FAILURE()),
        StageT(R"([{"check": [], "then": "string"}])", firstOfBuilder, FAILURE()),
        StageT(R"([{"check": [], "then": {}}])", firstOfBuilder, FAILURE()),
        // Empty 'then' array
        StageT(R"([{"check": [], "then": []}])", firstOfBuilder, FAILURE()),
        // Invalid 'then' array items - not objects
        StageT(R"([{"check": [], "then": [1]}])", firstOfBuilder, FAILURE()),
        StageT(R"([{"check": [], "then": ["string"]}])", firstOfBuilder, FAILURE()),
        StageT(R"([{"check": [], "then": [[]]}])", firstOfBuilder, FAILURE()),
        // Empty object in 'then' array
        StageT(R"([{"check": [], "then": [{}]}])", firstOfBuilder, FAILURE()),
        // Multiple keys in 'then' array item (should only have one output type per item)
        StageT(R"([{"check": [], "then": [{"file": [], "wazuh-indexer": []}]}])", firstOfBuilder, FAILURE()),
        // Extra keys in item (should fail - only check and then are allowed)
        StageT(R"([{"check": [], "then": [{"file": []}], "extra": "key"}])", firstOfBuilder, FAILURE()),
        // Invalid item in middle of array
        StageT(
            R"([{"check": [], "then": [{"file": []}]}, {"invalid": "item"}, {"check": [], "then": [{"wazuh-indexer": []}]}])",
            firstOfBuilder,
            FAILURE()),
        // Incorrect order
        StageT(R"([{"then": [], "check": [{"file": []}]}])", firstOfBuilder, FAILURE()),
        // Output builder throws exception
        StageT(R"([{"check": [], "then": [{"file": []}]}])",
               firstOfBuilder,
               FAILURE(
                   [](const auto& mocks)
                   {
                       const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(stageRegistry, get("check")).WillOnce(testing::Return(dummyCheckBuilder()));
                       EXPECT_CALL(stageRegistry, get("file")).WillOnce(testing::Return(dummyStageBuilderThrow()));
                       return None {};
                   })),
        // Check builder throws exception
        StageT(R"([{"check": [], "then": [{"file": []}]}])",
               firstOfBuilder,
               FAILURE(
                   [](const auto& mocks)
                   {
                       const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(stageRegistry, get("check")).WillOnce(testing::Return(dummyStageBuilderThrow()));
                       return None {};
                   })),
        // Single valid item
        StageT(R"([{"check": [], "then": [{"file": []}]}])",
               firstOfBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(stageRegistry, get("check")).WillOnce(testing::Return(dummyCheckBuilder()));
                       EXPECT_CALL(stageRegistry, get("file")).WillOnce(testing::Return(dummyOutputBuilder()));
                       return base::Or::create("first_of",
                                               {base::Implication::create("first_of.item-0",
                                                                          base::And::create("dummy-check", {}),
                                                                          base::Broadcast::create("first_of.item-0.then",
                                                                          {base::And::create("dummy-output", {})}))});
                   })),
        // Single valid item with wazuh-indexer
        StageT(R"([{"check": [], "then": [{"wazuh-indexer": []}]}])",
               firstOfBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(stageRegistry, get("check")).WillOnce(testing::Return(dummyCheckBuilder()));
                       EXPECT_CALL(stageRegistry, get("wazuh-indexer")).WillOnce(testing::Return(dummyOutputBuilder()));
                       return base::Or::create("first_of",
                                               {base::Implication::create(
                                                   "first_of.item-0",
                                                   base::And::create("dummy-check", {}),
                                                   base::Broadcast::create("first_of.item-0.then",
                                                                           {base::And::create("dummy-output", {})}))});
                   })),
        // Single item with multiple outputs in 'then' array (should use Broadcast)
        StageT(R"([{"check": [], "then": [{"file": []}, {"wazuh-indexer": []}]}])",
               firstOfBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(stageRegistry, get("check")).WillOnce(testing::Return(dummyCheckBuilder()));
                       EXPECT_CALL(stageRegistry, get("file")).WillOnce(testing::Return(dummyOutputBuilder()));
                       EXPECT_CALL(stageRegistry, get("wazuh-indexer")).WillOnce(testing::Return(dummyOutputBuilder()));
                       return base::Or::create("first_of",
                                               {base::Implication::create(
                                                   "first_of.item-0",
                                                   base::And::create("dummy-check", {}),
                                                   base::Broadcast::create("first_of.item-0.then",
                                                                           {base::And::create("dummy-output", {}),
                                                                            base::And::create("dummy-output", {})}))});
                   })),
        // Multiple valid items
        StageT(R"([{"check": [], "then": [{"file": []}]}, {"check": [], "then": [{"wazuh-indexer": []}]}])",
               firstOfBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(stageRegistry, get("check"))
                           .Times(2)
                           .WillRepeatedly(testing::Return(dummyCheckBuilder()));
                       EXPECT_CALL(stageRegistry, get("file")).WillOnce(testing::Return(dummyOutputBuilder()));
                       EXPECT_CALL(stageRegistry, get("wazuh-indexer")).WillOnce(testing::Return(dummyOutputBuilder()));
                       return base::Or::create(
                           "first_of",
                           {base::Implication::create("first_of.item-0",
                                                      base::And::create("dummy-check", {}),
                                                      base::Broadcast::create("first_of.item-0.then",
                                                                              {base::And::create("dummy-output", {})})),
                            base::Implication::create(
                                "first_of.item-1",
                                base::And::create("dummy-check", {}),
                                base::Broadcast::create("first_of.item-1.then",
                                                        {base::And::create("dummy-output", {})}))});
                   })),
        // Three valid items
        StageT(
            R"([{"check": [], "then": [{"file": []}]}, {"check": [], "then": [{"wazuh-indexer": []}]}, {"check": [], "then": [{"file": []}]}])",
            firstOfBuilder,
            SUCCESS(
                [](const auto& mocks)
                {
                    const auto& stageRegistry = mocks.registry->template getRegistry<StageBuilder>();
                    EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                    EXPECT_CALL(stageRegistry, get("check"))
                        .Times(3)
                        .WillRepeatedly(testing::Return(dummyCheckBuilder()));
                    EXPECT_CALL(stageRegistry, get("file"))
                        .Times(2)
                        .WillRepeatedly(testing::Return(dummyOutputBuilder()));
                    EXPECT_CALL(stageRegistry, get("wazuh-indexer")).WillOnce(testing::Return(dummyOutputBuilder()));
                    return base::Or::create(
                        "first_of",
                        {base::Implication::create(
                             "first_of.item-0",
                             base::And::create("dummy-check", {}),
                             base::Broadcast::create("first_of.item-0.then", {base::And::create("dummy-output", {})})),
                         base::Implication::create(
                             "first_of.item-1",
                             base::And::create("dummy-check", {}),
                             base::Broadcast::create("first_of.item-1.then", {base::And::create("dummy-output", {})})),
                         base::Implication::create("first_of.item-2",
                                                   base::And::create("dummy-check", {}),
                                                   base::Broadcast::create("first_of.item-2.then",
                                                                           {base::And::create("dummy-output", {})}))});
                }))),
    testNameFormatter<StageBuilderTest>("FirstOf"));
} // namespace stagebuildtest
