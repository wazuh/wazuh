#include "builders/baseBuilders_test.hpp"
#include "builders/stage/normalize.hpp"

using namespace builder::builders;

namespace
{
auto dummyStageBuilder()
{
    return [](const json::Json& def, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return base::And::create("dummy", {});
    };
}

auto dummyStageBuilderThrow()
{
    return [](const json::Json& def, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        throw std::runtime_error("Dummy helper throw");
    };
}
} // namespace
namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    StageBuilderTest,
    testing::Values(
        StageT(R"({})", normalizeBuilder, FAILURE()),
        StageT(R"(1)", normalizeBuilder, FAILURE()),
        StageT(R"(null)", normalizeBuilder, FAILURE()),
        StageT(R"([])", normalizeBuilder, FAILURE()),
        StageT(R"("a")", normalizeBuilder, FAILURE()),
        StageT(R"z([{"map": []}])z",
               normalizeBuilder,
               FAILURE(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("map")).WillOnce(testing::Return(base::Error {"Error"}));
                       return None {};
                   })),
        StageT(R"z([{"map": []}])z",
               normalizeBuilder,
               FAILURE(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("map")).WillOnce(testing::Return(dummyStageBuilderThrow()));
                       return None {};
                   })),
        StageT(R"z([{"map": []}])z",
               normalizeBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("map")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Chain::create("normalize",
                                                  {base::And::create("subblock", {base::And::create("dummy", {})})});
                   })),
        StageT(R"z([{"parse|key": []}])z",
               normalizeBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("parse")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Chain::create("normalize",
                                                  {base::And::create("subblock", {base::And::create("dummy", {})})});
                   })),
        StageT(R"z([{"check": []}])z",
               normalizeBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("check")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Chain::create("normalize",
                                                  {base::And::create("subblock", {base::And::create("dummy", {})})});
                   })),
        StageT(R"z([{"map": []}, {"parse|key": []}, {"check": []}])z",
               normalizeBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("map")).WillOnce(testing::Return(dummyStageBuilder()));
                       EXPECT_CALL(innerRegistry, get("parse")).WillOnce(testing::Return(dummyStageBuilder()));
                       EXPECT_CALL(innerRegistry, get("check")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Chain::create("normalize",
                                                  {base::And::create("subblock", {base::And::create("dummy", {})}),
                                                   base::And::create("subblock", {base::And::create("dummy", {})}),
                                                   base::And::create("subblock", {base::And::create("dummy", {})})});
                   })),
        StageT(R"z([{"map": [], "parse|key": [], "check": []}])z",
               normalizeBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("map")).WillOnce(testing::Return(dummyStageBuilder()));
                       EXPECT_CALL(innerRegistry, get("parse")).WillOnce(testing::Return(dummyStageBuilder()));
                       EXPECT_CALL(innerRegistry, get("check")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Chain::create("normalize",
                                                  {base::And::create("subblock",
                                                                     {base::And::create("dummy", {}),
                                                                      base::And::create("dummy", {}),
                                                                      base::And::create("dummy", {})})});
                   }))),
    testNameFormatter<StageBuilderTest>("Normalize"));
} // namespace stagebuildtest
