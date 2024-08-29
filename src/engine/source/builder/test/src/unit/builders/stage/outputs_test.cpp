#include "builders/baseBuilders_test.hpp"
#include "builders/stage/outputs.hpp"

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
        StageT(R"({})", outputsBuilder, FAILURE()),
        StageT(R"(1)", outputsBuilder, FAILURE()),
        StageT(R"("a")", outputsBuilder, FAILURE()),
        StageT(R"(null)", outputsBuilder, FAILURE()),
        StageT(R"([])", outputsBuilder, FAILURE()),
        StageT(R"(["notObject"])", outputsBuilder, FAILURE()),
        StageT(R"([{}])", outputsBuilder, FAILURE()),
        StageT(R"([{"output": "ingnored"}])",
               outputsBuilder,
               FAILURE(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("output")).WillOnce(testing::Return(base::Error {"Error"}));
                       return None {};
                   })),
        StageT(R"([{"output": "ingnored"}])",
               outputsBuilder,
               FAILURE(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("output")).WillOnce(testing::Return(dummyStageBuilderThrow()));
                       return None {};
                   })),
        StageT(R"([{"output": "ingnored"}])",
               outputsBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("output")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Broadcast::create("outputs", {base::And::create("dummy", {})});
                   })),
        StageT(R"([{"output1": "ingnored"}, {"output2": "ingnored"}])",
               outputsBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       const auto& innerRegistry = mocks.registry->template getRegistry<StageBuilder>();
                       EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));
                       EXPECT_CALL(innerRegistry, get("output1")).WillOnce(testing::Return(dummyStageBuilder()));
                       EXPECT_CALL(innerRegistry, get("output2")).WillOnce(testing::Return(dummyStageBuilder()));
                       return base::Broadcast::create("outputs",
                                                      {base::And::create("dummy", {}), base::And::create("dummy", {})});
                   })),
        StageT(R"([{"output1": "ingnored", "output2": "ingnored"}])", outputsBuilder, FAILURE())),
    testNameFormatter<StageBuilderTest>("Outputs"));
} // namespace stagebuildtest
