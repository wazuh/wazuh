// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"
#include "builders/stage/parse.hpp"

#include <logpar/registerParsers.hpp>
#include <schemf/emptySchema.hpp>

using namespace builder::builders;

namespace
{
auto getBuilder()
{
    // Logpar keeps a weak_ptr to the schema: it must outlive the build of a field expression
    static auto schema = schemf::mocks::EmptySchema::create();
    std::shared_ptr<hlp::logpar::Logpar> logpar =
        std::make_shared<hlp::logpar::Logpar>(json::Json {R"({"name": "name", "fields": {}})"}, schema);
    size_t debugLvl = 0;
    hlp::registerParsers(logpar);

    return getParseBuilder(logpar, debugLvl);
}
} // namespace
namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    StageBuilderTest,
    testing::Values(
        StageT(R"({})", getBuilder(), FAILURE()),
        StageT(R"("notArray")", getBuilder(), FAILURE()),
        StageT(R"(1)", getBuilder(), FAILURE()),
        StageT(R"("true")", getBuilder(), FAILURE()),
        StageT(R"(null)", getBuilder(), FAILURE()),
        StageT(R"([])", getBuilder(), FAILURE()),
        StageT(R"([{"target": "expr"}])",
               getBuilder(),
               SUCCESS(
                   [](const auto& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](const auto& expr) { return std::string(expr); }));

                       return base::Or::create("parse", {base::Term<base::EngineOp>::create("expr", {})});
                   })),
        StageT(R"([{"target": "expr"}, {"target": "other"}])",
               getBuilder(),
               SUCCESS(
                   [](const auto& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, definitions()).WillRepeatedly(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillRepeatedly(testing::Invoke([](const auto& expr) { return std::string(expr); }));

                       return base::Or::create("parse",
                                               {base::Term<base::EngineOp>::create("expr", {}),
                                                base::Term<base::EngineOp>::create("other", {})});
                   })),
        StageT(R"([{"target": "expr"}, {"target": "<invalid/expression"}])",
               getBuilder(),
               FAILURE(
                   [](const auto& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, definitions()).WillRepeatedly(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillRepeatedly(testing::Invoke([](const auto& expr) { return std::string(expr); }));
                       return None {};
                   })),
        StageT(R"([{"target": "expr", "target": "other"}])", getBuilder(), FAILURE())),
    testNameFormatter<StageBuilderTest>("Parse"));
} // namespace stagebuildtest

namespace stageruntest
{
class ParseStageRunTest : public BaseBuilderTest
{
protected:
    // Builds the stage [{"source": "<_kv/kv/=/,/'/'>"}] in test mode and returns the op of its only term
    base::EngineOp buildKvOp()
    {
        EXPECT_CALL(*mocks->ctx, definitions()).WillRepeatedly(testing::ReturnRef(*mocks->definitions));
        EXPECT_CALL(*mocks->definitions, replace(testing::_))
            .WillRepeatedly(testing::Invoke([](const auto& expr) { return std::string(expr); }));
        EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::Return(true));

        auto expression = getBuilder()(json::Json {R"([{"source": "<_kv/kv/=/,/'/'>"}])"}, mocks->ctx);
        auto term = expression->getPtr<base::Or>()->getOperands()[0]->getPtr<base::Term<base::EngineOp>>();
        return term->getFn();
    }
};

// A kv key that is not a valid JSON Pointer is a parse failure of the stage, not an exception
TEST_F(ParseStageRunTest, KvInvalidPointerEscapeFails)
{
    auto op = buildKvOp();
    auto event = makeEvent(R"({"source": "a~2=1,b=2"})");
    const json::Json original {*event};

    ASSERT_NO_THROW(op(event));
    auto result = op(event);

    EXPECT_FALSE(result.success());
    EXPECT_THAT(result.trace(), testing::HasSubstr("Parse operation failed"));
    EXPECT_THAT(result.trace(), testing::HasSubstr("key 'a~2' has an invalid JSON Pointer escape"));
    EXPECT_EQ(*result.payload(), original);
}

TEST_F(ParseStageRunTest, KvPointerEscapesAreMapped)
{
    auto op = buildKvOp();
    auto result = op(makeEvent(R"({"source": "a~0b=1,c~1d=2"})"));

    EXPECT_TRUE(result.success()) << result.trace();
    EXPECT_TRUE(result.payload()->exists("/_kv/a~0b"));
    EXPECT_TRUE(result.payload()->exists("/_kv/c~1d"));
}
} // namespace stageruntest
