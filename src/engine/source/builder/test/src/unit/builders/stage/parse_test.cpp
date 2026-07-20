#include "builders/baseBuilders_test.hpp"
#include "builders/stage/parse.hpp"

#include <logpar/registerParsers.hpp>
#include <schemf/emptySchema.hpp>

using namespace builder::builders;

namespace
{
auto getBuilder()
{
    std::shared_ptr<hlp::logpar::Logpar> logpar = std::make_shared<hlp::logpar::Logpar>(
        json::Json {R"({"name": "name", "fields": {}})"}, schemf::mocks::EmptySchema::create());
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
