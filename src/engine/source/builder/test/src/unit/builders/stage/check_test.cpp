#include "builders/baseBuilders_test.hpp"
#include "builders/stage/check.hpp"

using namespace builder::builders;

namespace
{
OpBuilderEntry getDummyFilterThrow()
{
    ValidationInfo info {schemf::ValidationToken {}};
    OpBuilder builder = [](const Reference& ref,
                           const std::vector<OpArg>& args,
                           const std::shared_ptr<const IBuildCtx>& buildCtx) -> FilterOp
    {
        throw std::runtime_error("Dummy helper throw");
    };

    return std::make_tuple(info, builder);
}

OpBuilderEntry getDummyFilter(bool result)
{
    ValidationInfo info {schemf::ValidationToken {}};
    FilterBuilder builder = [result](const Reference& ref,
                                     const std::vector<OpArg>& args,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx) -> FilterOp
    {
        return [result](base::ConstEvent) -> FilterResult
        {
            if (result)
            {
                return base::result::makeSuccess(true);
            }

            return base::result::makeFailure(false);
        };
    };

    return std::make_tuple(info, builder);
}

} // namespace

namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    StageBuilderTest,
    testing::Values(
        StageT(R"({})", checkBuilder, FAILURE()),
        StageT(R"(1)", checkBuilder, FAILURE()),
        StageT(R"(null)", checkBuilder, FAILURE()),
        /*** Array check ***/
        StageT(R"([])", checkBuilder, FAILURE()),
        StageT(R"(["notObject"])", checkBuilder, FAILURE()),
        StageT(R"z([{"target": "dummyThrow()"}])z",
               checkBuilder,
               FAILURE(expectFilterHelper<OpBuilderEntry>("dummyThrow", getDummyFilterThrow()))),
        StageT(R"z([{"target": "dummyOk()"}])z",
               checkBuilder,
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       expectFilterHelper<OpBuilderEntry>("dummyOk", getDummyFilter(true))(mocks);
                       return base::And::create("stage.check", {dummyTerm("target: dummyOk")});
                   })),
        StageT(R"z([{"target": "dummyOk()"}, {"target": "dummyOk2()"}])z",
               checkBuilder,
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       expectAnyFilterHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyFilter(true)},
                                                             Helper<OpBuilderEntry> {"dummyOk2", getDummyFilter(true)})(
                           mocks);
                       return base::And::create("stage.check",
                                                {dummyTerm("target: dummyOk"), dummyTerm("target: dummyOk2")});
                   })),
        StageT(R"z([{"target": "dummyOk()"}, {"target": "dummyOk2()"}, {"target": "dummythrow()"}])z",
               checkBuilder,
               FAILURE(expectAnyFilterHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyFilter(true)},
                                                             Helper<OpBuilderEntry> {"dummyOk2", getDummyFilter(true)},
                                                             Helper<OpBuilderEntry> {"dummythrow",
                                                                                     getDummyFilterThrow()}))),
        StageT(R"z([{"target": "dummyOk()"}, {"target": "dummythrow()"}, {"target": "dummyOk2()"}])z",
               checkBuilder,
               FAILURE(expectAnyFilterHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyFilter(true)},
                                                             Helper<OpBuilderEntry> {"dummythrow",
                                                                                     getDummyFilterThrow()}))),
        /*** Expression check ***/
        StageT(R"("")", checkBuilder, FAILURE()),
        StageT(R"z("dummyThrow($arg)")z",
               checkBuilder,
               FAILURE(
                   [](const BuildersMocks& mocks)
                   {
                       expectFilterHelper<OpBuilderEntry>("dummyThrow", getDummyFilterThrow())(mocks);
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                       return None {};
                   })),
        StageT(R"z("invalid expression")z",
               checkBuilder,
               FAILURE(
                   [](const BuildersMocks& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                       return None {};
                   })),
        StageT(R"z("dummyOk($arg)")z",
               checkBuilder,
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       expectFilterHelper<OpBuilderEntry>("dummyOk", getDummyFilter(true))(mocks);
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                       return dummyTerm("stage.check");
                   })),
        StageT(R"z("dummyOk($arg) AND dummyOk2($arg)")z",
               checkBuilder,
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       expectAnyFilterHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyFilter(true)},
                                                             Helper<OpBuilderEntry> {"dummyOk2", getDummyFilter(true)})(
                           mocks);
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                       return dummyTerm("stage.check");
                   })),
        StageT(R"z("dummyOk($arg) AND dummyOk2($arg) AND dummyThrow($arg)")z",
               checkBuilder,
               FAILURE(
                   [](const BuildersMocks& mocks)
                   {
                       expectFilterHelper<OpBuilderEntry>("dummyThrow", getDummyFilterThrow())(mocks);
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                       return None {};
                   })),
        StageT(R"z("dummyOk($arg) AND dummyThrow($arg) AND dummyOk2($arg)")z",
               checkBuilder,
               FAILURE(
                   [](const BuildersMocks& mocks)
                   {
                       expectAnyFilterHelper<OpBuilderEntry>(
                           Helper<OpBuilderEntry> {"dummyOk2", getDummyFilter(true)},
                           Helper<OpBuilderEntry> {"dummyThrow", getDummyFilterThrow()})(mocks);
                       EXPECT_CALL(*mocks.ctx, definitions()).WillOnce(testing::ReturnRef(*mocks.definitions));
                       EXPECT_CALL(*mocks.definitions, replace(testing::_))
                           .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                       return None {};
                   }))),
    testNameFormatter<StageBuilderTest>("Check"));
} // namespace stagebuildtest
