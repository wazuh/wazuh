#include "builders/baseBuilders_test.hpp"
#include "builders/stage/map.hpp"

using namespace builder::builders;

namespace
{
OpBuilderEntry getDummyMapThrow()
{
    ValidationInfo info {schemf::ValidationToken {}};
    OpBuilder builder = [](const std::vector<OpArg>& args, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        throw std::runtime_error("Dummy helper throw");
    };

    return std::make_tuple(info, builder);
}

OpBuilderEntry getDummyMap(bool result)
{
    ValidationInfo info {schemf::ValidationToken {}};
    OpBuilder builder = [result](const std::vector<OpArg>& args,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        return [result](base::ConstEvent) -> MapResult
        {
            if (result)
            {
                return base::result::makeSuccess(json::Json {});
            }

            return base::result::makeFailure(json::Json {});
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
        StageT(R"({})", mapBuilder, FAILURE()),
        StageT(R"(1)", mapBuilder, FAILURE()),
        StageT(R"("a")", mapBuilder, FAILURE()),
        StageT(R"(null)", mapBuilder, FAILURE()),
        StageT(R"([])", mapBuilder, FAILURE()),
        StageT(R"(["notObject"])", mapBuilder, FAILURE()),
        StageT(R"([{}])", mapBuilder, FAILURE()),
        StageT(R"z([{"target": "dummyThrow()"}])z",
               mapBuilder,
               FAILURE(expectMapHelper<OpBuilderEntry>("dummyThrow", getDummyMapThrow()))),
        StageT(R"z([{"target": "dummyOk()"}])z",
               mapBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       expectMapHelper<OpBuilderEntry>("dummyOk", getDummyMap(true))(mocks);
                       return base::Chain::create("stage.map", {dummyTerm("target: dummyOk")});
                   })),
        StageT(R"z([{"target": "dummyOk()"}, {"target": "dummyOk2()"}])z",
               mapBuilder,
               SUCCESS(
                   [](const auto& mocks)
                   {
                       expectAnyMapHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyMap(true)},
                                                          Helper<OpBuilderEntry> {"dummyOk2", getDummyMap(true)})(
                           mocks);
                       return base::Chain::create("stage.map",
                                                  {dummyTerm("target: dummyOk"), dummyTerm("target: dummyOk2")});
                   })),
        StageT(R"z([{"target": "dummyOk()"}, {"target": "dummyOk2()"}, {"target": "dummyThrow()"}])z",
               mapBuilder,
               FAILURE(expectAnyMapHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyMap(true)},
                                                          Helper<OpBuilderEntry> {"dummyOk2", getDummyMap(true)},
                                                          Helper<OpBuilderEntry> {"dummyThrow", getDummyMapThrow()}))),
        StageT(R"z([{"target": "dummyOk()"}, {"target": "dummyThrow()"}, {"target": "dummyOk2()"}])z",
               mapBuilder,
               FAILURE(expectAnyMapHelper<OpBuilderEntry>(Helper<OpBuilderEntry> {"dummyOk", getDummyMap(true)},
                                                          Helper<OpBuilderEntry> {"dummyThrow", getDummyMapThrow()})))),
    testNameFormatter<StageBuilderTest>("Map"));
} // namespace stagebuildtest
