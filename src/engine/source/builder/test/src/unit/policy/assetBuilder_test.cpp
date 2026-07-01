#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/behaviour.hpp>
#include <defs/mockDefinitions.hpp>

#include "expressionCmp.hpp"
#include "mockBuildCtx.hpp"
#include "mockRegistry.hpp"
#include "policy/assetBuilder.hpp"

using namespace base::test;
using namespace builder::policy;
using namespace builder::builders;
using namespace builder::builders::mocks;
using namespace builder::mocks;

auto traceExpr =
    base::Term<base::EngineOp>::create("AcceptAll", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
auto automappingExpr =
    base::Term<base::EngineOp>::create("Automapping", [](auto e) { return base::result::makeSuccess(e, ""); });
auto assetExpr = base::Implication::create(base::Name("name"),
                                           base::And::create(base::Name("condition"), {traceExpr}),
                                           base::And::create(base::Name("stages"), {}));

struct Mocks
{
    std::shared_ptr<defs::mocks::MockDefinitionsBuilder> m_mockDefBuilder;
    std::shared_ptr<defs::mocks::MockDefinitions> m_mockDefs;
    std::shared_ptr<MockMetaRegistry<OpBuilderEntry, StageBuilder, EnrichmentBuilder>> m_mockRegistry;
};

template<typename T>
class AssetBuilderTest : public ::testing::TestWithParam<T>
{

protected:
    std::shared_ptr<BuildCtx> m_buildCtx;
    Mocks m_mocks;
    std::shared_ptr<AssetBuilder> m_assetBuilder;

    void SetUp() override
    {
        m_buildCtx = std::make_shared<BuildCtx>();
        m_mocks.m_mockDefBuilder = std::make_shared<defs::mocks::MockDefinitionsBuilder>();
        m_mocks.m_mockDefs = std::make_shared<defs::mocks::MockDefinitions>();
        m_mocks.m_mockRegistry = MockMetaRegistry<OpBuilderEntry, StageBuilder, EnrichmentBuilder>::createMock();

        m_buildCtx->setDefinitions(m_mocks.m_mockDefs);
        m_buildCtx->setRegistry(m_mocks.m_mockRegistry);
        m_assetBuilder = std::make_shared<AssetBuilder>(m_buildCtx, m_mocks.m_mockDefBuilder);
    }
};

namespace nametest
{
using SuccessExpected = InnerExpected<base::Name, None>;
using FailureExpected = InnerExpected<None, None>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using NameT = std::tuple<std::string, Expc>;

using GetName = AssetBuilderTest<NameT>;
TEST_P(GetName, Value)
{
    auto [nameStr, expected] = GetParam();

    json::Json nameJson(nameStr.c_str());

    if (expected)
    {
        base::Name name;
        auto expectedName = expected.succCase()(None {});
        EXPECT_NO_THROW(name = m_assetBuilder->getName(nameJson));
        EXPECT_EQ(name, expectedName);
    }
    else
    {
        EXPECT_THROW(m_assetBuilder->getName(nameJson), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(AssetBuilder,
                         GetName,
                         ::testing::Values(NameT(R"("name")", SUCCESS("name")),
                                           NameT(R"(1)", FAILURE()),
                                           NameT(R"({})", FAILURE()),
                                           NameT(R"([])", FAILURE()),
                                           NameT(R"(true)", FAILURE()),
                                           NameT(R"(null)", FAILURE()),
                                           NameT(R"("name1/name2")", SUCCESS("name1/name2")),
                                           NameT(R"("name1/name2/name3")", SUCCESS("name1/name2/name3")),
                                           NameT(R"("name1/")", SUCCESS("name1")),
                                           NameT(R"("/name2")", SUCCESS("name2")),
                                           NameT(R"("name1//name2")", FAILURE())));
} // namespace nametest

namespace getparentstest
{
using SuccessExpected = InnerExpected<std::vector<base::Name>, None>;
using FailureExpected = InnerExpected<None, None>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using GetParentsT = std::tuple<std::string, Expc>;

using GetParents = AssetBuilderTest<GetParentsT>;
TEST_P(GetParents, Value)
{
    auto [parentsStr, expected] = GetParam();

    json::Json parentsJson(parentsStr.c_str());

    if (expected)
    {
        std::vector<base::Name> parents;
        auto expectedParents = expected.succCase()(None {});
        EXPECT_NO_THROW(parents = m_assetBuilder->getParents(parentsJson));
        EXPECT_EQ(parents, expectedParents);
    }
    else
    {
        EXPECT_THROW(m_assetBuilder->getParents(parentsJson), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(AssetBuilder,
                         GetParents,
                         ::testing::Values(GetParentsT(R"(["name1", "name2"])",
                                                       SUCCESS(std::vector<base::Name> {"name1", "name2"})),
                                           GetParentsT(R"([1, "name2"])", FAILURE()),
                                           GetParentsT(R"({})", FAILURE()),
                                           GetParentsT(R"(true)", FAILURE()),
                                           GetParentsT(R"(null)", FAILURE()),
                                           GetParentsT(R"("name1/name2")", FAILURE()),
                                           GetParentsT(R"("name1/name2/name3")", FAILURE()),
                                           GetParentsT(R"("name1/")", FAILURE()),
                                           GetParentsT(R"("/name2")", FAILURE()),
                                           GetParentsT(R"("name1//name2")", FAILURE()),
                                           GetParentsT(R"(["name1", "name2", "name1"])", FAILURE())));

} // namespace getparentstest

namespace assetbuildexpressiontest
{
using SuccessExpected = InnerExpected<base::Expression, Mocks>;
using FailureExpected = InnerExpected<None, Mocks>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using BuildExprT = std::tuple<std::string, std::vector<std::string>, Expc>;
using AV = std::vector<std::string>;

using BuildExpr = AssetBuilderTest<BuildExprT>;
TEST_P(BuildExpr, Value)
{
    auto [assetName, assetVecStr, expected] = GetParam();

    std::vector<std::tuple<std::string, json::Json>> assetVec;
    for (const auto& name : assetVecStr)
    {
        assetVec.emplace_back(std::make_tuple(name, json::Json {}));
    }

    if (expected)
    {
        base::Expression expr;
        auto expectedExpr = expected.succCase()(m_mocks);
        EXPECT_NO_THROW(expr = m_assetBuilder->buildExpression(base::Name(assetName), assetVec));
        builder::test::assertEqualExpr(expr, expectedExpr);
    }
    else
    {
        expected.failCase()(m_mocks);
        EXPECT_THROW(m_assetBuilder->buildExpression(base::Name(assetName), assetVec), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    AssetBuilder,
    BuildExpr,
    ::testing::Values(
        BuildExprT("name",
                   AV {},
                   FAILURE(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Throw(std::runtime_error("")));
                           return None {};
                       })),
        BuildExprT("name",
                   AV {"definitions"},
                   FAILURE(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Throw(std::runtime_error("")));
                           return None {};
                       })),
        BuildExprT("name",
                   AV {"definitions"},
                   SUCCESS(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Return(mocks.m_mockDefs));
                           auto condition = base::And::create(base::Name("condition"), {traceExpr});
                           auto consequence = base::And::create(base::Name("stages"), {});
                           return base::Implication::create(base::Name("name"), condition, consequence);
                       })),
        BuildExprT("name",
                   AV {},
                   SUCCESS(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Return(mocks.m_mockDefs));
                           auto condition = base::And::create(base::Name("condition"), {traceExpr});
                           auto consequence = base::And::create(base::Name("stages"), {});
                           return base::Implication::create(base::Name("name"), condition, consequence);
                       })),
        BuildExprT("name",
                   AV {"stageWithoutBuilder"},
                   FAILURE(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Return(mocks.m_mockDefs));
                           EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("stageWithoutBuilder"))
                               .WillOnce(testing::Return(base::Error {}));
                           return None {};
                       })),
        BuildExprT(
            "name",
            AV {"stageWithBuilder"},
            SUCCESS(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto stageExpr = base::Term<base::EngineOp>::create(
                        "stage", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("stageWithBuilder"))
                        .WillOnce(
                            testing::Return([stageExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return stageExpr; }));
                    auto condition = base::And::create(base::Name("condition"), {traceExpr});
                    auto consequence = base::And::create(base::Name("stages"), {stageExpr});
                    return base::Implication::create(base::Name("name"), condition, consequence);
                })),
        BuildExprT(
            "name",
            AV {"stageWithBuilderThrows"},
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("stageWithBuilderThrows"))
                        .WillOnce(testing::Return(
                            [](const json::Json& value, const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                            { throw std::runtime_error(""); }));
                    return None {};
                })),
        BuildExprT(
            "name",
            AV {"check"},
            SUCCESS(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto checkExpr = base::Term<base::EngineOp>::create(
                        "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(
                            testing::Return([checkExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return checkExpr; }));
                    auto condition = base::And::create(base::Name("condition"), {checkExpr, traceExpr});
                    auto consequence = base::And::create(base::Name("stages"), {});
                    return base::Implication::create(base::Name("name"), condition, consequence);
                })),
        BuildExprT(
            "name",
            AV {"check"}, // Throws
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(testing::Return(
                            [](const json::Json& value, const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                            { throw std::runtime_error(""); }));
                    return None {};
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"parse|field"},
            SUCCESS(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto parseExpr = base::Term<base::EngineOp>::create(
                        "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(
                            testing::Return([parseExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return parseExpr; }));

                    auto condition = base::And::create(base::Name("condition"), {parseExpr, traceExpr});
                    auto consequence = base::And::create(base::Name("stages"), {automappingExpr});
                    return base::Implication::create(base::Name("decoder/name/0"), condition, consequence);
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"parse|field"}, // Throws
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(testing::Return(
                            [](const json::Json& value, const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                            { throw std::runtime_error(""); }));
                    return None {};
                })),
        BuildExprT("decoder/name/0",
                   AV {"parse"}, // Throws
                   FAILURE(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Return(mocks.m_mockDefs));
                           return None {};
                       })),
        BuildExprT(
            "decoder/name/0",
            AV {"parse|"}, // Not throws, parse root event
            SUCCESS(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    auto parseExpr = base::Term<base::EngineOp>::create(
                        "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(
                            testing::Return([parseExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return parseExpr; }));

                    auto condition = base::And::create(base::Name("condition"), {parseExpr, traceExpr});
                    auto consequence = base::And::create(base::Name("stages"), {automappingExpr});
                    return base::Implication::create(base::Name("decoder/name/0"), condition, consequence);
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"check", "parse|field"},
            SUCCESS(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto checkExpr = base::Term<base::EngineOp>::create(
                        "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(
                            testing::Return([checkExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return checkExpr; }));

                    auto parseExpr = base::Term<base::EngineOp>::create(
                        "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(
                            testing::Return([parseExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return parseExpr; }));

                    auto condition = base::And::create(base::Name("condition"), {checkExpr, parseExpr, traceExpr});
                    auto consequence = base::And::create(base::Name("stages"), {automappingExpr});
                    return base::Implication::create(base::Name("decoder/name/0"), condition, consequence);
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"check", "parse|field"}, // Throws check
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(testing::Return(
                            [](const json::Json& value, const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                            { throw std::runtime_error(""); }));
                    return None {};
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"check", "parse|field"}, // Throws parse
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto checkExpr = base::Term<base::EngineOp>::create(
                        "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(
                            testing::Return([checkExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return checkExpr; }));

                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(testing::Return(
                            [](const json::Json& value, const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                            { throw std::runtime_error(""); }));
                    return None {};
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"check", "parse|field", "stageWithBuilder"},
            SUCCESS(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto checkExpr = base::Term<base::EngineOp>::create(
                        "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(
                            testing::Return([checkExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return checkExpr; }));

                    auto parseExpr = base::Term<base::EngineOp>::create(
                        "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(
                            testing::Return([parseExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return parseExpr; }));

                    auto stageExpr = base::Term<base::EngineOp>::create(
                        "stage", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("stageWithBuilder"))
                        .WillOnce(
                            testing::Return([stageExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return stageExpr; }));

                    auto condition = base::And::create(base::Name("condition"), {checkExpr, parseExpr, traceExpr});
                    auto consequence = base::And::create(base::Name("stages"), {stageExpr, automappingExpr});
                    return base::Implication::create(base::Name("decoder/name/0"), condition, consequence);
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"check", "parse|field", "stageWithBuilderThrows"},
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto checkExpr = base::Term<base::EngineOp>::create(
                        "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(
                            testing::Return([checkExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return checkExpr; }));

                    auto parseExpr = base::Term<base::EngineOp>::create(
                        "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(
                            testing::Return([parseExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return parseExpr; }));

                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("stageWithBuilderThrows"))
                        .WillOnce(testing::Return(
                            [](const json::Json& value, const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                            { throw std::runtime_error(""); }));
                    return None {};
                })),
        BuildExprT(
            "decoder/name/0",
            AV {"check", "parse|field", "stageWithoutBuilder"},
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));

                    auto checkExpr = base::Term<base::EngineOp>::create(
                        "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                        .WillOnce(
                            testing::Return([checkExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return checkExpr; }));

                    auto parseExpr = base::Term<base::EngineOp>::create(
                        "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                        .WillOnce(
                            testing::Return([parseExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                            { return parseExpr; }));

                    EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("stageWithoutBuilder"))
                        .WillOnce(testing::Return(base::Error {}));
                    return None {};
                }))

            ));

} // namespace assetbuildexpressiontest

namespace assetbuildtest
{

using SuccessExpected = InnerExpected<Asset, Mocks>;
using FailureExpected = InnerExpected<None, Mocks>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using BuildT = std::tuple<std::string, std::string, Expc>;

using BuildAsset = AssetBuilderTest<BuildT>;

TEST_P(BuildAsset, Build)
{
    auto [assetStr, expectedMsg, expected] = GetParam();
    auto asset = json::Json(assetStr.c_str());

    if (expected)
    {
        Asset assetObj;
        auto expectedAsset = expected.succCase()(m_mocks);
        EXPECT_NO_THROW(assetObj = m_assetBuilder->operator()(asset));
        EXPECT_EQ(assetObj.name(), expectedAsset.name());
        builder::test::assertEqualExpr(assetObj.expression(), expectedAsset.expression());
        EXPECT_EQ(assetObj.parents(), expectedAsset.parents());
    }
    else
    {
        expected.failCase()(m_mocks);
        if (!expectedMsg.empty())
        {
            EXPECT_THROW(
                {
                    try
                    {
                        m_assetBuilder->operator()(asset);
                    }
                    catch (const std::runtime_error& e)
                    {
                        EXPECT_THAT(e.what(), ::testing::HasSubstr(expectedMsg));
                        throw;
                    }
                },
                std::runtime_error);
        }
        else
        {
            EXPECT_THROW(m_assetBuilder->operator()(asset), std::runtime_error);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    AssetBuilder,
    BuildAsset,
    ::testing::Values(BuildT(R"({})", "", FAILURE()),
                      BuildT(R"({"noName": "name"})", "", FAILURE()),
                      BuildT(R"({"name": 1})", "", FAILURE()),
                      BuildT(R"({"name": "output/wazuh/0"})",
                             "",
                             SUCCESS(
                                 [](Mocks mocks)
                                 {
                                     EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                         .WillOnce(testing::Return(mocks.m_mockDefs));
                                     auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                     auto consequence = base::And::create(base::Name("stages"), {});
                                     return Asset(base::Name("output/wazuh/0"),
                                                  base::Implication::create(
                                                      base::Name("output/wazuh/0"), condition, consequence),
                                                  {});
                                 })),
                      BuildT(R"({"name": "output/wazuh/0", "metadata": {}})",
                             "",
                             SUCCESS(
                                 [](Mocks mocks)
                                 {
                                     EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                         .WillOnce(testing::Return(mocks.m_mockDefs));
                                     auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                     auto consequence = base::And::create(base::Name("stages"), {});
                                     return Asset(base::Name("output/wazuh/0"),
                                                  base::Implication::create(
                                                      base::Name("output/wazuh/0"), condition, consequence),
                                                  {});
                                 })),
                      BuildT(R"({"name": "output/wazuh/0", "parents": ["parent"]})",
                             "",
                             SUCCESS(
                                 [](Mocks mocks)
                                 {
                                     EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                         .WillOnce(testing::Return(mocks.m_mockDefs));
                                     auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                     auto consequence = base::And::create(base::Name("stages"), {});
                                     return Asset(base::Name("output/wazuh/0"),
                                                  base::Implication::create(
                                                      base::Name("output/wazuh/0"), condition, consequence),
                                                  {base::Name("parent")});
                                 })),
                      BuildT(R"({"name": "output/wazuh/0", "parents": {}})", "", FAILURE()),
                      BuildT(R"({"name": "output/wazuh/0", "check": {}})",
                             "",
                             SUCCESS(
                                 [](Mocks mocks)
                                 {
                                     EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                         .WillOnce(testing::Return(mocks.m_mockDefs));

                                     auto checkExpr = base::Term<base::EngineOp>::create(
                                         "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                     EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                                         .WillOnce(
                                             testing::Return([checkExpr](const json::Json& value,
                                                                         const std::shared_ptr<const IBuildCtx>& ctx)
                                                                 -> base::Expression { return checkExpr; }));

                                     auto condition =
                                         base::And::create(base::Name("condition"), {checkExpr, traceExpr});
                                     auto consequence = base::And::create(base::Name("stages"), {});
                                     return Asset(base::Name("output/wazuh/0"),
                                                  base::Implication::create(
                                                      base::Name("output/wazuh/0"), condition, consequence),
                                                  {});
                                 })),
                      BuildT(R"({"name": "output/wazuh/0", "check": {}})",
                             "",
                             FAILURE(
                                 [](Mocks mocks)
                                 {
                                     EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                         .WillOnce(testing::Throw(std::runtime_error("")));
                                     return None {};
                                 })),
                    // Stage validation: invalid cases (should fail)
                    // filter + normalize
                    BuildT(R"({"name": "filter/wazuh/0", "type": "pre-filter", "normalize": []})",
                        "Invalid stage 'normalize' for filter asset",
                        FAILURE()),
                    // filter + parse|message
                    BuildT(R"({"name": "filter/wazuh/0", "type": "pre-filter", "parse|message": []})",
                        "Invalid stage 'parse|message' for filter asset",
                        FAILURE()),
                    // filter + outputs
                    BuildT(R"({"name": "filter/wazuh/0", "type": "pre-filter", "outputs": []})",
                        "Invalid stage 'outputs' for filter asset",
                        FAILURE()),
                    // decoder + outputs
                    BuildT(R"({"name": "decoder/wazuh/0", "outputs": []})",
                        "Invalid stage 'outputs' for decoder asset",
                        FAILURE()),
                    // output + normalize
                    BuildT(R"({"name": "output/wazuh/0", "normalize": []})",
                        "Invalid stage 'normalize' for output asset",
                        FAILURE()),
                    // output + parse|message
                    BuildT(R"({"name": "output/wazuh/0", "parse|message": []})",
                        "Invalid stage 'parse|message' for output asset",
                        FAILURE()),
                    // outputs + invalid operation
                    BuildT(R"({"name": "output/wazuh/0", "outputs": [{"invalid_op": {}}]})",
                        "Invalid output operation 'invalid_op' for output asset",
                        FAILURE()),

                    // Stage validation: valid cases (should pass)
                    // filter + check
                    BuildT(R"({"name": "filter/wazuh/0", "type": "pre-filter", "check": []})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto checkExpr = base::Term<base::EngineOp>::create(
                                    "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                                    .WillOnce(testing::Return(
                                        [checkExpr](const json::Json& value,
                                                    const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return checkExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {checkExpr, traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {});
                                return Asset(base::Name("filter/wazuh/0"),
                                            base::Implication::create(base::Name("filter/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // decoder + normalize
                    BuildT(R"({"name": "decoder/wazuh/0", "normalize": []})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto normalizeExpr = base::Term<base::EngineOp>::create(
                                    "normalize", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("normalize"))
                                    .WillOnce(testing::Return(
                                        [normalizeExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return normalizeExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {normalizeExpr, automappingExpr});
                                return Asset(base::Name("decoder/wazuh/0"),
                                            base::Implication::create(base::Name("decoder/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // decoder + parse|message
                    BuildT(R"({"name": "decoder/wazuh/0", "parse|message": []})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto parseExpr = base::Term<base::EngineOp>::create(
                                    "parse", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("parse"))
                                    .WillOnce(testing::Return(
                                        [parseExpr](const json::Json& value,
                                                    const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return parseExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {parseExpr, traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {automappingExpr});
                                return Asset(base::Name("decoder/wazuh/0"),
                                            base::Implication::create(base::Name("decoder/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // output + check
                    BuildT(R"({"name": "output/wazuh/0", "check": []})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto checkExpr = base::Term<base::EngineOp>::create(
                                    "check", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("check"))
                                    .WillOnce(testing::Return(
                                        [checkExpr](const json::Json& value,
                                                    const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return checkExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {checkExpr, traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {});
                                return Asset(base::Name("output/wazuh/0"),
                                            base::Implication::create(base::Name("output/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // output + outputs with first_of
                    BuildT(R"({"name": "output/wazuh/0", "outputs": [{"first_of": {}}]})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto outputsExpr = base::Term<base::EngineOp>::create(
                                    "outputs", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("outputs"))
                                    .WillOnce(testing::Return(
                                        [outputsExpr](const json::Json& value,
                                                    const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return outputsExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {outputsExpr});
                                return Asset(base::Name("output/wazuh/0"),
                                            base::Implication::create(base::Name("output/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // decoder + parse| (empty field after pipe)
                    BuildT(R"({"name": "decoder/wazuh/0", "parse|": []})",
                        "Invalid parse stage 'parse|' for decoder asset 'decoder/wazuh/0': missing field",
                        FAILURE()),
                    // decoder + parse|field..invalid (invalid DotPath)
                    BuildT(R"({"name": "decoder/wazuh/0", "parse|field..invalid": []})",
                        "Invalid parse stage 'parse|field..invalid' for decoder asset",
                        FAILURE()),
                    // output + outputs: null (not an array)
                    BuildT(R"({"name": "output/wazuh/0", "outputs": null})",
                        "Invalid outputs stage for output asset 'output/wazuh/0'. Expected a non-empty array of objects",
                        FAILURE()),
                    // output + outputs: [] (empty array)
                    BuildT(R"({"name": "output/wazuh/0", "outputs": []})",
                        "Invalid outputs stage for output asset 'output/wazuh/0'. Expected a non-empty array of objects",
                        FAILURE()),
                    // output + outputs: ["string"] (item is not an object)
                    BuildT(R"({"name": "output/wazuh/0", "outputs": ["string"]})",
                        "Invalid outputs stage for output asset 'output/wazuh/0'. Expected every item to be an object",
                        FAILURE()),
                    // output + outputs: [{}] (empty object — no operation)
                    BuildT(R"({"name": "output/wazuh/0", "outputs": [{}]})",
                        "Invalid outputs stage for output asset 'output/wazuh/0'. Each item must contain exactly one operation",
                        FAILURE()),
                    // output + outputs: [{"first_of": {}, "file": {}}] (multiple operations in one item)
                    BuildT(R"({"name": "output/wazuh/0", "outputs": [{"first_of": {}, "file": {}}]})",
                        "Invalid outputs stage for output asset 'output/wazuh/0'. Each item must contain exactly one operation",
                        FAILURE()),
                    // output + outputs: [{"file": {}}]
                    BuildT(R"({"name": "output/wazuh/0", "outputs": [{"file": {}}]})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto outputsExpr = base::Term<base::EngineOp>::create(
                                    "outputs", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("outputs"))
                                    .WillOnce(testing::Return(
                                        [outputsExpr](const json::Json& value,
                                                    const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return outputsExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {outputsExpr});
                                return Asset(base::Name("output/wazuh/0"),
                                            base::Implication::create(base::Name("output/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // output + outputs: [{"wazuh-indexer": {}}]
                    BuildT(R"({"name": "output/wazuh/0", "outputs": [{"wazuh-indexer": {}}]})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto outputsExpr = base::Term<base::EngineOp>::create(
                                    "outputs", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("outputs"))
                                    .WillOnce(testing::Return(
                                        [outputsExpr](const json::Json& value,
                                                    const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return outputsExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {outputsExpr});
                                return Asset(base::Name("output/wazuh/0"),
                                            base::Implication::create(base::Name("output/wazuh/0"), condition, consequence),
                                            {});
                            })),
                    // decoder + definitions + normalize (definitions should be skipped)
                    BuildT(R"({"name": "decoder/wazuh/0", "definitions": {"foo": "bar"}, "normalize": []})",
                        "",
                        SUCCESS(
                            [](Mocks mocks)
                            {
                                EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                                    .WillOnce(testing::Return(mocks.m_mockDefs));
                                auto normalizeExpr = base::Term<base::EngineOp>::create(
                                    "normalize", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
                                EXPECT_CALL(mocks.m_mockRegistry->getRegistry<StageBuilder>(), get("normalize"))
                                    .WillOnce(testing::Return(
                                        [normalizeExpr](const json::Json& value,
                                                        const std::shared_ptr<const IBuildCtx>& ctx) -> base::Expression
                                        { return normalizeExpr; }));
                                auto condition = base::And::create(base::Name("condition"), {traceExpr});
                                auto consequence = base::And::create(base::Name("stages"), {normalizeExpr, automappingExpr});
                                return Asset(base::Name("decoder/wazuh/0"),
                                            base::Implication::create(base::Name("decoder/wazuh/0"), condition, consequence),
                                            {});
                            }))
                        ));

} // namespace assetbuildtest
