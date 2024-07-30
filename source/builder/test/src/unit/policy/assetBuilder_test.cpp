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
auto delVarExpr =
    base::Term<base::EngineOp>::create("DeleteVariables", [](auto e) { return base::result::makeSuccess(e, ""); });
auto assetExpr = base::And::create(base::Name("name"), {base::And::create(base::Name("condition"), {traceExpr})});

struct Mocks
{
    std::shared_ptr<defs::mocks::MockDefinitionsBuilder> m_mockDefBuilder;
    std::shared_ptr<defs::mocks::MockDefinitions> m_mockDefs;
    std::shared_ptr<MockMetaRegistry<OpBuilderEntry, StageBuilder>> m_mockRegistry;
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
        m_mocks.m_mockRegistry = MockMetaRegistry<OpBuilderEntry, StageBuilder>::createMock();

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

using BuildExprT = std::tuple<std::vector<std::string>, Expc>;
using AV = std::vector<std::string>;

using BuildExpr = AssetBuilderTest<BuildExprT>;
TEST_P(BuildExpr, Value)
{
    auto [assetVecStr, expected] = GetParam();

    std::vector<std::tuple<std::string, json::Json>> assetVec;
    for (const auto& name : assetVecStr)
    {
        assetVec.emplace_back(std::make_tuple(name, json::Json {}));
    }

    if (expected)
    {
        base::Expression expr;
        auto expectedExpr = expected.succCase()(m_mocks);
        EXPECT_NO_THROW(expr = m_assetBuilder->buildExpression(base::Name("name"), assetVec));
        builder::test::assertEqualExpr(expr, expectedExpr);
    }
    else
    {
        expected.failCase()(m_mocks);
        EXPECT_THROW(m_assetBuilder->buildExpression(base::Name("name"), assetVec), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    AssetBuilder,
    BuildExpr,
    ::testing::Values(
        BuildExprT(AV {},
                   FAILURE(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Throw(std::runtime_error("")));
                           return None {};
                       })),
        BuildExprT(AV {"definitions"},
                   FAILURE(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Throw(std::runtime_error("")));
                           return None {};
                       })),
        BuildExprT(AV {"definitions"},
                   SUCCESS(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Return(mocks.m_mockDefs));
                           return base::And::create(base::Name("name"),
                                                    {base::And::create(base::Name("condition"), {traceExpr})});
                       })),
        BuildExprT(AV {},
                   SUCCESS(
                       [](Mocks mocks)
                       {
                           EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                               .WillOnce(testing::Return(mocks.m_mockDefs));
                           return base::And::create(base::Name("name"),
                                                    {base::And::create(base::Name("condition"), {traceExpr})});
                       })),
        BuildExprT(AV {"stageWithoutBuilder"},
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
                    auto consequence = base::And::create(base::Name("stages"), {stageExpr, delVarExpr});
                    return base::Implication::create(base::Name("name"), condition, consequence);
                })),
        BuildExprT(
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
                    auto consequence = base::And::create(base::Name("stages"), {delVarExpr});
                    return base::And::create(base::Name("name"), {condition});
                })),
        BuildExprT(
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
                    return base::And::create(base::Name("name"), {condition});
                })),
        BuildExprT(
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
        BuildExprT(
            AV {"parse"}, // Throws
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    return None {};
                })),
                BuildExprT(
            AV {"parse|"}, // Throws
            FAILURE(
                [](Mocks mocks)
                {
                    EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_)).WillOnce(testing::Return(mocks.m_mockDefs));
                    return None {};
                })),
        BuildExprT(
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
                    return base::And::create(base::Name("name"), {condition});
                })),
        BuildExprT(
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
                    auto consequence = base::And::create(base::Name("stages"), {stageExpr, delVarExpr});
                    return base::Implication::create(base::Name("name"), condition, consequence);
                })),
        BuildExprT(
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

using BuildT = std::tuple<std::string, Expc>;

using BuildAsset = AssetBuilderTest<BuildT>;

TEST_P(BuildAsset, Build)
{
    auto [assetStr, expected] = GetParam();
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
        EXPECT_THROW(m_assetBuilder->operator()(asset), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    AssetBuilder,
    BuildAsset,
    ::testing::Values(
        BuildT(R"({})", FAILURE()),
        BuildT(R"({"noName": "name"})", FAILURE()),
        BuildT(R"({"name": 1})", FAILURE()),
        BuildT(R"({"name": "name"})", SUCCESS(Asset(base::Name("name"), assetExpr, {}))),
        BuildT(R"({"name": "name", "metadata": {}})", SUCCESS(Asset(base::Name("name"), assetExpr, {}))),
        BuildT(R"({"name": "name", "parents": ["parent"]})",
               SUCCESS(Asset(base::Name("name"), assetExpr, {base::Name("parent")}))),
        BuildT(R"({"name": "name", "parents": {}})", FAILURE()),
        BuildT(
            R"({"name": "name", "check": {}})",
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
                    return Asset(base::Name("name"), base::And::create(base::Name("name"), {condition}), {});
                })),
        BuildT(R"({"name": "name", "check": {}})",
               FAILURE(
                   [](Mocks mocks)
                   {
                       EXPECT_CALL(*mocks.m_mockDefBuilder, build(testing::_))
                           .WillOnce(testing::Throw(std::runtime_error("")));
                       return None {};
                   }))));

} // namespace assetbuildtest
