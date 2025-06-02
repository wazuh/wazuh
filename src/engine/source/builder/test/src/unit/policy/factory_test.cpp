#include <gtest/gtest.h>

#include <sstream>

#include <base/behaviour.hpp>
#include <store/mockStore.hpp>

#include "expressionCmp.hpp"
#include "factory_test.hpp"
#include "mockRegistry.hpp"
#include "policy/factory.hpp"
#include "policy/mockAssetBuilder.hpp"

using namespace builder::policy;
using namespace base::test;
using namespace store::mocks;
using namespace builder::mocks;
using namespace builder::policy::mocks;

namespace readtest
{
using SuccessExpected = InnerExpected<factory::PolicyData::Params, const std::shared_ptr<MockStoreRead>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<MockStoreRead>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using ReadT = std::tuple<store::Doc, Expc>;
class ReadData : public testing::TestWithParam<ReadT>
{
};

TEST_P(ReadData, Doc)
{
    auto [doc, expected] = GetParam();
    auto store = std::make_shared<MockStoreRead>();

    if (expected)
    {
        factory::PolicyData got;
        auto expectedData = factory::PolicyData(expected.succCase()(store));
        ASSERT_NO_THROW(got = factory::readData(doc, store));
        ASSERT_EQ(got.name(), expectedData.name());
        ASSERT_EQ(got.hash(), expectedData.hash());
        ASSERT_EQ(got.subgraphs(), expectedData.subgraphs());
    }
    else
    {
        expected.failCase()(store);
        ASSERT_THROW(factory::readData(doc, store), std::runtime_error);
    }
}

using D = factory::PolicyData::Params;
using A = std::unordered_map<store::NamespaceId, std::unordered_set<base::Name>>;

// TODO: add integration testss
INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    ReadData,
    ::testing::Values(
        // Invalid name
        ReadT("{}", FAILURE()),
        ReadT(R"({"name": "test"})", FAILURE()),
        ReadT(R"({"name": 1})", FAILURE()),
        ReadT(R"({"name": ""})", FAILURE()),
        // Invalid hash
        ReadT(R"({"name": "test"})", FAILURE()),
        ReadT(R"({"name": "test", "hash": ""})", FAILURE()),
        ReadT(R"({"name": "test", "hash": 1})", FAILURE()),
        // Invalid default parents
        ReadT(R"({"name": "test", "hash": "test", "default_parents": {"asset": [1]}})", FAILURE()),
        ReadT(R"({"name": "test", "hash": "test", "default_parents": {"asset": [""]}})", FAILURE()),
        ReadT(R"({"name": "test", "hash": "test", "default_parents": {"asset": ["name"]}})", FAILURE()),
        // Invalid assets
        ReadT(R"({"name": "test", "hash": "test", "assets": [1]})", FAILURE()),
        ReadT(R"({"name": "test", "hash": "test", "assets": [""]})", FAILURE()),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["rule/asset"]})",
              FAILURE(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("rule/asset")))
                          .WillOnce(testing::Return(storeGetNamespaceError()));
                      return None {};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["rule/asset", "rule/asset"]})",
              FAILURE(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("rule/asset")))
                          .WillRepeatedly(testing::Return(storeGetNamespaceResp("ns")));
                      return None {};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["asset"]})",
              FAILURE(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("asset")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                      return None {};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["other/asset"]})",
              FAILURE(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("other/asset")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                      return None {};
                  })),
        // Invalid integrations
        // TODO: add more cases
        ReadT(R"({"name": "test", "hash": "test", "assets": ["integration/name"]})",
              FAILURE(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("integration/name")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                      EXPECT_CALL(*store, readDoc(base::Name("integration/name")))
                          .WillOnce(testing::Return(storeReadError<store::Doc>()));
                      return None {};
                  })),
        // SUCCESS cases
        ReadT(R"({"name": "test", "hash": "test"})",
              SUCCESS([](const std::shared_ptr<MockStoreRead>& store) { return D {.name = "test", .hash = "test"}; })),
        ReadT(R"({"name": "test", "hash": "test", "assets": []})",
              SUCCESS([](const std::shared_ptr<MockStoreRead>& store) { return D {.name = "test", .hash = "test"}; })),
        ReadT(
            R"({"name": "test", "hash": "test", "default_parents": {"ns": ["decoder/asset/0"]}, "assets": ["decoder/asset/0"]})",
            SUCCESS(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .defaultParents = {{"ns", "decoder/asset/0"}},
                              .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset/0"}}}}}}};
                })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["decoder/asset/0"]})",
              SUCCESS(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset/0")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                      return D {.name = "test",
                                .hash = "test",
                                .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset/0"}}}}}}};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "defaultParents": {}, "assets": ["decoder/asset/0"]})",
              SUCCESS(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset/0")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                      return D {.name = "test",
                                .hash = "test",
                                .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset/0"}}}}}}};
                  })),
        ReadT(
            R"({"name": "test", "hash": "test", "defaultParents": {"otherNs": "decoder/other/0"}, "assets": ["decoder/asset/0"]})",
            SUCCESS(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset/0"}}}}}}};
                })),
        ReadT(
            R"({"name": "test", "hash": "test", "default_parents": {"ns": ["decoder/asset/0"]}, "assets": ["decoder/asset/0", "output/asset/0", "rule/asset/0", "filter/asset/0"]})",
            SUCCESS(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                    EXPECT_CALL(*store, getNamespace(base::Name("output/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                    EXPECT_CALL(*store, getNamespace(base::Name("rule/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                    EXPECT_CALL(*store, getNamespace(base::Name("filter/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .defaultParents = {{"ns", "decoder/asset/0"}},
                              .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset/0"}}}}},
                                         {factory::PolicyData::AssetType::OUTPUT, {{"ns", {{"output/asset/0"}}}}},
                                         {factory::PolicyData::AssetType::RULE, {{"ns", {{"rule/asset/0"}}}}},
                                         {factory::PolicyData::AssetType::FILTER, {{"ns", {{"filter/asset/0"}}}}}}};
                })),
        ReadT(
            R"({"name": "test", "hash": "test", "default_parents": {"ns": ["rule/asset/0"]}, "assets": ["rule/asset/0"]})",
            SUCCESS(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("rule/asset/0")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .defaultParents = {{"ns", "rule/asset/0"}},
                              .assets = {{factory::PolicyData::AssetType::RULE, {{"ns", {{"rule/asset/0"}}}}}}};
                }))));
} // namespace readtest

namespace buildassetstest
{

using SuccessExpected = InnerExpected<factory::BuiltAssets,
                                      const std::shared_ptr<MockStoreRead>&,
                                      const std::shared_ptr<MockAssetBuilder>&>;
using FailureExpected =
    InnerExpected<None, const std::shared_ptr<MockStoreRead>&, const std::shared_ptr<MockAssetBuilder>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using BuildT = std::tuple<factory::PolicyData, Expc>;
class BuildAssets : public testing::TestWithParam<BuildT>
{
};

TEST_P(BuildAssets, PolicyData)
{
    auto [policyData, expected] = GetParam();
    auto assetBuilder = std::make_shared<MockAssetBuilder>();
    auto store = std::make_shared<MockStoreRead>();
    if (expected)
    {
        factory::BuiltAssets got;
        auto expectedData = expected.succCase()(store, assetBuilder);
        ASSERT_NO_THROW(got = factory::buildAssets(policyData, store, assetBuilder));
        ASSERT_EQ(got, expectedData);
    }
    else
    {
        expected.failCase()(store, assetBuilder);
        ASSERT_THROW(factory::buildAssets(policyData, store, assetBuilder), std::runtime_error);
    }
}

using D = factory::PolicyData::Params;
using A = std::unordered_map<store::NamespaceId, std::unordered_set<base::Name>>;

INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    BuildAssets,
    ::testing::Values(
        BuildT(D {.name = "test", .hash = "test"}, SUCCESS()),
        BuildT(D {.name = "test", .hash = "test", .defaultParents = {{"ns", "decoder/asset"}}}, SUCCESS()),
        BuildT(D {.name = "test",
                  .hash = "test",
                  .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}},
               SUCCESS(
                   [](const std::shared_ptr<MockStoreRead>& store,
                      const std::shared_ptr<MockAssetBuilder>& assetBuilder)
                   {
                       store::Doc asset;
                       EXPECT_CALL(*store, readDoc(base::Name("decoder/asset")))
                           .WillOnce(testing::Return(storeReadDocResp(asset)));
                       EXPECT_CALL(*assetBuilder, CallableOp(asset)).WillOnce(testing::Return(Asset {}));

                       return factory::BuiltAssets(
                           {{factory::PolicyData::AssetType::DECODER, {{"decoder/asset", Asset {}}}}});
                   })),
        BuildT(
            D {.name = "test",
               .hash = "test",
               .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}},
                          {factory::PolicyData::AssetType::RULE, {{"ns", {{"rule/asset"}}}}},
                          {factory::PolicyData::AssetType::OUTPUT, {{"ns", {{"output/asset"}}}}},
                          {factory::PolicyData::AssetType::FILTER, {{"ns", {{"filter/asset"}}}}}}},

            SUCCESS(
                [](const std::shared_ptr<MockStoreRead>& store, const std::shared_ptr<MockAssetBuilder>& assetBuilder)
                {
                    store::Doc asset;
                    EXPECT_CALL(*store, readDoc(testing::_)).WillRepeatedly(testing::Return(storeReadDocResp(asset)));
                    EXPECT_CALL(*assetBuilder, CallableOp(asset)).WillRepeatedly(testing::Return(Asset {}));

                    return factory::BuiltAssets(
                        {{factory::PolicyData::AssetType::DECODER, {{"decoder/asset", Asset {}}}},
                         {factory::PolicyData::AssetType::RULE, {{"rule/asset", Asset {}}}},
                         {factory::PolicyData::AssetType::OUTPUT, {{"output/asset", Asset {}}}},
                         {factory::PolicyData::AssetType::FILTER, {{"filter/asset", Asset {}}}}});
                })),
        BuildT(D {.name = "test",
                  .hash = "test",
                  .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}},
               FAILURE(
                   [](const std::shared_ptr<MockStoreRead>& store,
                      const std::shared_ptr<MockAssetBuilder>& assetBuilder)
                   {
                       store::Doc asset;
                       EXPECT_CALL(*store, readDoc(base::Name("decoder/asset")))
                           .WillOnce(testing::Return(storeReadDocResp(asset)));
                       EXPECT_CALL(*assetBuilder, CallableOp(asset)).WillOnce(testing::Throw(std::runtime_error("")));

                       return None {};
                   })),
        BuildT(D {.name = "test",
                  .hash = "test",
                  .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}},
                             {factory::PolicyData::AssetType::RULE, {{"ns", {{"rule/asset"}}}}},
                             {factory::PolicyData::AssetType::OUTPUT, {{"ns", {{"output/asset"}}}}}}},
               FAILURE(
                   [](const std::shared_ptr<MockStoreRead>& store,
                      const std::shared_ptr<MockAssetBuilder>& assetBuilder)
                   {
                       store::Doc asset;
                       EXPECT_CALL(*store, readDoc(testing::_))
                           .WillOnce(testing::Return(storeReadDocResp(asset)))
                           .WillOnce(testing::Return(storeReadDocResp(asset)));
                       EXPECT_CALL(*assetBuilder, CallableOp(asset))
                           .WillOnce(testing::Return(Asset {}))
                           .WillOnce(testing::Throw(std::runtime_error("")));

                       return None {};
                   })),
        BuildT(D {.name = "test",
                  .hash = "test",
                  .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}},
               FAILURE(
                   [](const std::shared_ptr<MockStoreRead>& store,
                      const std::shared_ptr<MockAssetBuilder>& assetBuilder)
                   {
                       EXPECT_CALL(*store, readDoc(base::Name("decoder/asset")))
                           .WillOnce(testing::Throw(std::runtime_error("")));

                       return None {};
                   })),
        BuildT(D {.name = "test",
                  .hash = "test",
                  .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}},
                             {factory::PolicyData::AssetType::RULE, {{"ns", {{"rule/asset"}}}}}}},
               FAILURE(
                   [](const std::shared_ptr<MockStoreRead>& store,
                      const std::shared_ptr<MockAssetBuilder>& assetBuilder)
                   {
                       store::Doc asset;
                       EXPECT_CALL(*store, readDoc(base::Name("decoder/asset")))
                           .WillOnce(testing::Return(storeReadDocResp(asset)));
                       EXPECT_CALL(*store, readDoc(base::Name("rule/asset")))
                           .WillOnce(testing::Throw(std::runtime_error("")));

                       EXPECT_CALL(*assetBuilder, CallableOp(asset)).WillOnce(testing::Return(Asset {}));

                       return None {};
                   }))

            ));

} // namespace buildassetstest

namespace buildgraphtest
{
using SuccessExpected = InnerExpected<AssetData, None>;
using FailureExpected = InnerExpected<AssetData, None>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using BuildT = std::tuple<Expc>;
class BuildGraph : public testing::TestWithParam<BuildT>
{
};

// TODO: add get graph str tests

TEST_P(BuildGraph, AssetsAndData)
{
    auto [expected] = GetParam();
    if (expected)
    {
        auto assetData = expected.succCase()(None {});
        auto builtAssets = assetData.builtAssets;
        auto policyData = assetData.policyData;
        auto expectedGraph = assetData.policyGraph;
        factory::PolicyGraph got;
        ASSERT_NO_THROW(got = factory::buildGraph(builtAssets, policyData));

        auto strData = [&]() -> std::string
        {
            std::stringstream ss;
            ss << "Got:\n";
            for (auto [type, graph] : got.subgraphs)
            {
                ss << graph.getGraphStr() << "\n";
            }
            ss << "Expected:\n";
            for (auto [type, graph] : expectedGraph.subgraphs)
            {
                ss << graph.getGraphStr() << "\n";
            }

            return ss.str();
        };

        // Edges are ordered, but assets not, we cannot rely that edges will be in the same order
        // ASSERT_EQ(got, expectedGraph)
        // So we do manual comparison of each part of the graph
        for (auto [type, graph] : got.subgraphs)
        {
            ASSERT_EQ(graph.node(graph.rootId()), expectedGraph.subgraphs.at(type).node(graph.rootId())) << strData();

            ASSERT_EQ(graph.nodes().size(), expectedGraph.subgraphs.at(type).nodes().size()) << strData();
            for (auto [key, node] : graph.nodes())
            {
                // We do not compare the actual Asset because Expressions are hold on a shared_ptr
                // Thus, the comparison will always fail as the pointers will be different
                ASSERT_TRUE(expectedGraph.subgraphs.at(type).nodes().find(key)
                            != expectedGraph.subgraphs.at(type).nodes().end())
                    << strData();
            }

            ASSERT_EQ(graph.edges().size(), expectedGraph.subgraphs.at(type).edges().size()) << strData();
            for (auto [parent, children] : graph.edges())
            {
                auto expectedChildren = expectedGraph.subgraphs.at(type).children(parent);
                ASSERT_EQ(children.size(), expectedChildren.size()) << strData();
                for (auto child : children)
                {
                    ASSERT_TRUE(std::find(expectedChildren.begin(), expectedChildren.end(), child)
                                != expectedChildren.end())
                        << strData();
                }
            }
        }
    }
    else
    {
        auto assetData = expected.failCase()(None {});
        auto builtAssets = assetData.builtAssets;
        auto policyData = assetData.policyData;
        ASSERT_THROW(factory::buildGraph(builtAssets, policyData), std::runtime_error);
    }
}

using AD = AssetData;
using AT = factory::PolicyData::AssetType;
INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    BuildGraph,
    testing::Values(
        // Fail cases
        // Missing decoder
        BuildT(FAILURE(AD()(AT::DECODER, "decoder/asset", "decoder/missing"))),
        BuildT(FAILURE(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/Input"))),
        BuildT(FAILURE(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3"))),
        // Missing rule
        BuildT(FAILURE(AD()(AT::DECODER, "decoder/asset", "decoder/Input")(AT::RULE, "rule/asset", "rule/missing"))),
        // Missing output
        BuildT(FAILURE(AD()(AT::DECODER, "decoder/asset", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
            AT::OUTPUT, "output/asset", "output/missing"))),
        // Cross asset dependencies
        BuildT(FAILURE(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "output/asset")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
            AT::OUTPUT, "output/asset", "output/Input"))),
        // SUCCESS cases
        BuildT(SUCCESS()),
        BuildT(SUCCESS(AD()(AT::DECODER, "decoder/asset", "decoder/Input"))),
        BuildT(SUCCESS(
            AD()(AT::DECODER, "decoder/asset", "decoder/parent")(AT::DECODER, "decoder/parent", "decoder/Input"))),
        BuildT(SUCCESS(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/Input")(AT::DECODER, "decoder/parent2", "decoder/Input"))),
        BuildT(SUCCESS(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input"))),
        BuildT(SUCCESS(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
            AT::OUTPUT, "output/asset", "output/Input"))),
        BuildT(SUCCESS(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/parent1", "rule/parent2")(
            AT::RULE, "rule/parent1", "rule/parent3")(AT::RULE, "rule/parent2", "rule/parent3")(
            AT::RULE, "rule/parent3", "rule/Input")(AT::OUTPUT, "output/asset", "output/parent1", "output/parent2")(
            AT::OUTPUT, "output/parent1", "output/parent3")(AT::OUTPUT, "output/parent2", "output/parent3")(
            AT::OUTPUT, "output/parent3", "output/Input"))),
        BuildT(SUCCESS(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/parent1", "rule/parent2")(
            AT::RULE, "rule/parent1", "rule/parent3")(AT::RULE, "rule/parent2", "rule/parent3")(
            AT::RULE, "rule/parent3", "rule/Input")(AT::OUTPUT, "output/asset", "output/parent1", "output/parent2")(
            AT::OUTPUT, "output/parent1", "output/parent3")(AT::OUTPUT, "output/parent2", "output/parent3")(
            AT::OUTPUT, "output/parent3", "output/Input")(AT::FILTER, "filter/asset1", "decoder/parent1")(
            AT::FILTER, "filter/asset2", "rule/parent2")(AT::FILTER, "filter/asset3", "output/parent3")))

            ));
} // namespace buildgraphtest

namespace buildexpressiontest
{
using SuccessExpected = InnerExpected<base::Expression, None>;
using FailureExpected = InnerExpected<None, None>;

using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using AD = buildgraphtest::AssetData;
using buildgraphtest::assetExpr;
using BuildT = std::tuple<AD, Expc>;
class BuildExpression : public testing::TestWithParam<BuildT>
{
};

TEST_P(BuildExpression, GraphAndData)
{
    auto [assetData, expected] = GetParam();
    if (expected)
    {
        auto policyData = assetData.policyData;
        auto policyGraph = assetData.policyGraph;
        auto expectedExpr = expected.succCase()(None {});
        base::Expression got;
        ASSERT_NO_THROW(got = factory::buildExpression(policyGraph, policyData));

        builder::test::assertEqualExpr(got, expectedExpr);
    }
    else
    {
        auto policyData = assetData.policyData;
        auto policyGraph = assetData.policyGraph;
        ASSERT_THROW(factory::buildExpression(policyGraph, policyData), std::runtime_error);
    }
}

using AT = factory::PolicyData::AssetType;
using namespace base;
INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    BuildExpression,
    testing::Values(
        // Empty graph
        BuildT(AD(), SUCCESS(Chain::create("policy/testname", {}))),
        // Single assets
        BuildT(AD()(AT::DECODER, "decoder/asset", "decoder/Input"),
               SUCCESS(Chain::create("policy/testname", {Or::create("decoder/Input", {assetExpr("decoder/asset")})}))),
        BuildT(AD()(AT::RULE, "rule/asset", "rule/Input"),
               SUCCESS(Chain::create("policy/testname", {Broadcast::create("rule/Input", {assetExpr("rule/asset")})}))),
        BuildT(AD()(AT::OUTPUT, "output/asset", "output/Input"),
               SUCCESS(Chain::create("policy/testname",
                                     {Broadcast::create("output/Input", {assetExpr("output/asset")})}))),
        // One of each asset
        BuildT(AD()(AT::DECODER, "decoder/asset", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
                   AT::OUTPUT, "output/asset", "output/Input"),
               SUCCESS(Chain::create("policy/testname",
                                     {Or::create("decoder/Input", {assetExpr("decoder/asset")}),
                                      Broadcast::create("rule/Input", {assetExpr("rule/asset")}),
                                      Broadcast::create("output/Input", {assetExpr("output/asset")})}))),
        // One parent
        BuildT(AD()(AT::DECODER, "decoder/asset", "decoder/parent")(AT::DECODER, "decoder/parent", "decoder/Input"),
               SUCCESS(Chain::create("policy/testname",
                                     {Or::create("decoder/Input",
                                                 {Implication::create("decoder/parent/Node",
                                                                      assetExpr("decoder/parent"),
                                                                      Or::create("decoder/parent/Children",
                                                                                 {assetExpr("decoder/asset")}))})}))),
        BuildT(AD()(AT::RULE, "rule/asset", "rule/parent")(AT::RULE, "rule/parent", "rule/Input"),
               SUCCESS(Chain::create(
                   "policy/testname",
                   {Broadcast::create("rule/Input",
                                      {Implication::create("rule/parent/Node",
                                                           assetExpr("rule/parent"),
                                                           Broadcast::create("rule/parent/Children",
                                                                             {assetExpr("rule/asset")}))})}))),
        BuildT(AD()(AT::OUTPUT, "output/asset", "output/parent")(AT::OUTPUT, "output/parent", "output/Input"),
               SUCCESS(Chain::create(
                   "policy/testname",
                   {Broadcast::create("output/Input",
                                      {Implication::create("output/parent/Node",
                                                           assetExpr("output/parent"),
                                                           Broadcast::create("output/parent/Children",
                                                                             {assetExpr("output/asset")}))})}))),
        // One parent for each asset
        BuildT(
            AD()(AT::DECODER, "decoder/asset", "decoder/parent")(AT::DECODER, "decoder/parent", "decoder/Input")(
                AT::RULE, "rule/asset", "rule/parent")(AT::RULE, "rule/parent", "rule/Input")(
                AT::OUTPUT, "output/asset", "output/parent")(AT::OUTPUT, "output/parent", "output/Input"),
            SUCCESS(Chain::create(
                "policy/testname",
                {Or::create("decoder/Input",
                            {Implication::create("decoder/parent/Node",
                                                 assetExpr("decoder/parent"),
                                                 Or::create("decoder/parent/Children", {assetExpr("decoder/asset")}))}),
                 Broadcast::create("rule/Input",
                                   {Implication::create("rule/parent/Node",
                                                        assetExpr("rule/parent"),
                                                        Broadcast::create("rule/parent/Children",
                                                                          {assetExpr("rule/asset")}))}),
                 Broadcast::create("output/Input",
                                   {Implication::create("output/parent/Node",
                                                        assetExpr("output/parent"),
                                                        Broadcast::create("output/parent/Children",
                                                                          {assetExpr("output/asset")}))})}))),
        // Two parents
        BuildT(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
                   AT::DECODER, "decoder/parent1", "decoder/Input")(AT::DECODER, "decoder/parent2", "decoder/Input"),
               SUCCESS(Chain::create("policy/testname",
                                     {Or::create("decoder/Input",
                                                 {Implication::create("decoder/parent1/Node",
                                                                      assetExpr("decoder/parent1"),
                                                                      Or::create("decoder/parent1/Children",
                                                                                 {assetExpr("decoder/asset")})),
                                                  Implication::create("decoder/parent2/Node",
                                                                      assetExpr("decoder/parent2"),
                                                                      Or::create("decoder/parent2/Children",
                                                                                 {assetExpr("decoder/asset")}))})}))),
        BuildT(
            AD()(AT::RULE, "rule/asset", "rule/parent1", "rule/parent2")(AT::RULE, "rule/parent1", "rule/Input")(
                AT::RULE, "rule/parent2", "rule/Input"),
            SUCCESS(Chain::create(
                "policy/testname",
                {Broadcast::create(
                    "rule/Input",
                    {Implication::create("rule/parent1/Node",
                                         assetExpr("rule/parent1"),
                                         Broadcast::create("rule/parent1/Children", {assetExpr("rule/asset")})),
                     Implication::create("rule/parent2/Node",
                                         assetExpr("rule/parent2"),
                                         Broadcast::create("rule/parent2/Children", {assetExpr("rule/asset")}))})}))),
        BuildT(AD()(AT::OUTPUT, "output/asset", "output/parent1", "output/parent2")(
                   AT::OUTPUT, "output/parent1", "output/Input")(AT::OUTPUT, "output/parent2", "output/Input"),
               SUCCESS(Chain::create(
                   "policy/testname",
                   {Broadcast::create("output/Input",
                                      {Implication::create("output/parent1/Node",
                                                           assetExpr("output/parent1"),
                                                           Broadcast::create("output/parent1/Children",
                                                                             {assetExpr("output/asset")})),
                                       Implication::create("output/parent2/Node",
                                                           assetExpr("output/parent2"),
                                                           Broadcast::create("output/parent2/Children",
                                                                             {assetExpr("output/asset")}))})}))),
        // Two parents for each asset type
        BuildT(
            AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
                AT::DECODER, "decoder/parent1", "decoder/Input")(AT::DECODER, "decoder/parent2", "decoder/Input")(
                AT::RULE, "rule/asset", "rule/parent1", "rule/parent2")(AT::RULE, "rule/parent1", "rule/Input")(
                AT::RULE, "rule/parent2", "rule/Input")(AT::OUTPUT, "output/asset", "output/parent1", "output/parent2")(
                AT::OUTPUT, "output/parent1", "output/Input")(AT::OUTPUT, "output/parent2", "output/Input"),
            SUCCESS(Chain::create(
                "policy/testname",
                {Or::create("decoder/Input",
                            {Implication::create("decoder/parent1/Node",
                                                 assetExpr("decoder/parent1"),
                                                 Or::create("decoder/parent1/Children", {assetExpr("decoder/asset")})),
                             Implication::create("decoder/parent2/Node",
                                                 assetExpr("decoder/parent2"),
                                                 Or::create("decoder/parent2/Children",
                                                            {assetExpr("decoder/asset")}))}),
                 Broadcast::create(
                     "rule/Input",
                     {Implication::create("rule/parent1/Node",
                                          assetExpr("rule/parent1"),
                                          Broadcast::create("rule/parent1/Children", {assetExpr("rule/asset")})),
                      Implication::create("rule/parent2/Node",
                                          assetExpr("rule/parent2"),
                                          Broadcast::create("rule/parent2/Children", {assetExpr("rule/asset")}))}),
                 Broadcast::create("output/Input",
                                   {Implication::create("output/parent1/Node",
                                                        assetExpr("output/parent1"),
                                                        Broadcast::create("output/parent1/Children",
                                                                          {assetExpr("output/asset")})),
                                    Implication::create("output/parent2/Node",
                                                        assetExpr("output/parent2"),
                                                        Broadcast::create("output/parent2/Children",
                                                                          {assetExpr("output/asset")}))})}))),
        // One asset with one parent, one asset with two parents (sharing one parent), one asset child of the first
        // and one asset child of root
        BuildT(AD()(AT::DECODER, "decoder/child1", "decoder/parent1")(
                   AT::DECODER, "decoder/child2", "decoder/parent1", "decoder/parent2")(
                   AT::DECODER, "decoder/child3", "decoder/child1")(AT::DECODER, "decoder/parent1", "decoder/Input")(
                   AT::DECODER, "decoder/parent2", "decoder/Input")(AT::DECODER, "decoder/child4", "decoder/Input"),
               SUCCESS(Chain::create(
                   "policy/testname",
                   {Or::create(
                       "decoder/Input",
                       {Implication::create("decoder/parent1/Node",
                                            assetExpr("decoder/parent1"),
                                            Or::create("decoder/parent1/Children",
                                                       {Implication::create("decoder/child1/Node",
                                                                            assetExpr("decoder/child1"),
                                                                            Or::create("decoder/child1/Children",
                                                                                       {assetExpr("decoder/child3")})),
                                                        assetExpr("decoder/child2")})),
                        Implication::create("decoder/parent2/Node",
                                            assetExpr("decoder/parent2"),
                                            Or::create("decoder/parent2/Children", {assetExpr("decoder/child2")})),
                        assetExpr("decoder/child4")})}))),
        BuildT(AD()(AT::RULE, "rule/child1", "rule/parent1")(AT::RULE, "rule/child2", "rule/parent1", "rule/parent2")(
                   AT::RULE, "rule/child3", "rule/child1")(AT::RULE, "rule/parent1", "rule/Input")(
                   AT::RULE, "rule/parent2", "rule/Input")(AT::RULE, "rule/child4", "rule/Input"),
               SUCCESS(Chain::create(
                   "policy/testname",
                   {Broadcast::create(
                       "rule/Input",
                       {Implication::create(
                            "rule/parent1/Node",
                            assetExpr("rule/parent1"),
                            Broadcast::create("rule/parent1/Children",
                                              {Implication::create("rule/child1/Node",
                                                                   assetExpr("rule/child1"),
                                                                   Broadcast::create("rule/child1/Children",
                                                                                     {assetExpr("rule/child3")})),
                                               assetExpr("rule/child2")})),
                        Implication::create("rule/parent2/Node",
                                            assetExpr("rule/parent2"),
                                            Broadcast::create("rule/parent2/Children", {assetExpr("rule/child2")})),
                        assetExpr("rule/child4")})}))),
        BuildT(AD()(AT::OUTPUT, "output/child1", "output/parent1")(
                   AT::OUTPUT, "output/child2", "output/parent1", "output/parent2")(
                   AT::OUTPUT, "output/child3", "output/child1")(AT::OUTPUT, "output/parent1", "output/Input")(
                   AT::OUTPUT, "output/parent2", "output/Input")(AT::OUTPUT, "output/child4", "output/Input"),
               SUCCESS(Chain::create(
                   "policy/testname",
                   {Broadcast::create(
                       "output/Input",
                       {Implication::create(
                            "output/parent1/Node",
                            assetExpr("output/parent1"),
                            Broadcast::create("output/parent1/Children",
                                              {Implication::create("output/child1/Node",
                                                                   assetExpr("output/child1"),
                                                                   Broadcast::create("output/child1/Children",
                                                                                     {assetExpr("output/child3")})),
                                               assetExpr("output/child2")})),
                        Implication::create("output/parent2/Node",
                                            assetExpr("output/parent2"),
                                            Broadcast::create("output/parent2/Children", {assetExpr("output/child2")})),
                        assetExpr("output/child4")})}))),
        // complex graph (last use case for each asset type)
        BuildT(
            AD()(AT::DECODER, "decoder/child1", "decoder/parent1")(
                AT::DECODER, "decoder/child2", "decoder/parent1", "decoder/parent2")(
                AT::DECODER, "decoder/child3", "decoder/child1")(AT::DECODER, "decoder/parent1", "decoder/Input")(
                AT::DECODER, "decoder/parent2", "decoder/Input")(AT::DECODER, "decoder/child4", "decoder/Input")(
                AT::RULE, "rule/child1", "rule/parent1")(AT::RULE, "rule/child2", "rule/parent1", "rule/parent2")(
                AT::RULE, "rule/child3", "rule/child1")(AT::RULE, "rule/parent1", "rule/Input")(
                AT::RULE, "rule/parent2", "rule/Input")(AT::RULE, "rule/child4", "rule/Input")(
                AT::OUTPUT, "output/child1", "output/parent1")(
                AT::OUTPUT, "output/child2", "output/parent1", "output/parent2")(
                AT::OUTPUT, "output/child3", "output/child1")(AT::OUTPUT, "output/parent1", "output/Input")(
                AT::OUTPUT, "output/parent2", "output/Input")(AT::OUTPUT, "output/child4", "output/Input"),
            SUCCESS(Chain::create(
                "policy/testname",
                {Or::create(
                     "decoder/Input",
                     {Implication::create("decoder/parent1/Node",
                                          assetExpr("decoder/parent1"),
                                          Or::create("decoder/parent1/Children",
                                                     {Implication::create("decoder/child1/Node",
                                                                          assetExpr("decoder/child1"),
                                                                          Or::create("decoder/child1/Children",
                                                                                     {assetExpr("decoder/child3")})),
                                                      assetExpr("decoder/child2")})),
                      Implication::create("decoder/parent2/Node",
                                          assetExpr("decoder/parent2"),
                                          Or::create("decoder/parent2/Children", {assetExpr("decoder/child2")})),
                      assetExpr("decoder/child4")}),
                 Broadcast::create(
                     "rule/Input",
                     {Implication::create(
                          "rule/parent1/Node",
                          assetExpr("rule/parent1"),
                          Broadcast::create("rule/parent1/Children",
                                            {Implication::create("rule/child1/Node",
                                                                 assetExpr("rule/child1"),
                                                                 Broadcast::create("rule/child1/Children",
                                                                                   {assetExpr("rule/child3")})),
                                             assetExpr("rule/child2")})),
                      Implication::create("rule/parent2/Node",
                                          assetExpr("rule/parent2"),
                                          Broadcast::create("rule/parent2/Children", {assetExpr("rule/child2")})),
                      assetExpr("rule/child4")}),
                 Broadcast::create(
                     "output/Input",
                     {Implication::create(
                          "output/parent1/Node",
                          assetExpr("output/parent1"),
                          Broadcast::create("output/parent1/Children",
                                            {Implication::create("output/child1/Node",
                                                                 assetExpr("output/child1"),
                                                                 Broadcast::create("output/child1/Children",
                                                                                   {assetExpr("output/child3")})),
                                             assetExpr("output/child2")})),
                      Implication::create("output/parent2/Node",
                                          assetExpr("output/parent2"),
                                          Broadcast::create("output/parent2/Children", {assetExpr("output/child2")})),
                      assetExpr("output/child4")})})))

            ));

} // namespace buildexpressiontest
namespace buildsubgraphtest
{
using buildgraphtest::assetExpr;

struct SubgraphCase
{
    Graph<base::Name, Asset> subgraph;
    bool reverseOrderDecoders; // only applies for Or
    std::shared_ptr<base::Operation> expected;
};

class BuildSubgraphOr : public ::testing::TestWithParam<SubgraphCase>
{
};

TEST_P(BuildSubgraphOr, OrOperation)
{
    const auto& param = GetParam();
    const auto& graph = param.subgraph;
    bool reverseOrderDecoders = param.reverseOrderDecoders;

    base::Expression got;
    ASSERT_NO_THROW({ got = factory::buildSubgraphExpression<base::Or>(graph, reverseOrderDecoders); });

    builder::test::assertEqualExpr(got, param.expected);
}

static Graph<base::Name, Asset> makeEmptyGraph()
{
    Graph<base::Name, Asset> g;
    g.setRoot("__ROOT__",
              Asset("__ROOT__", assetExpr("__ROOT__"), std::vector<base::Name> {} // root has no parents
                    ));
    return g;
}

using namespace base;
INSTANTIATE_TEST_SUITE_P(OrOperation,
                         BuildSubgraphOr,
                         ::testing::Values(
                             // A single child "H" under the root.
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aH("H", assetExpr("H"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("H", std::move(aH));
                                               g.addEdge("__ROOT__", "H");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ false,
                                           /* expected */ Or::create("__ROOT__", {assetExpr("H")})},

                             // Parent "P" with one child "C"
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP("P", assetExpr("P"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P", std::move(aP));
                                               g.addEdge("__ROOT__", "P");
                                               Asset aC("C", assetExpr("C"), std::vector<base::Name> {"P"});
                                               g.addNode("C", std::move(aC));
                                               g.addEdge("P", "C");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ false,
                                           /* expected */
                                           []()
                                           {
                                               auto children = Or::create("P/Children", {});
                                               children->getOperands().push_back(assetExpr("C"));
                                               auto impl = Implication::create("P/Node", assetExpr("P"), children);
                                               return Or::create("__ROOT__", {impl});
                                           }()},

                             // Same graph as before with reverseOrderDecoders=true.
                             // Since P has only one child, reversing does nothing.
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP("P", assetExpr("P"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P", std::move(aP));
                                               g.addEdge("__ROOT__", "P");
                                               Asset aC("C", assetExpr("C"), std::vector<base::Name> {"P"});
                                               g.addNode("C", std::move(aC));
                                               g.addEdge("P", "C");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ true,
                                           /* expected */
                                           []()
                                           {
                                               auto children = Or::create("P/Children", {});
                                               children->getOperands().push_back(assetExpr("C"));
                                               auto impl = Implication::create("P/Node", assetExpr("P"), children);
                                               return Or::create("__ROOT__", {impl});
                                           }()},

                             // Parent "P" with two children "C1" and "C2" in that order:
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP("P", assetExpr("P"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P", std::move(aP));
                                               g.addEdge("__ROOT__", "P");
                                               Asset aC1("C1", assetExpr("C1"), std::vector<base::Name> {"P"});
                                               g.addNode("C1", std::move(aC1));
                                               g.addEdge("P", "C1");
                                               Asset aC2("C2", assetExpr("C2"), std::vector<base::Name> {"P"});
                                               g.addNode("C2", std::move(aC2));
                                               g.addEdge("P", "C2");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ false,
                                           /* expected */
                                           []()
                                           {
                                               auto children = Or::create("P/Children", {});
                                               children->getOperands().push_back(assetExpr("C1"));
                                               children->getOperands().push_back(assetExpr("C2"));
                                               auto impl = Implication::create("P/Node", assetExpr("P"), children);
                                               return Or::create("__ROOT__", {impl});
                                           }()},

                             // Same graph as before, but reverseOrderDecoders = true → reverses to [C2, C1]
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP("P", assetExpr("P"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P", std::move(aP));
                                               g.addEdge("__ROOT__", "P");
                                               Asset aC1("C1", assetExpr("C1"), std::vector<base::Name> {"P"});
                                               g.addNode("C1", std::move(aC1));
                                               g.addEdge("P", "C1");
                                               Asset aC2("C2", assetExpr("C2"), std::vector<base::Name> {"P"});
                                               g.addNode("C2", std::move(aC2));
                                               g.addEdge("P", "C2");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ true,
                                           /* expected */
                                           []()
                                           {
                                               auto children = Or::create("P/Children", {});
                                               children->getOperands().push_back(assetExpr("C2"));
                                               children->getOperands().push_back(assetExpr("C1"));
                                               auto impl = Implication::create("P/Node", assetExpr("P"), children);
                                               return Or::create("__ROOT__", {impl});
                                           }()},

                             // Two parents "P1" and "P2" sharing child "C":
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP1("P1", assetExpr("P1"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P1", std::move(aP1));
                                               g.addEdge("__ROOT__", "P1");
                                               Asset aP2("P2", assetExpr("P2"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P2", std::move(aP2));
                                               g.addEdge("__ROOT__", "P2");
                                               Asset aC("C", assetExpr("C"), std::vector<base::Name> {"P1", "P2"});
                                               g.addNode("C", std::move(aC));
                                               g.addEdge("P1", "C");
                                               g.addEdge("P2", "C");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ false,
                                           /* expected */
                                           []()
                                           {
                                               auto children1 = Or::create("P1/Children", {});
                                               children1->getOperands().push_back(assetExpr("C"));
                                               auto impl1 = Implication::create("P1/Node", assetExpr("P1"), children1);

                                               auto children2 = Or::create("P2/Children", {});
                                               children2->getOperands().push_back(assetExpr("C"));
                                               auto impl2 = Implication::create("P2/Node", assetExpr("P2"), children2);

                                               return Or::create("__ROOT__", {impl1, impl2});
                                           }()},

                             // Two parents "P1" and "P2", each with two children, using reverse.
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP1("P1", assetExpr("P1"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P1", std::move(aP1));
                                               g.addEdge("__ROOT__", "P1");
                                               Asset aP2("P2", assetExpr("P2"), std::vector<base::Name> {"__ROOT__"});
                                               g.addNode("P2", std::move(aP2));
                                               g.addEdge("__ROOT__", "P2");
                                               Asset aA("A", assetExpr("A"), std::vector<base::Name> {"P1"});
                                               g.addNode("A", std::move(aA));
                                               g.addEdge("P1", "A");
                                               Asset aB("B", assetExpr("B"), std::vector<base::Name> {"P1"});
                                               g.addNode("B", std::move(aB));
                                               g.addEdge("P1", "B");
                                               Asset aC("C", assetExpr("C"), std::vector<base::Name> {"P2"});
                                               g.addNode("C", std::move(aC));
                                               g.addEdge("P2", "C");
                                               Asset aD("D", assetExpr("D"), std::vector<base::Name> {"P2"});
                                               g.addNode("D", std::move(aD));
                                               g.addEdge("P2", "D");
                                               return g;
                                           }(),
                                           /* reverseOrderDecoders */ true,
                                           /* expected */
                                           []()
                                           {
                                               auto children1 = Or::create("P1/Children", {});
                                               children1->getOperands().push_back(assetExpr("B"));
                                               children1->getOperands().push_back(assetExpr("A"));
                                               auto impl1 = Implication::create("P1/Node", assetExpr("P1"), children1);

                                               auto children2 = Or::create("P2/Children", {});
                                               children2->getOperands().push_back(assetExpr("D"));
                                               children2->getOperands().push_back(assetExpr("C"));
                                               auto impl2 = Implication::create("P2/Node", assetExpr("P2"), children2);

                                               return Or::create("__ROOT__", {impl1, impl2});
                                           }()}));

} // namespace buildsubgraphtest
