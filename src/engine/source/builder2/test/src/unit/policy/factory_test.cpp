#include <gtest/gtest.h>

#include <sstream>

#include <store/mockStore.hpp>
#include <test/behaviour.hpp>

#include "builders/mockRegistry.hpp"
#include "factory_test.hpp"
#include "policy/factory.hpp"
#include "policy/mockAssetBuilder.hpp"

using namespace builder::policy;
using namespace base::test;
using namespace store::mocks;
using namespace builder::builders::mocks;
using namespace builder::policy::mocks;

namespace readtest
{
using SuccessExpected = InnerExpected<factory::PolicyData::Params, const std::shared_ptr<MockStoreRead>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<MockStoreRead>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto Success = Expc::success();
auto Failure = Expc::failure();

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
        ReadT("{}", Failure()),
        ReadT(R"({"name": "test"})", Failure()),
        ReadT(R"({"name": 1})", Failure()),
        ReadT(R"({"name": ""})", Failure()),
        // Invalid hash
        ReadT(R"({"name": "test"})", Failure()),
        ReadT(R"({"name": "test", "hash": ""})", Failure()),
        ReadT(R"({"name": "test", "hash": 1})", Failure()),
        // Invalid default parents
        ReadT(R"({"name": "test", "hash": "test", "default_parents": {"asset": 1}})", Failure()),
        ReadT(R"({"name": "test", "hash": "test", "default_parents": {"asset": ""}})", Failure()),
        ReadT(R"({"name": "test", "hash": "test", "default_parents": {"asset": "name"}})", Failure()),
        // Invalid assets
        ReadT(R"({"name": "test", "hash": "test"})", Failure()),
        ReadT(R"({"name": "test", "hash": "test", "assets": []})", Failure()),
        ReadT(R"({"name": "test", "hash": "test", "assets": [1]})", Failure()),
        ReadT(R"({"name": "test", "hash": "test", "assets": [""]})", Failure()),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["rule/asset"]})",
              Failure(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("rule/asset")))
                          .WillOnce(testing::Return(storeGetNamespaceError()));
                      return None {};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["rule/asset", "rule/asset"]})",
              Failure(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("rule/asset")))
                          .WillRepeatedly(testing::Return(storeGetNamespaceResp("ns")));
                      return None {};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["asset"]})",
              Failure(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("asset")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                      return None {};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["other/asset"]})",
              Failure(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("other/asset")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                      return None {};
                  })),
        // Invalid integrations
        // TODO: add more cases
        ReadT(R"({"name": "test", "hash": "test", "assets": ["integration/name"]})",
              Failure(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("integration/name")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                      EXPECT_CALL(*store, readDoc(base::Name("integration/name")))
                          .WillOnce(testing::Return(storeReadError<store::Doc>()));
                      return None {};
                  })),
        // Success cases
        ReadT(
            R"({"name": "test", "hash": "test", "default_parents": {"ns": "decoder/asset"}, "assets": ["decoder/asset"]})",
            Success(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .defaultParents = {{"ns", "decoder/asset"}},
                              .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}};
                })),
        ReadT(R"({"name": "test", "hash": "test", "assets": ["decoder/asset"]})",
              Success(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                      return D {.name = "test",
                                .hash = "test",
                                .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}};
                  })),
        ReadT(R"({"name": "test", "hash": "test", "defaultParents": {}, "assets": ["decoder/asset"]})",
              Success(
                  [](const std::shared_ptr<MockStoreRead>& store)
                  {
                      EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset")))
                          .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                      return D {.name = "test",
                                .hash = "test",
                                .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}};
                  })),
        ReadT(
            R"({"name": "test", "hash": "test", "defaultParents": {"otherNs": "decoder/other"}, "assets": ["decoder/asset"]})",
            Success(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}};
                })),
        ReadT(
            R"({"name": "test", "hash": "test", "default_parents": {"ns": "decoder/asset"}, "assets": ["decoder/asset", "output/asset", "rule/asset", "filter/asset"]})",
            Success(
                [](const std::shared_ptr<MockStoreRead>& store)
                {
                    EXPECT_CALL(*store, getNamespace(base::Name("decoder/asset")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                    EXPECT_CALL(*store, getNamespace(base::Name("output/asset")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                    EXPECT_CALL(*store, getNamespace(base::Name("rule/asset")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));
                    EXPECT_CALL(*store, getNamespace(base::Name("filter/asset")))
                        .WillOnce(testing::Return(storeGetNamespaceResp("ns")));

                    return D {.name = "test",
                              .hash = "test",
                              .defaultParents = {{"ns", "decoder/asset"}},
                              .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}},
                                         {factory::PolicyData::AssetType::OUTPUT, {{"ns", {{"output/asset"}}}}},
                                         {factory::PolicyData::AssetType::RULE, {{"ns", {{"rule/asset"}}}}},
                                         {factory::PolicyData::AssetType::FILTER, {{"ns", {{"filter/asset"}}}}}}};
                }))

            ));
} // namespace readtest

namespace buildassetstest
{

using SuccessExpected = InnerExpected<factory::BuiltAssets,
                                      const std::shared_ptr<MockStoreRead>&,
                                      const std::shared_ptr<MockAssetBuilder>&>;
using FailureExpected =
    InnerExpected<None, const std::shared_ptr<MockStoreRead>&, const std::shared_ptr<MockAssetBuilder>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto Success = Expc::success();
auto Failure = Expc::failure();

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
        BuildT(D {.name = "test", .hash = "test"}, Success()),
        BuildT(D {.name = "test", .hash = "test", .defaultParents = {{"ns", "decoder/asset"}}}, Success()),
        BuildT(D {.name = "test",
                  .hash = "test",
                  .assets = {{factory::PolicyData::AssetType::DECODER, {{"ns", {{"decoder/asset"}}}}}}},
               Success(
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

            Success(
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
               Failure(
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
               Failure(
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
               Failure(
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
               Failure(
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
auto Success = Expc::success();
auto Failure = Expc::failure();

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
        BuildT(Failure(AD()(AT::DECODER, "decoder/asset", "decoder/missing"))),
        BuildT(Failure(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/Input"))),
        BuildT(Failure(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3"))),
        // Missing rule
        BuildT(Failure(AD()(AT::DECODER, "decoder/asset", "decoder/Input")(AT::RULE, "rule/asset", "rule/missing"))),
        // Missing output
        BuildT(Failure(AD()(AT::DECODER, "decoder/asset", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
            AT::OUTPUT, "output/asset", "output/missing"))),
        // Cross asset dependencies
        BuildT(Failure(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "output/asset")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
            AT::OUTPUT, "output/asset", "output/Input"))),
        // Success cases
        BuildT(Success()),
        BuildT(Success(AD()(AT::DECODER, "decoder/asset", "decoder/Input"))),
        BuildT(Success(
            AD()(AT::DECODER, "decoder/asset", "decoder/parent")(AT::DECODER, "decoder/parent", "decoder/Input"))),
        BuildT(Success(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/Input")(AT::DECODER, "decoder/parent2", "decoder/Input"))),
        BuildT(Success(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input"))),
        BuildT(Success(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/Input")(
            AT::OUTPUT, "output/asset", "output/Input"))),
        BuildT(Success(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
            AT::DECODER, "decoder/parent1", "decoder/parent3")(AT::DECODER, "decoder/parent2", "decoder/parent3")(
            AT::DECODER, "decoder/parent3", "decoder/Input")(AT::RULE, "rule/asset", "rule/parent1", "rule/parent2")(
            AT::RULE, "rule/parent1", "rule/parent3")(AT::RULE, "rule/parent2", "rule/parent3")(
            AT::RULE, "rule/parent3", "rule/Input")(AT::OUTPUT, "output/asset", "output/parent1", "output/parent2")(
            AT::OUTPUT, "output/parent1", "output/parent3")(AT::OUTPUT, "output/parent2", "output/parent3")(
            AT::OUTPUT, "output/parent3", "output/Input"))),
        BuildT(Success(AD()(AT::DECODER, "decoder/asset", "decoder/parent1", "decoder/parent2")(
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
auto Success = Expc::success();
auto Failure = Expc::failure();

using AD = buildgraphtest::AssetData;
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

        // TODO manual comparison through visitor and test cases;
    }
    else
    {
        auto policyData = assetData.policyData;
        auto policyGraph = assetData.policyGraph;
        ASSERT_THROW(factory::buildExpression(policyGraph, policyData), std::runtime_error);
    }
}

using AT = factory::PolicyData::AssetType;
INSTANTIATE_TEST_SUITE_P(PolicyFactory,
                         BuildExpression,
                         testing::Values(BuildT(AD(), Success())

                                             ));

} // namespace buildexpressiontest
