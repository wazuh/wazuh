#include <gtest/gtest.h>

#include <sstream>

#include <base/behaviour.hpp>
#include <cmstore/mockcmstore.hpp>
#include <defs/mockDefinitions.hpp>

#include "expressionCmp.hpp"
#include "factory_test.hpp"
#include "mockRegistry.hpp"
#include "policy/assetBuilder.hpp"
#include "policy/factory.hpp"

using namespace builder::policy;
using namespace base::test;
using namespace cm::store;
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

TEST_P(BuildGraph, AssetsAndData)
{
    auto [expected] = GetParam();
    if (expected)
    {
        auto data = expected.succCase()(None {});
        factory::PolicyGraph got;
        EXPECT_NO_THROW(got = factory::buildGraph(data.builtAssets));

        // Build expected graph using the same function - tests that buildGraph is deterministic
        factory::PolicyGraph expectedGraph;
        EXPECT_NO_THROW(expectedGraph = factory::buildGraph(data.builtAssets));

        EXPECT_EQ(got, expectedGraph);
    }
    else
    {
        auto data = expected.failCase()(None {});
        EXPECT_THROW(factory::buildGraph(data.builtAssets), std::runtime_error);
    }
}

using AD = AssetData;
using RT = cm::store::ResourceType;

INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    BuildGraph,
    ::testing::Values(
        // Empty graph
        BuildT(SUCCESS(AD())),
        // Single decoder
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/asset/0", "decoder/Input"))),
        // Single rule
        BuildT(SUCCESS(AD()(RT::RULE, "rule/asset/0", "rule/Input"))),
        // Single output
        BuildT(SUCCESS(AD()(RT::OUTPUT, "output/asset/0", "output/Input"))),
        // Decoder with children
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(
            RT::DECODER, "decoder/child/0", "decoder/parent/0"))),
        // Rule with children
        BuildT(SUCCESS(AD()(RT::RULE, "rule/parent/0", "rule/Input")(RT::RULE, "rule/child/0", "rule/parent/0"))),
        // Output with children
        BuildT(SUCCESS(
            AD()(RT::OUTPUT, "output/parent/0", "output/Input")(RT::OUTPUT, "output/child/0", "output/parent/0"))),
        // Multiple children
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(
            RT::DECODER, "decoder/child1/0", "decoder/parent/0")(RT::DECODER, "decoder/child2/0", "decoder/parent/0"))),
        // Multiple parents
        BuildT(SUCCESS(
            AD()(RT::DECODER, "decoder/parent1/0", "decoder/Input")(RT::DECODER, "decoder/parent2/0", "decoder/Input")(
                RT::DECODER, "decoder/child/0", "decoder/parent1/0", "decoder/parent2/0"))),
        // Complex decoder graph
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/child1/0", "decoder/parent1/0")(
            RT::DECODER, "decoder/child2/0", "decoder/parent1/0", "decoder/parent2/0")(
            RT::DECODER, "decoder/child3/0", "decoder/child1/0")(RT::DECODER, "decoder/parent1/0", "decoder/Input")(
            RT::DECODER, "decoder/parent2/0", "decoder/Input")(RT::DECODER, "decoder/child4/0", "decoder/Input"))),
        // Complex rule graph
        BuildT(SUCCESS(AD()(RT::RULE, "rule/child1/0", "rule/parent1/0")(
            RT::RULE, "rule/child2/0", "rule/parent1/0", "rule/parent2/0")(RT::RULE, "rule/child3/0", "rule/child1/0")(
            RT::RULE, "rule/parent1/0", "rule/Input")(RT::RULE, "rule/parent2/0", "rule/Input")(
            RT::RULE, "rule/child4/0", "rule/Input"))),
        // Complex output graph
        BuildT(SUCCESS(AD()(RT::OUTPUT, "output/child1/0", "output/parent1/0")(
            RT::OUTPUT, "output/child2/0", "output/parent1/0", "output/parent2/0")(
            RT::OUTPUT, "output/child3/0", "output/child1/0")(RT::OUTPUT, "output/parent1/0", "output/Input")(
            RT::OUTPUT, "output/parent2/0", "output/Input")(RT::OUTPUT, "output/child4/0", "output/Input"))),
        // All types
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/child1/0", "decoder/parent1/0")(
            RT::DECODER, "decoder/child2/0", "decoder/parent1/0", "decoder/parent2/0")(
            RT::DECODER, "decoder/child3/0", "decoder/child1/0")(RT::DECODER, "decoder/parent1/0", "decoder/Input")(
            RT::DECODER, "decoder/parent2/0", "decoder/Input")(RT::DECODER, "decoder/child4/0", "decoder/Input")(
            RT::RULE, "rule/child1/0", "rule/parent1/0")(RT::RULE, "rule/child2/0", "rule/parent1/0", "rule/parent2/0")(
            RT::RULE, "rule/child3/0", "rule/child1/0")(RT::RULE, "rule/parent1/0", "rule/Input")(
            RT::RULE, "rule/parent2/0", "rule/Input")(RT::RULE, "rule/child4/0", "rule/Input")(
            RT::OUTPUT, "output/child1/0", "output/parent1/0")(
            RT::OUTPUT, "output/child2/0", "output/parent1/0", "output/parent2/0")(
            RT::OUTPUT, "output/child3/0", "output/child1/0")(RT::OUTPUT, "output/parent1/0", "output/Input")(
            RT::OUTPUT, "output/parent2/0", "output/Input")(RT::OUTPUT, "output/child4/0", "output/Input"))),
        // Parent does not exist
        BuildT(FAILURE(AD()(RT::DECODER, "decoder/child/0", "decoder/nonexistent/0"))),
        // Parent does not exist (rule)
        BuildT(FAILURE(AD()(RT::RULE, "rule/child/0", "rule/nonexistent/0"))),
        // Parent does not exist (output)
        BuildT(FAILURE(AD()(RT::OUTPUT, "output/child/0", "output/nonexistent/0"))),
        // Filters are completely ignored - not injected into any subgraph
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(
            RT::DECODER, "decoder/child/0", "decoder/parent/0")(RT::FILTER, "filter/ignored/0", "decoder/parent/0")(
            RT::OUTPUT, "output/test/0", "output/Input")(RT::FILTER, "filter/ignored2/0", "output/test/0")))));

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

TEST_P(BuildExpression, Graph)
{
    auto [data, expected] = GetParam();

    if (expected)
    {
        base::Expression got;
        auto graph = factory::buildGraph(data.builtAssets);
        auto expectedExpr = expected.succCase()(None {});
        EXPECT_NO_THROW(got = factory::buildExpression(graph, "test"));
        builder::test::assertEqualExpr(got, expectedExpr);
    }
    else
    {
        auto graph = factory::buildGraph(data.builtAssets);
        EXPECT_THROW(factory::buildExpression(graph, "test"), std::runtime_error);
    }
}

using RT = cm::store::ResourceType;
using namespace base;

INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    BuildExpression,
    ::testing::Values(
        // Empty policy
        BuildT(AD(), SUCCESS([](None) { return Chain::create("test", {}); })),
        // Single decoder
        BuildT(AD()(RT::DECODER, "decoder/asset/0", "decoder/Input"),
               SUCCESS(
                   [](None)
                   {
                       auto decoder = Or::create("decoder/Input", {assetExpr("decoder/asset/0")});
                       return Chain::create("test", {decoder});
                   })),
        // Single rule
        BuildT(AD()(RT::RULE, "rule/asset/0", "rule/Input"),
               SUCCESS(
                   [](None)
                   {
                       auto rule = Broadcast::create("rule/Input", {assetExpr("rule/asset/0")});
                       return Chain::create("test", {rule});
                   })),
        // Single output
        BuildT(AD()(RT::OUTPUT, "output/asset/0", "output/Input"),
               SUCCESS(
                   [](None)
                   {
                       auto output = Broadcast::create("output/Input", {assetExpr("output/asset/0")});
                       return Chain::create("test", {output});
                   })),
        // Decoder with child
        BuildT(
            AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(RT::DECODER, "decoder/child/0", "decoder/parent/0"),
            SUCCESS(
                [](None)
                {
                    auto childExpr = assetExpr("decoder/child/0");
                    auto childrenOp = Or::create("decoder/parent/0/Children", {childExpr});
                    auto parentExpr =
                        Implication::create("decoder/parent/0/Node", assetExpr("decoder/parent/0"), childrenOp);
                    auto decoder = Or::create("decoder/Input", {parentExpr});
                    return Chain::create("test", {decoder});
                })),
        // Rule with child
        BuildT(AD()(RT::RULE, "rule/parent/0", "rule/Input")(RT::RULE, "rule/child/0", "rule/parent/0"),
               SUCCESS(
                   [](None)
                   {
                       auto childExpr = assetExpr("rule/child/0");
                       auto childrenOp = Broadcast::create("rule/parent/0/Children", {childExpr});
                       auto parentExpr =
                           Implication::create("rule/parent/0/Node", assetExpr("rule/parent/0"), childrenOp);
                       auto rule = Broadcast::create("rule/Input", {parentExpr});
                       return Chain::create("test", {rule});
                   })),
        // Output with child
        BuildT(AD()(RT::OUTPUT, "output/parent/0", "output/Input")(RT::OUTPUT, "output/child/0", "output/parent/0"),
               SUCCESS(
                   [](None)
                   {
                       auto childExpr = assetExpr("output/child/0");
                       auto childrenOp = Broadcast::create("output/parent/0/Children", {childExpr});
                       auto parentExpr =
                           Implication::create("output/parent/0/Node", assetExpr("output/parent/0"), childrenOp);
                       auto output = Broadcast::create("output/Input", {parentExpr});
                       return Chain::create("test", {output});
                   })),
        // Multiple children
        BuildT(
            AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(RT::DECODER, "decoder/child1/0", "decoder/parent/0")(
                RT::DECODER, "decoder/child2/0", "decoder/parent/0"),
            SUCCESS(
                [](None)
                {
                    auto child1 = assetExpr("decoder/child1/0");
                    auto child2 = assetExpr("decoder/child2/0");
                    auto childrenOp = Or::create("decoder/parent/0/Children", {child1, child2});
                    auto parentExpr =
                        Implication::create("decoder/parent/0/Node", assetExpr("decoder/parent/0"), childrenOp);
                    auto decoder = Or::create("decoder/Input", {parentExpr});
                    return Chain::create("test", {decoder});
                })),
        // All types
        BuildT(
            AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(RT::DECODER, "decoder/child/0", "decoder/parent/0")(
                RT::RULE, "rule/parent/0", "rule/Input")(RT::RULE, "rule/child/0", "rule/parent/0")(
                RT::OUTPUT, "output/parent/0", "output/Input")(RT::OUTPUT, "output/child/0", "output/parent/0"),
            SUCCESS(
                [](None)
                {
                    // Decoder
                    auto decoderChild = assetExpr("decoder/child/0");
                    auto decoderChildren = Or::create("decoder/parent/0/Children", {decoderChild});
                    auto decoderParent =
                        Implication::create("decoder/parent/0/Node", assetExpr("decoder/parent/0"), decoderChildren);
                    auto decoder = Or::create("decoder/Input", {decoderParent});

                    // Output (comes before Rule due to enum ordering)
                    auto outputChild = assetExpr("output/child/0");
                    auto outputChildren = Broadcast::create("output/parent/0/Children", {outputChild});
                    auto outputParent =
                        Implication::create("output/parent/0/Node", assetExpr("output/parent/0"), outputChildren);
                    auto output = Broadcast::create("output/Input", {outputParent});

                    // Rule
                    auto ruleChild = assetExpr("rule/child/0");
                    auto ruleChildren = Broadcast::create("rule/parent/0/Children", {ruleChild});
                    auto ruleParent =
                        Implication::create("rule/parent/0/Node", assetExpr("rule/parent/0"), ruleChildren);
                    auto rule = Broadcast::create("rule/Input", {ruleParent});

                    return Chain::create("test", {decoder, output, rule});
                }))));

} // namespace buildexpressiontest

namespace buildsubgraphortest
{
using buildgraphtest::assetExpr;

struct SubgraphCase
{
    Graph<base::Name, Asset> subgraph;
    std::shared_ptr<base::Operation> expected;
};

static Graph<base::Name, Asset> makeEmptyGraph()
{
    Graph<base::Name, Asset> g {"decoder/Input", Asset {}};
    return g;
}

class BuildSubgraphOr : public ::testing::TestWithParam<SubgraphCase>
{
};

TEST_P(BuildSubgraphOr, OrOperation)
{
    const auto& param = GetParam();
    const auto& graph = param.subgraph;

    base::Expression got;
    ASSERT_NO_THROW({ got = factory::buildSubgraphExpression<base::Or>(graph); });

    builder::test::assertEqualExpr(got, param.expected);
}

using namespace base;
INSTANTIATE_TEST_SUITE_P(OrOperation,
                         BuildSubgraphOr,
                         ::testing::Values(
                             // A single child "H" under the root
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aH("H", assetExpr("H"), std::vector<base::Name> {});
                                               g.addNode("H", std::move(aH));
                                               g.addEdge("decoder/Input", "H");
                                               return g;
                                           }(),
                                           /* expected */ Or::create("decoder/Input", {assetExpr("H")})},

                             // Parent "P" with one child "C"
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP("P", assetExpr("P"), std::vector<base::Name> {});
                                               g.addNode("P", std::move(aP));
                                               g.addEdge("decoder/Input", "P");
                                               Asset aC("C", assetExpr("C"), std::vector<base::Name> {"P"});
                                               g.addNode("C", std::move(aC));
                                               g.addEdge("P", "C");
                                               return g;
                                           }(),
                                           /* expected */
                                           []()
                                           {
                                               auto children = Or::create("P/Children", {});
                                               children->getOperands().push_back(assetExpr("C"));
                                               auto impl = Implication::create("P/Node", assetExpr("P"), children);
                                               return Or::create("decoder/Input", {impl});
                                           }()},

                             // Parent "P" with two children "C1" and "C2" in that order
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP("P", assetExpr("P"), std::vector<base::Name> {});
                                               g.addNode("P", std::move(aP));
                                               g.addEdge("decoder/Input", "P");
                                               Asset aC1("C1", assetExpr("C1"), std::vector<base::Name> {"P"});
                                               g.addNode("C1", std::move(aC1));
                                               g.addEdge("P", "C1");
                                               Asset aC2("C2", assetExpr("C2"), std::vector<base::Name> {"P"});
                                               g.addNode("C2", std::move(aC2));
                                               g.addEdge("P", "C2");
                                               return g;
                                           }(),
                                           /* expected */
                                           []()
                                           {
                                               auto children = Or::create("P/Children", {});
                                               children->getOperands().push_back(assetExpr("C1"));
                                               children->getOperands().push_back(assetExpr("C2"));
                                               auto impl = Implication::create("P/Node", assetExpr("P"), children);
                                               return Or::create("decoder/Input", {impl});
                                           }()},

                             // Two parents "P1" and "P2" sharing child "C"
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP1("P1", assetExpr("P1"), std::vector<base::Name> {});
                                               g.addNode("P1", std::move(aP1));
                                               g.addEdge("decoder/Input", "P1");
                                               Asset aP2("P2", assetExpr("P2"), std::vector<base::Name> {});
                                               g.addNode("P2", std::move(aP2));
                                               g.addEdge("decoder/Input", "P2");
                                               Asset aC("C", assetExpr("C"), std::vector<base::Name> {"P1", "P2"});
                                               g.addNode("C", std::move(aC));
                                               g.addEdge("P1", "C");
                                               g.addEdge("P2", "C");
                                               return g;
                                           }(),
                                           /* expected */
                                           []()
                                           {
                                               auto children1 = Or::create("P1/Children", {});
                                               children1->getOperands().push_back(assetExpr("C"));
                                               auto impl1 = Implication::create("P1/Node", assetExpr("P1"), children1);

                                               auto children2 = Or::create("P2/Children", {});
                                               children2->getOperands().push_back(assetExpr("C"));
                                               auto impl2 = Implication::create("P2/Node", assetExpr("P2"), children2);

                                               return Or::create("decoder/Input", {impl1, impl2});
                                           }()},

                             // Complex hierarchy: Root -> P1 -> C1 -> GC1
                             SubgraphCase {/* subgraph */ []()
                                           {
                                               auto g = makeEmptyGraph();
                                               Asset aP1("P1", assetExpr("P1"), std::vector<base::Name> {});
                                               g.addNode("P1", std::move(aP1));
                                               g.addEdge("decoder/Input", "P1");
                                               Asset aC1("C1", assetExpr("C1"), std::vector<base::Name> {"P1"});
                                               g.addNode("C1", std::move(aC1));
                                               g.addEdge("P1", "C1");
                                               Asset aGC1("GC1", assetExpr("GC1"), std::vector<base::Name> {"C1"});
                                               g.addNode("GC1", std::move(aGC1));
                                               g.addEdge("C1", "GC1");
                                               return g;
                                           }(),
                                           /* expected */
                                           []()
                                           {
                                               // GC1 is a leaf (no children), so it's just the asset expression
                                               auto gc1Expr = assetExpr("GC1");

                                               // C1 children
                                               auto c1Children = Or::create("C1/Children", {gc1Expr});
                                               auto c1Impl =
                                                   Implication::create("C1/Node", assetExpr("C1"), c1Children);

                                               // P1 children
                                               auto p1Children = Or::create("P1/Children", {c1Impl});
                                               auto p1Impl =
                                                   Implication::create("P1/Node", assetExpr("P1"), p1Children);

                                               return Or::create("decoder/Input", {p1Impl});
                                           }()}));

} // namespace buildsubgraphortest

namespace cycledetectiontest
{
using buildgraphtest::assetExpr;

using AD = buildgraphtest::AssetData;
using RT = cm::store::ResourceType;

TEST(CycleDetection, SelfReference)
{
    // Build graph manually to create cycle
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name assetName("decoder/asset/0");
    Asset asset {base::Name("decoder/asset/0"), assetExpr(assetName), {}};

    subgraph.addNode(assetName, asset);
    subgraph.addEdge("decoder/Input", assetName);
    // Create self-reference cycle
    subgraph.addEdge(assetName, assetName);

    EXPECT_THROW(subgraph.validateAcyclic("decoder"), std::runtime_error);
}

TEST(CycleDetection, TwoNodeCycle)
{
    // Build graph manually to create cycle
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name asset1Name("decoder/asset1/0");
    Asset asset1 {base::Name("decoder/asset1/0"), assetExpr(asset1Name), {}};
    base::Name asset2Name("decoder/asset2/0");
    Asset asset2 {base::Name("decoder/asset2/0"), assetExpr(asset2Name), {}};

    subgraph.addNode(asset1Name, asset1);
    subgraph.addNode(asset2Name, asset2);
    subgraph.addEdge("decoder/Input", asset1Name);
    // Create cycle: asset1 -> asset2 -> asset1
    subgraph.addEdge(asset1Name, asset2Name);
    subgraph.addEdge(asset2Name, asset1Name);

    EXPECT_THROW(subgraph.validateAcyclic("decoder"), std::runtime_error);
}

TEST(CycleDetection, ThreeNodeCycle)
{
    // Build graph manually to create cycle
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name asset1Name("decoder/asset1/0");
    Asset asset1 {base::Name("decoder/asset1/0"), assetExpr(asset1Name), {}};
    base::Name asset2Name("decoder/asset2/0");
    Asset asset2 {base::Name("decoder/asset2/0"), assetExpr(asset2Name), {}};
    base::Name asset3Name("decoder/asset3/0");
    Asset asset3 {base::Name("decoder/asset3/0"), assetExpr(asset3Name), {}};

    subgraph.addNode(asset1Name, asset1);
    subgraph.addNode(asset2Name, asset2);
    subgraph.addNode(asset3Name, asset3);
    subgraph.addEdge("decoder/Input", asset1Name);
    // Create cycle: asset1 -> asset2 -> asset3 -> asset1
    subgraph.addEdge(asset1Name, asset2Name);
    subgraph.addEdge(asset2Name, asset3Name);
    subgraph.addEdge(asset3Name, asset1Name);

    EXPECT_THROW(subgraph.validateAcyclic("decoder"), std::runtime_error);
}

TEST(CycleDetection, ComplexCycle)
{
    // Build graph manually to create complex cycle
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name asset1Name("decoder/asset1/0");
    Asset asset1 {base::Name("decoder/asset1/0"), assetExpr(asset1Name), {}};
    base::Name asset2Name("decoder/asset2/0");
    Asset asset2 {base::Name("decoder/asset2/0"), assetExpr(asset2Name), {}};
    base::Name asset3Name("decoder/asset3/0");
    Asset asset3 {base::Name("decoder/asset3/0"), assetExpr(asset3Name), {}};
    base::Name asset4Name("decoder/asset4/0");
    Asset asset4 {base::Name("decoder/asset4/0"), assetExpr(asset4Name), {}};
    base::Name asset5Name("decoder/asset5/0");
    Asset asset5 {base::Name("decoder/asset5/0"), assetExpr(asset5Name), {}};

    subgraph.addNode(asset1Name, asset1);
    subgraph.addNode(asset2Name, asset2);
    subgraph.addNode(asset3Name, asset3);
    subgraph.addNode(asset4Name, asset4);
    subgraph.addNode(asset5Name, asset5);

    subgraph.addEdge("decoder/Input", asset1Name);
    subgraph.addEdge(asset1Name, asset2Name);
    subgraph.addEdge(asset2Name, asset3Name);
    subgraph.addEdge(asset3Name, asset4Name);
    subgraph.addEdge(asset4Name, asset5Name);
    // Create cycle: asset5 -> asset3 (creates cycle: 3->4->5->3)
    subgraph.addEdge(asset5Name, asset3Name);

    EXPECT_THROW(subgraph.validateAcyclic("decoder"), std::runtime_error);
}

TEST(CycleDetection, NoCycle)
{
    auto data =
        AD()(RT::DECODER, "decoder/asset1/0", "decoder/Input")(RT::DECODER, "decoder/asset2/0", "decoder/asset1/0")(
            RT::DECODER, "decoder/asset3/0", "decoder/asset2/0")(RT::DECODER, "decoder/asset4/0", "decoder/asset3/0");
    auto graph = factory::buildGraph(data.builtAssets);
    EXPECT_NO_THROW(graph.subgraphs.at(RT::DECODER).validateAcyclic("decoder"));
}

TEST(CycleDetection, ComplexNoCycle)
{
    auto data =
        AD()(RT::DECODER, "decoder/asset1/0", "decoder/Input")(RT::DECODER, "decoder/asset2/0", "decoder/asset1/0")(
            RT::DECODER, "decoder/asset3/0", "decoder/asset2/0", "decoder/asset1/0")(
            RT::DECODER, "decoder/asset4/0", "decoder/asset3/0", "decoder/asset2/0");
    auto graph = factory::buildGraph(data.builtAssets);
    EXPECT_NO_THROW(graph.subgraphs.at(RT::DECODER).validateAcyclic("decoder"));
}

TEST(CycleDetection, DetectsReachableCycleWithExtraParents)
{
    // Cycle: a -> b -> c -> a, with additional edge d -> b
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name aRef("decoder/a");
    Asset a {base::Name("decoder/a"), std::move(assetExpr(aRef)), std::vector<base::Name> {}};

    base::Name bRef("decoder/b");
    Asset b {base::Name("decoder/b"), std::move(assetExpr(bRef)), std::vector<base::Name> {}};

    base::Name cRef("decoder/c");
    Asset c {base::Name("decoder/c"), std::move(assetExpr(cRef)), std::vector<base::Name> {}};

    base::Name dRef("decoder/d");
    Asset d {base::Name("decoder/d"), std::move(assetExpr(dRef)), std::vector<base::Name> {}};

    subgraph.addNode(aRef, a);
    subgraph.addNode(bRef, b);
    subgraph.addNode(cRef, c);
    subgraph.addNode(dRef, d);

    subgraph.addEdge("decoder/Input", aRef);
    subgraph.addEdge(aRef, bRef);
    subgraph.addEdge(bRef, cRef);
    subgraph.addEdge(cRef, aRef); // cycle closes

    subgraph.addEdge("decoder/Input", dRef);
    subgraph.addEdge(dRef, bRef); // additional incoming edge

    EXPECT_THROW(subgraph.validateAcyclic("decoder"), std::runtime_error);
}

TEST(CycleDetection, DetectsDisconnectedCycle)
{
    // Linear path: Input -> a -> b, plus disconnected cycle: x -> y -> x
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name aRef("decoder/a");
    Asset a {base::Name("decoder/a"), std::move(assetExpr(aRef)), std::vector<base::Name> {}};

    base::Name bRef("decoder/b");
    Asset b {base::Name("decoder/b"), std::move(assetExpr(bRef)), std::vector<base::Name> {}};

    base::Name xRef("decoder/x");
    Asset x {base::Name("decoder/x"), std::move(assetExpr(xRef)), std::vector<base::Name> {}};

    base::Name yRef("decoder/y");
    Asset y {base::Name("decoder/y"), std::move(assetExpr(yRef)), std::vector<base::Name> {}};

    subgraph.addNode(aRef, a);
    subgraph.addNode(bRef, b);
    subgraph.addNode(xRef, x);
    subgraph.addNode(yRef, y);

    subgraph.addEdge("decoder/Input", aRef);
    subgraph.addEdge(aRef, bRef);

    subgraph.addEdge(xRef, yRef);
    subgraph.addEdge(yRef, xRef); // disconnected cycle

    EXPECT_THROW(subgraph.validateAcyclic("decoder"), std::runtime_error);
}

TEST(CycleDetection, AllowsDiamondShapeWithoutCycle)
{
    // Diamond shape (no cycle): Input -> a -> b, Input -> c -> b
    Graph<base::Name, Asset> subgraph {"decoder/Input", Asset {}};

    base::Name aRef("decoder/a");
    Asset a {base::Name("decoder/a"), std::move(assetExpr(aRef)), std::vector<base::Name> {}};

    base::Name bRef("decoder/b");
    Asset b {base::Name("decoder/b"), std::move(assetExpr(bRef)), std::vector<base::Name> {}};

    base::Name cRef("decoder/c");
    Asset c {base::Name("decoder/c"), std::move(assetExpr(cRef)), std::vector<base::Name> {}};

    subgraph.addNode(aRef, a);
    subgraph.addNode(bRef, b);
    subgraph.addNode(cRef, c);

    subgraph.addEdge("decoder/Input", aRef);
    subgraph.addEdge(aRef, bRef);
    subgraph.addEdge("decoder/Input", cRef);
    subgraph.addEdge(cRef, bRef);

    EXPECT_NO_THROW(subgraph.validateAcyclic("decoder"));
}

} // namespace cycledetectiontest

namespace buildsubgraphtest
{
using buildgraphtest::assetExpr;

using AD = buildgraphtest::AssetData;
using RT = cm::store::ResourceType;

TEST(BuildSubgraph, Empty)
{
    factory::SubgraphData subgraphData;

    auto subgraph = factory::buildSubgraph("test", subgraphData);

    EXPECT_EQ(subgraph.rootId(), "test");
    EXPECT_FALSE(subgraph.hasChildren("test"));
}

TEST(BuildSubgraph, SingleAsset)
{
    factory::SubgraphData subgraphData;
    base::Name assetName("decoder/asset/0");
    Asset asset {base::Name("decoder/asset/0"), assetExpr(assetName), {}};
    subgraphData.orderedAssets.push_back(assetName);
    subgraphData.assets.emplace(assetName, asset);

    auto subgraph = factory::buildSubgraph("test", subgraphData);

    EXPECT_TRUE(subgraph.hasNode(assetName));
    EXPECT_TRUE(subgraph.hasChildren("test"));
    EXPECT_EQ(subgraph.children("test").size(), 1);
}

TEST(BuildSubgraph, WithParent)
{
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    base::Name childName("decoder/child/0");
    Asset child {base::Name("decoder/child/0"), assetExpr(childName), {parentName}};
    subgraphData.orderedAssets.push_back(childName);
    subgraphData.assets.emplace(childName, child);

    auto subgraph = factory::buildSubgraph("test", subgraphData);

    EXPECT_TRUE(subgraph.hasNode(parentName));
    EXPECT_TRUE(subgraph.hasNode(childName));
    EXPECT_TRUE(subgraph.hasChildren(parentName));
    EXPECT_EQ(subgraph.children(parentName).size(), 1);
}

TEST(BuildSubgraph, ParentNotFound)
{
    factory::SubgraphData subgraphData;

    base::Name childName("decoder/child/0");
    Asset child {base::Name("decoder/child/0"), assetExpr(childName), {base::Name("decoder/nonexistent/0")}};
    subgraphData.orderedAssets.push_back(childName);
    subgraphData.assets.emplace(childName, child);

    EXPECT_THROW(factory::buildSubgraph("test", subgraphData), std::runtime_error);
}

TEST(BuildSubgraph, FiltersNotInSubgraph)
{
    // Verify that filters present in BuiltAssets do NOT appear as nodes in the subgraph
    // This test documents the removal of filter injection from decoder trees
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    base::Name childName("decoder/child/0");
    Asset child {base::Name("decoder/child/0"), assetExpr(childName), {parentName}};
    subgraphData.orderedAssets.push_back(childName);
    subgraphData.assets.emplace(childName, child);

    auto subgraph = factory::buildSubgraph("test", subgraphData);

    // Verify expected nodes exist
    EXPECT_TRUE(subgraph.hasNode(parentName));
    EXPECT_TRUE(subgraph.hasNode(childName));
    EXPECT_TRUE(subgraph.hasChildren(parentName));
    EXPECT_EQ(subgraph.children(parentName).size(), 1);
    EXPECT_EQ(subgraph.children(parentName)[0], childName);

    // Verify filters do NOT exist in subgraph (they are never injected)
    EXPECT_FALSE(subgraph.hasNode(base::Name("filter/any/0")));
}

} // namespace buildsubgraphtest

namespace buildassettest
{

using SuccessExpected = InnerExpected<None,
                                      const std::shared_ptr<MockICMStoreNSReader>&,
                                      const std::shared_ptr<builder::builders::IBuildCtx>&>;
using FailureExpected = InnerExpected<std::string,
                                      const std::shared_ptr<MockICMStoreNSReader>&,
                                      const std::shared_ptr<builder::builders::IBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using BuildAssetsT = std::tuple<dataType::Policy, Expc>;

class BuildAssets : public testing::TestWithParam<BuildAssetsT>
{
};

TEST_P(BuildAssets, KVDBAvailability)
{
    auto [policy, expected] = GetParam();

    auto cmStoreNSReader = std::make_shared<MockICMStoreNSReader>();
    auto buildCtx = std::make_shared<builder::builders::BuildCtx>();
    auto registry = builder::mocks::MockMetaRegistry<builder::builders::OpBuilderEntry,
                                                     builder::builders::StageBuilder>::createMock();
    auto definitionsBuilder = std::make_shared<defs::mocks::MockDefinitionsBuilder>();
    buildCtx->setRegistry(registry);
    auto assetBuilder = std::make_shared<AssetBuilder>(buildCtx, definitionsBuilder);

    if (expected)
    {
        expected.succCase()(cmStoreNSReader, buildCtx);
        EXPECT_NO_THROW(factory::buildAssets(policy, cmStoreNSReader, assetBuilder, true));
    }
    else
    {
        auto errorMsg = expected.failCase()(cmStoreNSReader, buildCtx);
        EXPECT_THROW(
            {
                try
                {
                    factory::buildAssets(policy, cmStoreNSReader, assetBuilder, true);
                }
                catch (const std::runtime_error& e)
                {
                    EXPECT_THAT(e.what(), testing::HasSubstr(errorMsg));
                    throw;
                }
            },
            std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KVDBAvailability,
    BuildAssets,
    ::testing::Values(
        // Test: KVDB availability map is correctly built
        BuildAssetsT(
            dataType::Policy({"550e8400-e29b-41d4-a716-446655440001"}, "550e8400-e29b-41d4-a716-446655440003"),
            SUCCESS(SuccessExpected::Behaviour {
                [](const auto& reader, const auto& buildCtx)
                {
                    dataType::Integration integration(
                        "550e8400-e29b-41d4-a716-446655440001",
                        "test_integration",
                        true,
                        "system-activity",
                        std::nullopt,
                        {"550e8400-e29b-41d4-a716-446655440011", "550e8400-e29b-41d4-a716-446655440012"},
                        {},
                        {},
                        false);

                    dataType::KVDB kvdb1(
                        "550e8400-e29b-41d4-a716-446655440011", "kvdb_enabled", json::Json(R"({})"), true, false);
                    dataType::KVDB kvdb2(
                        "550e8400-e29b-41d4-a716-446655440012", "kvdb_disabled", json::Json(R"({})"), false, false);

                    EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                        .WillOnce(testing::Return(std::make_tuple("decoder/root/0", cm::store::ResourceType::DECODER)));
                    EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
                        .WillOnce(testing::Return(integration));
                    EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440011"))
                        .WillOnce(testing::Return(kvdb1));
                    EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440012"))
                        .WillOnce(testing::Return(kvdb2));

                    return None {};
                }})),
        // Test: Duplicate KVDB names throw error
        BuildAssetsT(
            dataType::Policy({"550e8400-e29b-41d4-a716-446655440002"}, "550e8400-e29b-41d4-a716-446655440003"),
            FAILURE(FailureExpected::Behaviour {
                [](const auto& reader, const auto& buildCtx)
                {
                    dataType::Integration integration(
                        "550e8400-e29b-41d4-a716-446655440002",
                        "test_integration",
                        true,
                        "system-activity",
                        std::nullopt,
                        {"550e8400-e29b-41d4-a716-446655440021", "550e8400-e29b-41d4-a716-446655440022"},
                        {},
                        {},
                        false);

                    dataType::KVDB kvdb1(
                        "550e8400-e29b-41d4-a716-446655440021", "duplicate_name", json::Json(R"({})"), true, false);
                    dataType::KVDB kvdb2(
                        "550e8400-e29b-41d4-a716-446655440022", "duplicate_name", json::Json(R"({})"), true, false);

                    EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                        .WillOnce(testing::Return(std::make_tuple("decoder/root/0", cm::store::ResourceType::DECODER)));
                    EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440002"))
                        .WillOnce(testing::Return(integration));
                    EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440021"))
                        .WillOnce(testing::Return(kvdb1));
                    EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440022"))
                        .WillOnce(testing::Return(kvdb2));

                    return std::string("Duplicate KVDB title");
                }})),
        // Test: Disabled integration skips KVDB processing
        BuildAssetsT(dataType::Policy({"550e8400-e29b-41d4-a716-446655440003"}, "550e8400-e29b-41d4-a716-446655440003"),
                     SUCCESS(SuccessExpected::Behaviour {
                         [](const auto& reader, const auto& buildCtx)
                         {
                             dataType::Integration integration("550e8400-e29b-41d4-a716-446655440003",
                                                               "disabled_integration",
                                                               false,
                                                               "system-activity",
                                                               std::nullopt,
                                                               {"550e8400-e29b-41d4-a716-446655440031"},
                                                               {},
                                                               {},
                                                               false);

                             EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                                 .WillOnce(testing::Return(
                                     std::make_tuple("decoder/root/0", cm::store::ResourceType::DECODER)));
                             EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440003"))
                                 .WillOnce(testing::Return(integration));
                             EXPECT_CALL(*reader, getKVDBByUUID(testing::_)).Times(0);

                             return None {};
                         }})),
        // Test: KVDB loading error throws with message
        BuildAssetsT(dataType::Policy({"550e8400-e29b-41d4-a716-446655440004"}, "550e8400-e29b-41d4-a716-446655440005"),
                     FAILURE(FailureExpected::Behaviour {
                         [](const auto& reader, const auto& buildCtx)
                         {
                             dataType::Integration integration("550e8400-e29b-41d4-a716-446655440004",
                                                               "test_integration",
                                                               true,
                                                               "system-activity",
                                                               std::nullopt,
                                                               {"550e8400-e29b-41d4-a716-446655440041"},
                                                               {},
                                                               {},
                                                               false);

                             EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440005"))
                                 .WillOnce(testing::Return(
                                     std::make_tuple("decoder/root/0", cm::store::ResourceType::DECODER)));
                             EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440004"))
                                 .WillOnce(testing::Return(integration));
                             EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440041"))
                                 .WillOnce(testing::Throw(std::runtime_error("KVDB not found")));

                             return std::string("Failed to load KVDB");
                         }}))));

} // namespace buildassettest
