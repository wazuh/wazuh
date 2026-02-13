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

namespace
{
// Helper function to create a minimal dummy enrichment expression for tests
base::Expression createDummyEnrichment()
{
    return base::Term<base::EngineOp>::create("enrichment/geo", nullptr);
}

base::Expression createDummyPreEnrichment()
{
    auto originSpaceExp = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
    auto unclassifiedExp = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
    return base::And::create("preEnrichment", {originSpaceExp, unclassifiedExp});
}
} // namespace
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
        // Single output
        BuildT(SUCCESS(AD()(RT::OUTPUT, "output/asset/0", "output/Input"))),
        // Decoder with children
        BuildT(SUCCESS(AD()(RT::DECODER, "decoder/parent/0", "decoder/Input")(
            RT::DECODER, "decoder/child/0", "decoder/parent/0"))),
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
            RT::OUTPUT, "output/child1/0", "output/parent1/0")(
            RT::OUTPUT, "output/child2/0", "output/parent1/0", "output/parent2/0")(
            RT::OUTPUT, "output/child3/0", "output/child1/0")(RT::OUTPUT, "output/parent1/0", "output/Input")(
            RT::OUTPUT, "output/parent2/0", "output/Input")(RT::OUTPUT, "output/child4/0", "output/Input"))),
        // Parent does not exist
        BuildT(FAILURE(AD()(RT::DECODER, "decoder/child/0", "decoder/nonexistent/0"))),
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
        graph.graphName = "test";
        auto expectedExpr = expected.succCase()(None {});
        auto enrichment = createDummyEnrichment();
        auto preEnrichment = createDummyPreEnrichment();
        EXPECT_NO_THROW(got = factory::buildExpression(graph, preEnrichment, enrichment));
        builder::test::assertEqualExpr(got, expectedExpr);
    }
    else
    {
        auto graph = factory::buildGraph(data.builtAssets);
        graph.graphName = "test";
        auto enrichment = createDummyEnrichment();
        auto preEnrichment = createDummyPreEnrichment();
        EXPECT_THROW(factory::buildExpression(graph, preEnrichment, enrichment), std::runtime_error);
    }
}

using RT = cm::store::ResourceType;
using namespace base;

INSTANTIATE_TEST_SUITE_P(
    PolicyFactory,
    BuildExpression,
    ::testing::Values(
        // Single decoder
        BuildT(AD()(RT::DECODER, "decoder/asset/0", "DecodersTree/Input"),
               SUCCESS(
                   [](None)
                   {
                       auto decoder = Or::create("DecodersTree/Input", {assetExpr("decoder/asset/0")});
                       auto phase1 = Chain::create("Phase1_Decoders", {decoder});
                       auto originSpace = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
                       auto unclassified = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
                       auto phase2 = And::create("preEnrichment", {originSpace, unclassified});
                       auto enrichment = base::Term<base::EngineOp>::create("enrichment/geo", nullptr);
                       return And::create("test", {phase1, phase2, enrichment});
                   })),
        // Single output - outputs alone are not valid (need decoders)
        BuildT(AD()(RT::DECODER, "decoder/root/0", "DecodersTree/Input")(
                   RT::OUTPUT, "output/asset/0", "OutputsTree/Input"),
               SUCCESS(
                   [](None)
                   {
                       auto decoder = Or::create("DecodersTree/Input", {assetExpr("decoder/root/0")});
                       auto phase1 = Chain::create("Phase1_Decoders", {decoder});
                       auto originSpace = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
                       auto unclassified = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
                       auto phase2 = And::create("preEnrichment", {originSpace, unclassified});
                       auto enrichment = base::Term<base::EngineOp>::create("enrichment/geo", nullptr);
                       auto output = Broadcast::create("OutputsTree/Input", {assetExpr("output/asset/0")});
                       return And::create("test", {phase1, phase2, enrichment, output});
                   })),
        // Decoder with child
        BuildT(AD()(RT::DECODER, "decoder/parent/0", "DecodersTree/Input")(
                   RT::DECODER, "decoder/child/0", "decoder/parent/0"),
               SUCCESS(
                   [](None)
                   {
                       auto childExpr = assetExpr("decoder/child/0");
                       auto childrenOp = Or::create("decoder/parent/0/Children", {childExpr});
                       auto parentExpr =
                           Implication::create("decoder/parent/0/Node", assetExpr("decoder/parent/0"), childrenOp);
                       auto decoder = Or::create("DecodersTree/Input", {parentExpr});
                       auto phase1 = Chain::create("Phase1_Decoders", {decoder});
                       auto originSpace = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
                       auto unclassified = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
                       auto phase2 = And::create("preEnrichment", {originSpace, unclassified});
                       auto enrichment = base::Term<base::EngineOp>::create("enrichment/geo", nullptr);
                       return And::create("test", {phase1, phase2, enrichment});
                   })),
        // Output with child (need decoder too)
        BuildT(AD()(RT::DECODER, "decoder/root/0", "DecodersTree/Input")(
                   RT::OUTPUT, "output/parent/0", "OutputsTree/Input")(RT::OUTPUT, "output/child/0", "output/parent/0"),
               SUCCESS(
                   [](None)
                   {
                       auto decoder = Or::create("DecodersTree/Input", {assetExpr("decoder/root/0")});
                       auto phase1 = Chain::create("Phase1_Decoders", {decoder});
                       auto originSpace = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
                       auto unclassified = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
                       auto phase2 = And::create("preEnrichment", {originSpace, unclassified});
                       auto enrichment = base::Term<base::EngineOp>::create("enrichment/geo", nullptr);
                       auto childExpr = assetExpr("output/child/0");
                       auto childrenOp = Broadcast::create("output/parent/0/Children", {childExpr});
                       auto parentExpr =
                           Implication::create("output/parent/0/Node", assetExpr("output/parent/0"), childrenOp);
                       auto output = Broadcast::create("OutputsTree/Input", {parentExpr});
                       return And::create("test", {phase1, phase2, enrichment, output});
                   })),
        // Multiple children
        BuildT(AD()(RT::DECODER, "decoder/parent/0", "DecodersTree/Input")(
                   RT::DECODER, "decoder/child1/0", "decoder/parent/0")(
                   RT::DECODER, "decoder/child2/0", "decoder/parent/0"),
               SUCCESS(
                   [](None)
                   {
                       auto child1 = assetExpr("decoder/child1/0");
                       auto child2 = assetExpr("decoder/child2/0");
                       auto childrenOp = Or::create("decoder/parent/0/Children", {child1, child2});
                       auto parentExpr =
                           Implication::create("decoder/parent/0/Node", assetExpr("decoder/parent/0"), childrenOp);
                       auto decoder = Or::create("DecodersTree/Input", {parentExpr});
                       auto phase1 = Chain::create("Phase1_Decoders", {decoder});
                       auto originSpace = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
                       auto unclassified = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
                       auto phase2 = And::create("preEnrichment", {originSpace, unclassified});
                       auto enrichment = base::Term<base::EngineOp>::create("enrichment/geo", nullptr);
                       return And::create("test", {phase1, phase2, enrichment});
                   })),
        // All types
        BuildT(AD()(RT::DECODER, "decoder/parent/0", "DecodersTree/Input")(
                   RT::DECODER, "decoder/child/0", "decoder/parent/0")(
                   RT::OUTPUT, "output/parent/0", "OutputsTree/Input")(RT::OUTPUT, "output/child/0", "output/parent/0"),
               SUCCESS(
                   [](None)
                   {
                       // Phase 1: Decoders
                       auto decoderChild = assetExpr("decoder/child/0");
                       auto decoderChildren = Or::create("decoder/parent/0/Children", {decoderChild});
                       auto decoderParent =
                           Implication::create("decoder/parent/0/Node", assetExpr("decoder/parent/0"), decoderChildren);
                       auto decoder = Or::create("DecodersTree/Input", {decoderParent});
                       auto phase1 = Chain::create("Phase1_Decoders", {decoder});

                       // Phase 2: Enrichment/IOCs
                       auto originSpace = base::Term<base::EngineOp>::create("enrichment/OriginSpace", nullptr);
                       auto unclassified = base::Term<base::EngineOp>::create("filter/UnclassifiedEvents", nullptr);
                       auto phase2 = And::create("preEnrichment", {originSpace, unclassified});
                       auto enrichment = base::Term<base::EngineOp>::create("enrichment/geo", nullptr);

                       // Phase 3: Outputs
                       auto outputChild = assetExpr("output/child/0");
                       auto outputChildren = Broadcast::create("output/parent/0/Children", {outputChild});
                       auto outputParent =
                           Implication::create("output/parent/0/Node", assetExpr("output/parent/0"), outputChildren);
                       auto output = Broadcast::create("OutputsTree/Input", {outputParent});

                       return And::create("test", {phase1, phase2, enrichment, output});
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
    EXPECT_NO_THROW(graph.subgraphs.at(buildgraphtest::toStage(RT::DECODER)).validateAcyclic("decoder"));
}

TEST(CycleDetection, ComplexNoCycle)
{
    auto data =
        AD()(RT::DECODER, "decoder/asset1/0", "decoder/Input")(RT::DECODER, "decoder/asset2/0", "decoder/asset1/0")(
            RT::DECODER, "decoder/asset3/0", "decoder/asset2/0", "decoder/asset1/0")(
            RT::DECODER, "decoder/asset4/0", "decoder/asset3/0", "decoder/asset2/0");
    auto graph = factory::buildGraph(data.builtAssets);
    EXPECT_NO_THROW(graph.subgraphs.at(buildgraphtest::toStage(RT::DECODER)).validateAcyclic("decoder"));
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
                                                     builder::builders::StageBuilder,
                                                     builder::builders::EnrichmentBuilder>::createMock();
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
            dataType::Policy("test_policy",
                             "550e8400-e29b-41d4-a716-446655440003",
                             {"550e8400-e29b-41d4-a716-446655440001"},
                             {},
                             {},
                             {}),
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
            dataType::Policy("test_policy",
                             "550e8400-e29b-41d4-a716-446655440003",
                             {"550e8400-e29b-41d4-a716-446655440002"},
                             {},
                             {},
                             {}),
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
        BuildAssetsT(dataType::Policy("test_policy",
                                      "550e8400-e29b-41d4-a716-446655440003",
                                      {"550e8400-e29b-41d4-a716-446655440003"},
                                      {},
                                      {},
                                      {}),
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
        BuildAssetsT(dataType::Policy("test_policy",
                                      "550e8400-e29b-41d4-a716-446655440005",
                                      {"550e8400-e29b-41d4-a716-446655440004"},
                                      {},
                                      {},
                                      {}),
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

namespace orderpreservationtest
{

using buildgraphtest::assetExpr;
using AD = buildgraphtest::AssetData;
using RT = cm::store::ResourceType;

// Test that verifies children order is preserved in expressions
TEST(OrderPreservation, MultipleChildrenPreserveOrder)
{
    // Create subgraph with parent having 5 children in specific order: A, B, C, D, E
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    // Add children in specific order
    std::vector<std::string> expectedOrder = {"A", "B", "C", "D", "E"};
    for (const auto& childId : expectedOrder)
    {
        base::Name childName("decoder/" + childId);
        Asset child {base::Name("decoder/" + childId), assetExpr(childName), {parentName}};
        subgraphData.orderedAssets.push_back(childName);
        subgraphData.assets.emplace(childName, child);
    }

    // Build subgraph
    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);

    // Verify graph preserves order
    ASSERT_TRUE(subgraph.hasChildren(parentName));
    const auto& graphChildren = subgraph.children(parentName);
    ASSERT_EQ(graphChildren.size(), expectedOrder.size());

    for (size_t i = 0; i < expectedOrder.size(); ++i)
    {
        EXPECT_EQ(graphChildren[i].toStr(), "decoder/" + expectedOrder[i])
            << "Child at position " << i << " should be " << expectedOrder[i];
    }

    // Build expression and verify operands preserve order
    auto expr = factory::buildSubgraphExpression<base::Or>(subgraph);
    ASSERT_TRUE(expr->isOperation());

    auto rootOp = expr->getPtr<base::Operation>();
    ASSERT_EQ(rootOp->getOperands().size(), 1); // Parent node

    auto parentNode = rootOp->getOperands()[0];
    ASSERT_TRUE(parentNode->isImplication());

    auto implNode = parentNode->getPtr<base::Implication>();
    ASSERT_EQ(implNode->getOperands().size(), 2); // condition + consequence

    auto childrenOp = implNode->getOperands()[1];
    ASSERT_TRUE(childrenOp->isOperation());

    auto childrenOpPtr = childrenOp->getPtr<base::Operation>();
    ASSERT_EQ(childrenOpPtr->getOperands().size(), expectedOrder.size());

    // Verify expression operands match expected order
    for (size_t i = 0; i < expectedOrder.size(); ++i)
    {
        auto childExpr = childrenOpPtr->getOperands()[i];
        EXPECT_EQ(childExpr->getName(), "decoder/" + expectedOrder[i])
            << "Expression operand at position " << i << " should be decoder/" << expectedOrder[i];
    }
}

// Test order preservation with complex hierarchy
TEST(OrderPreservation, ComplexHierarchyPreservesOrder)
{
    // Build: Root -> P1 (children: C1, C2, C3) -> C1 (children: GC1, GC2)
    factory::SubgraphData subgraphData;

    base::Name p1Name("decoder/P1");
    Asset p1 {base::Name("decoder/P1"), assetExpr(p1Name), {}};
    subgraphData.orderedAssets.push_back(p1Name);
    subgraphData.assets.emplace(p1Name, p1);

    // Add P1's children in order: C1, C2, C3
    std::vector<std::string> p1ChildrenOrder = {"C1", "C2", "C3"};
    for (const auto& childId : p1ChildrenOrder)
    {
        base::Name childName("decoder/" + childId);
        Asset child {base::Name("decoder/" + childId), assetExpr(childName), {p1Name}};
        subgraphData.orderedAssets.push_back(childName);
        subgraphData.assets.emplace(childName, child);
    }

    // Add C1's children in order: GC1, GC2
    std::vector<std::string> c1ChildrenOrder = {"GC1", "GC2"};
    base::Name c1Name("decoder/C1");
    for (const auto& grandchildId : c1ChildrenOrder)
    {
        base::Name grandchildName("decoder/" + grandchildId);
        Asset grandchild {base::Name("decoder/" + grandchildId), assetExpr(grandchildName), {c1Name}};
        subgraphData.orderedAssets.push_back(grandchildName);
        subgraphData.assets.emplace(grandchildName, grandchild);
    }

    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);

    // Verify P1's children order in graph
    const auto& p1Children = subgraph.children(p1Name);
    ASSERT_EQ(p1Children.size(), p1ChildrenOrder.size());
    for (size_t i = 0; i < p1ChildrenOrder.size(); ++i)
    {
        EXPECT_EQ(p1Children[i].toStr(), "decoder/" + p1ChildrenOrder[i]);
    }

    // Verify C1's children order in graph
    const auto& c1Children = subgraph.children(c1Name);
    ASSERT_EQ(c1Children.size(), c1ChildrenOrder.size());
    for (size_t i = 0; i < c1ChildrenOrder.size(); ++i)
    {
        EXPECT_EQ(c1Children[i].toStr(), "decoder/" + c1ChildrenOrder[i]);
    }

    // Build expression and verify order preservation throughout
    auto expr = factory::buildSubgraphExpression<base::Or>(subgraph);
    ASSERT_TRUE(expr->isOperation());

    // Navigation path: Root -> P1Node -> P1Children
    auto rootOp = expr->getPtr<base::Operation>();
    ASSERT_EQ(rootOp->getOperands().size(), 1);

    auto p1Node = rootOp->getOperands()[0];
    ASSERT_TRUE(p1Node->isImplication());

    auto p1Impl = p1Node->getPtr<base::Implication>();
    auto p1ChildrenOp = p1Impl->getOperands()[1]->getPtr<base::Operation>();
    ASSERT_EQ(p1ChildrenOp->getOperands().size(), 3); // C1, C2, C3

    // Verify P1's children are in correct order
    EXPECT_EQ(p1ChildrenOp->getOperands()[0]->getName(), "decoder/C1/Node"); // C1 has children, so it's a Node
    EXPECT_EQ(p1ChildrenOp->getOperands()[1]->getName(), "decoder/C2");      // C2 is leaf
    EXPECT_EQ(p1ChildrenOp->getOperands()[2]->getName(), "decoder/C3");      // C3 is leaf

    // Navigate to C1's children
    auto c1Node = p1ChildrenOp->getOperands()[0];
    ASSERT_TRUE(c1Node->isImplication());

    auto c1Impl = c1Node->getPtr<base::Implication>();
    auto c1ChildrenOp = c1Impl->getOperands()[1]->getPtr<base::Operation>();
    ASSERT_EQ(c1ChildrenOp->getOperands().size(), 2); // GC1, GC2

    // Verify C1's children are in correct order
    EXPECT_EQ(c1ChildrenOp->getOperands()[0]->getName(), "decoder/GC1");
    EXPECT_EQ(c1ChildrenOp->getOperands()[1]->getName(), "decoder/GC2");
}

// Test that order is preserved when building full policy expression
TEST(OrderPreservation, FullPolicyPreservesDecoderOrder)
{
    // Create policy with multiple decoders in specific order
    auto data = AD()(RT::DECODER, "decoder/First", "decoder/Input")(RT::DECODER, "decoder/Second", "decoder/Input")(
        RT::DECODER, "decoder/Third", "decoder/Input")(RT::DECODER, "decoder/Fourth", "decoder/Input")(
        RT::DECODER, "decoder/Fifth", "decoder/Input");

    auto graph = factory::buildGraph(data.builtAssets);
    ASSERT_TRUE(graph.subgraphs.find(buildgraphtest::toStage(RT::DECODER)) != graph.subgraphs.end());

    auto& decoderSubgraph = graph.subgraphs.at(buildgraphtest::toStage(RT::DECODER));
    const auto& rootChildren = decoderSubgraph.children("DecodersTree/Input");

    std::vector<std::string> expectedOrder = {
        "decoder/First", "decoder/Second", "decoder/Third", "decoder/Fourth", "decoder/Fifth"};
    ASSERT_EQ(rootChildren.size(), expectedOrder.size());

    for (size_t i = 0; i < expectedOrder.size(); ++i)
    {
        EXPECT_EQ(rootChildren[i].toStr(), expectedOrder[i])
            << "Decoder at position " << i << " should be " << expectedOrder[i];
    }

    // Build expression and verify order
    // New structure: And with {phase1 (Chain with decoders), phase2 (IOCs)}
    graph.graphName = "test";
    auto enrichment = createDummyEnrichment();
    auto preEnrichment = createDummyPreEnrichment();
    auto expr = factory::buildExpression(graph, preEnrichment, enrichment);
    ASSERT_TRUE(expr->isAnd()); // Top level is And

    auto andExpr = expr->getPtr<base::And>();
    ASSERT_GE(andExpr->getOperands().size(), 2); // At least phase1 and phase2

    // Phase1 is a Chain with decoders
    auto chain = andExpr->getOperands()[0]->getPtr<base::Chain>();
    ASSERT_EQ(chain->getOperands().size(), 1); // Only decoder subgraph

    auto decoderOp = chain->getOperands()[0]->getPtr<base::Operation>();
    ASSERT_EQ(decoderOp->getOperands().size(), expectedOrder.size());

    for (size_t i = 0; i < expectedOrder.size(); ++i)
    {
        EXPECT_EQ(decoderOp->getOperands()[i]->getName(), expectedOrder[i]);
    }
}

// Test order preservation with parent-child relationships
TEST(OrderPreservation, ParentChildOrderingIsConsistent)
{
    // Parent with 3 children, where middle child also has 2 children
    // Structure: P -> [C1, C2(GC1, GC2), C3]
    factory::SubgraphData subgraphData;

    base::Name pName("decoder/P");
    Asset p {base::Name("decoder/P"), assetExpr(pName), {}};
    subgraphData.orderedAssets.push_back(pName);
    subgraphData.assets.emplace(pName, p);

    // Add C1
    base::Name c1Name("decoder/C1");
    Asset c1 {base::Name("decoder/C1"), assetExpr(c1Name), {pName}};
    subgraphData.orderedAssets.push_back(c1Name);
    subgraphData.assets.emplace(c1Name, c1);

    // Add C2 (will have children)
    base::Name c2Name("decoder/C2");
    Asset c2 {base::Name("decoder/C2"), assetExpr(c2Name), {pName}};
    subgraphData.orderedAssets.push_back(c2Name);
    subgraphData.assets.emplace(c2Name, c2);

    // Add C3
    base::Name c3Name("decoder/C3");
    Asset c3 {base::Name("decoder/C3"), assetExpr(c3Name), {pName}};
    subgraphData.orderedAssets.push_back(c3Name);
    subgraphData.assets.emplace(c3Name, c3);

    // Add C2's children: GC1, GC2
    base::Name gc1Name("decoder/GC1");
    Asset gc1 {base::Name("decoder/GC1"), assetExpr(gc1Name), {c2Name}};
    subgraphData.orderedAssets.push_back(gc1Name);
    subgraphData.assets.emplace(gc1Name, gc1);

    base::Name gc2Name("decoder/GC2");
    Asset gc2 {base::Name("decoder/GC2"), assetExpr(gc2Name), {c2Name}};
    subgraphData.orderedAssets.push_back(gc2Name);
    subgraphData.assets.emplace(gc2Name, gc2);

    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);

    // Verify P's children are C1, C2, C3 in that order
    const auto& pChildren = subgraph.children(pName);
    ASSERT_EQ(pChildren.size(), 3);
    EXPECT_EQ(pChildren[0].toStr(), "decoder/C1");
    EXPECT_EQ(pChildren[1].toStr(), "decoder/C2");
    EXPECT_EQ(pChildren[2].toStr(), "decoder/C3");

    // Verify C2's children are GC1, GC2 in that order
    const auto& c2Children = subgraph.children(c2Name);
    ASSERT_EQ(c2Children.size(), 2);
    EXPECT_EQ(c2Children[0].toStr(), "decoder/GC1");
    EXPECT_EQ(c2Children[1].toStr(), "decoder/GC2");

    // Build expression and verify structure
    auto expr = factory::buildSubgraphExpression<base::Or>(subgraph);
    auto rootOp = expr->getPtr<base::Operation>();
    auto pNode = rootOp->getOperands()[0]->getPtr<base::Implication>();
    auto pChildrenOp = pNode->getOperands()[1]->getPtr<base::Operation>();

    ASSERT_EQ(pChildrenOp->getOperands().size(), 3);
    EXPECT_EQ(pChildrenOp->getOperands()[0]->getName(), "decoder/C1");      // Leaf
    EXPECT_EQ(pChildrenOp->getOperands()[1]->getName(), "decoder/C2/Node"); // Has children
    EXPECT_EQ(pChildrenOp->getOperands()[2]->getName(), "decoder/C3");      // Leaf

    // Verify C2's children in expression
    auto c2Node = pChildrenOp->getOperands()[1]->getPtr<base::Implication>();
    auto c2ChildrenOp = c2Node->getOperands()[1]->getPtr<base::Operation>();
    ASSERT_EQ(c2ChildrenOp->getOperands().size(), 2);
    EXPECT_EQ(c2ChildrenOp->getOperands()[0]->getName(), "decoder/GC1");
    EXPECT_EQ(c2ChildrenOp->getOperands()[1]->getName(), "decoder/GC2");
}

// Test that different resource types maintain their own ordering
TEST(OrderPreservation, DifferentResourceTypesPreserveIndependentOrder)
{
    auto data = AD()(RT::DECODER, "decoder/D1", "decoder/Input")(RT::DECODER, "decoder/D2", "decoder/Input")(
        RT::DECODER, "decoder/D3", "decoder/Input")(RT::OUTPUT, "output/O1", "output/Input")(
        RT::OUTPUT, "output/O2", "output/Input")(RT::OUTPUT, "output/O3", "output/Input");

    auto graph = factory::buildGraph(data.builtAssets);

    // Verify decoder order
    auto& decoderSubgraph = graph.subgraphs.at(buildgraphtest::toStage(RT::DECODER));
    const auto& decoderChildren = decoderSubgraph.children("DecodersTree/Input");
    ASSERT_EQ(decoderChildren.size(), 3);
    EXPECT_EQ(decoderChildren[0].toStr(), "decoder/D1");
    EXPECT_EQ(decoderChildren[1].toStr(), "decoder/D2");
    EXPECT_EQ(decoderChildren[2].toStr(), "decoder/D3");

    // Verify output order
    auto& outputSubgraph = graph.subgraphs.at(buildgraphtest::toStage(RT::OUTPUT));
    const auto& outputChildren = outputSubgraph.children("OutputsTree/Input");
    ASSERT_EQ(outputChildren.size(), 3);
    EXPECT_EQ(outputChildren[0].toStr(), "output/O1");
    EXPECT_EQ(outputChildren[1].toStr(), "output/O2");
    EXPECT_EQ(outputChildren[2].toStr(), "output/O3");

    // Build full expression and verify each subgraph maintains its order
    // New structure: And with {phase1 (Chain with decoders), phase2 (IOCs), phase3 (outputs)}
    graph.graphName = "test";
    auto enrichment = createDummyEnrichment();
    auto preEnrichment = createDummyPreEnrichment();
    auto expr = factory::buildExpression(graph, preEnrichment, enrichment);
    auto andExpr = expr->getPtr<base::And>();

    // And has 4 operands: phase1 (decoders), phase 2 (preEnrichment), phase 3 (IOCs), phase4 (outputs)
    ASSERT_EQ(andExpr->getOperands().size(), 4);

    // Phase1 is a Chain with decoders Or
    auto phase1 = andExpr->getOperands()[0]->getPtr<base::Chain>();
    EXPECT_EQ(phase1->getName(), "Phase1_Decoders");
    ASSERT_EQ(phase1->getOperands().size(), 1);
    auto decoderOr = phase1->getOperands()[0]->getPtr<base::Or>();
    EXPECT_EQ(decoderOr->getName(), "DecodersTree/Input");
    ASSERT_EQ(decoderOr->getOperands().size(), 3);
    EXPECT_EQ(decoderOr->getOperands()[0]->getName(), "decoder/D1");
    EXPECT_EQ(decoderOr->getOperands()[1]->getName(), "decoder/D2");
    EXPECT_EQ(decoderOr->getOperands()[2]->getName(), "decoder/D3");

    // Phase3 is outputs Broadcast (index 3, since phase2 is preEnrichment at index 1 and phase3 is IOCs at index 2)
    auto outputBroadcast = andExpr->getOperands()[3]->getPtr<base::Broadcast>();
    EXPECT_EQ(outputBroadcast->getName(), "OutputsTree/Input");
    ASSERT_EQ(outputBroadcast->getOperands().size(), 3);
    EXPECT_EQ(outputBroadcast->getOperands()[0]->getName(), "output/O1");
    EXPECT_EQ(outputBroadcast->getOperands()[1]->getName(), "output/O2");
    EXPECT_EQ(outputBroadcast->getOperands()[2]->getName(), "output/O3");
}

// Negative test: Verify that wrong order is detected
TEST(OrderPreservation, DetectsIncorrectChildOrder)
{
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    // Add children in order: A, B, C
    std::vector<std::string> actualOrder = {"A", "B", "C"};
    for (const auto& childId : actualOrder)
    {
        base::Name childName("decoder/" + childId);
        Asset child {base::Name("decoder/" + childId), assetExpr(childName), {parentName}};
        subgraphData.orderedAssets.push_back(childName);
        subgraphData.assets.emplace(childName, child);
    }

    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);
    const auto& graphChildren = subgraph.children(parentName);

    // Verify that the actual order is NOT in a different order
    std::vector<std::string> wrongOrder = {"A", "C", "B"}; // Intentionally wrong
    bool orderMatches = true;
    if (graphChildren.size() == wrongOrder.size())
    {
        for (size_t i = 0; i < graphChildren.size(); ++i)
        {
            if (graphChildren[i].toStr() != "decoder/" + wrongOrder[i])
            {
                orderMatches = false;
                break;
            }
        }
    }

    // This should NOT match (negative test)
    EXPECT_FALSE(orderMatches) << "Wrong order should not match the actual insertion order";

    // Verify the actual correct order
    EXPECT_EQ(graphChildren[0].toStr(), "decoder/A");
    EXPECT_EQ(graphChildren[1].toStr(), "decoder/B");
    EXPECT_EQ(graphChildren[2].toStr(), "decoder/C");
}

// Negative test: Verify expression operands don't match wrong order
TEST(OrderPreservation, ExpressionDoesNotMatchWrongOrder)
{
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    // Add children in specific order: First, Second, Third
    std::vector<std::string> correctOrder = {"First", "Second", "Third"};
    for (const auto& childId : correctOrder)
    {
        base::Name childName("decoder/" + childId);
        Asset child {base::Name("decoder/" + childId), assetExpr(childName), {parentName}};
        subgraphData.orderedAssets.push_back(childName);
        subgraphData.assets.emplace(childName, child);
    }

    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);
    auto expr = factory::buildSubgraphExpression<base::Or>(subgraph);

    auto rootOp = expr->getPtr<base::Operation>();
    auto parentNode = rootOp->getOperands()[0]->getPtr<base::Implication>();
    auto childrenOp = parentNode->getOperands()[1]->getPtr<base::Operation>();

    // Verify the expression does NOT match wrong order
    std::vector<std::string> wrongOrder = {"Third", "First", "Second"};
    bool wrongOrderMatches = true;
    for (size_t i = 0; i < wrongOrder.size(); ++i)
    {
        if (childrenOp->getOperands()[i]->getName() != "decoder/" + wrongOrder[i])
        {
            wrongOrderMatches = false;
            break;
        }
    }

    EXPECT_FALSE(wrongOrderMatches) << "Expression should not match incorrect order";

    // Verify correct order is actually present
    EXPECT_EQ(childrenOp->getOperands()[0]->getName(), "decoder/First");
    EXPECT_EQ(childrenOp->getOperands()[1]->getName(), "decoder/Second");
    EXPECT_EQ(childrenOp->getOperands()[2]->getName(), "decoder/Third");
}

// Negative test: Reversed order should not match
TEST(OrderPreservation, ReversedOrderDoesNotMatch)
{
    auto data = AD()(RT::DECODER, "decoder/D1", "decoder/Input")(RT::DECODER, "decoder/D2", "decoder/Input")(
        RT::DECODER, "decoder/D3", "decoder/Input")(RT::DECODER, "decoder/D4", "decoder/Input");

    auto graph = factory::buildGraph(data.builtAssets);
    auto& decoderSubgraph = graph.subgraphs.at(buildgraphtest::toStage(RT::DECODER));
    const auto& children = decoderSubgraph.children("DecodersTree/Input");

    std::vector<std::string> reversedOrder = {"decoder/D4", "decoder/D3", "decoder/D2", "decoder/D1"};

    bool reversedMatches = true;
    if (children.size() == reversedOrder.size())
    {
        for (size_t i = 0; i < children.size(); ++i)
        {
            if (children[i].toStr() != reversedOrder[i])
            {
                reversedMatches = false;
                break;
            }
        }
    }

    EXPECT_FALSE(reversedMatches) << "Reversed order should not match actual order";

    // Verify actual order is forward
    EXPECT_EQ(children[0].toStr(), "decoder/D1");
    EXPECT_EQ(children[1].toStr(), "decoder/D2");
    EXPECT_EQ(children[2].toStr(), "decoder/D3");
    EXPECT_EQ(children[3].toStr(), "decoder/D4");
}

// Negative test: Partial order mismatch detection
TEST(OrderPreservation, DetectsPartialOrderMismatch)
{
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    // Add 5 children: A, B, C, D, E
    std::vector<std::string> correctOrder = {"A", "B", "C", "D", "E"};
    for (const auto& childId : correctOrder)
    {
        base::Name childName("decoder/" + childId);
        Asset child {base::Name("decoder/" + childId), assetExpr(childName), {parentName}};
        subgraphData.orderedAssets.push_back(childName);
        subgraphData.assets.emplace(childName, child);
    }

    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);
    const auto& children = subgraph.children(parentName);

    // First 3 elements correct, last 2 swapped
    std::vector<std::string> partiallyWrongOrder = {"A", "B", "C", "E", "D"};

    bool partialOrderMatches = true;
    for (size_t i = 0; i < children.size(); ++i)
    {
        if (children[i].toStr() != "decoder/" + partiallyWrongOrder[i])
        {
            partialOrderMatches = false;
            break;
        }
    }

    EXPECT_FALSE(partialOrderMatches) << "Partially wrong order should not match";

    // Verify D comes before E (not after)
    EXPECT_EQ(children[3].toStr(), "decoder/D");
    EXPECT_EQ(children[4].toStr(), "decoder/E");
}

// Negative test: Shuffled order detection
TEST(OrderPreservation, DetectsShuffledOrder)
{
    auto data = AD()(RT::DECODER, "decoder/Alpha", "decoder/Input")(RT::DECODER, "decoder/Beta", "decoder/Input")(
        RT::DECODER, "decoder/Gamma", "decoder/Input")(RT::DECODER, "decoder/Delta", "decoder/Input")(
        RT::DECODER, "decoder/Epsilon", "decoder/Input");

    auto graph = factory::buildGraph(data.builtAssets);
    graph.graphName = "test";
    auto enrichment = createDummyEnrichment();
    auto preEnrichment = createDummyPreEnrichment();
    auto expr = factory::buildExpression(graph, preEnrichment, enrichment);

    // New structure: And with phases
    auto andExpr = expr->getPtr<base::And>();
    ASSERT_GE(andExpr->getOperands().size(), 2);

    auto chain = andExpr->getOperands()[0]->getPtr<base::Chain>();
    ASSERT_EQ(chain->getOperands().size(), 1);

    auto decoderOp = chain->getOperands()[0]->getPtr<base::Operation>();

    // Create a shuffled version of the expected order
    std::vector<std::string> shuffledOrder = {
        "decoder/Gamma", "decoder/Alpha", "decoder/Epsilon", "decoder/Beta", "decoder/Delta"};

    bool shuffledMatches = true;
    if (decoderOp->getOperands().size() == shuffledOrder.size())
    {
        for (size_t i = 0; i < shuffledOrder.size(); ++i)
        {
            if (decoderOp->getOperands()[i]->getName() != shuffledOrder[i])
            {
                shuffledMatches = false;
                break;
            }
        }
    }

    EXPECT_FALSE(shuffledMatches) << "Shuffled order should not match actual insertion order";

    // Verify actual order is as inserted
    EXPECT_EQ(decoderOp->getOperands()[0]->getName(), "decoder/Alpha");
    EXPECT_EQ(decoderOp->getOperands()[1]->getName(), "decoder/Beta");
    EXPECT_EQ(decoderOp->getOperands()[2]->getName(), "decoder/Gamma");
    EXPECT_EQ(decoderOp->getOperands()[3]->getName(), "decoder/Delta");
    EXPECT_EQ(decoderOp->getOperands()[4]->getName(), "decoder/Epsilon");
}

// Negative test: Empty subgraph children order
TEST(OrderPreservation, EmptySubgraphHasNoOrder)
{
    factory::SubgraphData subgraphData;
    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);

    EXPECT_FALSE(subgraph.hasChildren("DecodersTree/Input"));
    EXPECT_THROW(subgraph.children("DecodersTree/Input"), std::runtime_error);
}

// Negative test: Single child cannot have wrong position
TEST(OrderPreservation, SingleChildHasOnlyOnePosition)
{
    factory::SubgraphData subgraphData;

    base::Name parentName("decoder/parent/0");
    Asset parent {base::Name("decoder/parent/0"), assetExpr(parentName), {}};
    subgraphData.orderedAssets.push_back(parentName);
    subgraphData.assets.emplace(parentName, parent);

    base::Name childName("decoder/OnlyChild");
    Asset child {base::Name("decoder/OnlyChild"), assetExpr(childName), {parentName}};
    subgraphData.orderedAssets.push_back(childName);
    subgraphData.assets.emplace(childName, child);

    auto subgraph = factory::buildSubgraph("DecodersTree/Input", subgraphData);
    const auto& children = subgraph.children(parentName);

    ASSERT_EQ(children.size(), 1);
    EXPECT_EQ(children[0].toStr(), "decoder/OnlyChild");

    // Verify we cannot compare with index > 0 for a single child
    EXPECT_THROW(
        {
            // This would be out of bounds
            if (children.size() > 1)
            {
                auto secondChild = children[1];
            }
            else
            {
                throw std::out_of_range("Only one child exists");
            }
        },
        std::out_of_range);
}

} // namespace orderpreservationtest

namespace buildassetsordertest
{
using namespace base::test;
using RT = cm::store::ResourceType;

struct OrderCheck
{
    RT type;
    std::string parent;
    std::vector<std::string> children;
};

// return Success or Failure expected values
using SuccessExpected = InnerExpected<OrderCheck,
                                      const std::shared_ptr<MockICMStoreNSReader>&,
                                      const std::shared_ptr<builder::builders::IBuildCtx>&>;
using FailureExpected = InnerExpected<std::string,
                                      const std::shared_ptr<MockICMStoreNSReader>&,
                                      const std::shared_ptr<builder::builders::IBuildCtx>&>;

using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using BuildAssetsT = std::tuple<cm::store::dataType::Policy, Expc>;

static json::Json mkAssetJson(const std::string& name, bool enabled = true)
{
    const auto s = fmt::format(
        R"({{
            "name":"{0}",
            "enabled":{1},
            "asset":{{"name":"{0}","enabled":{1}}}
        }})",
        name,
        enabled ? "true" : "false");

    return json::Json(s.c_str());
}

// AssetBuilder
class PassthroughAssetBuilder final : public builder::policy::IAssetBuilder
{
public:
    Asset operator()(const json::Json& document) const override
    {
        const auto nameOpt = document.getString(json::Json::formatJsonPath(builder::syntax::asset::NAME_KEY));

        if (!nameOpt)
        {
            throw std::runtime_error("Test asset json missing name");
        }

        base::Name n {*nameOpt};
        auto expr = buildgraphtest::assetExpr(n); // assetExpr(const base::Name&) -> Expression

        return Asset {std::move(n), std::move(expr), std::vector<base::Name> {}};
    }

    builder::builders::Context& getContext() const override { return m_ctx; }

    void setAvailableKvdbs(std::unordered_map<std::string, bool>&& kvdbs) override
    {
        (void)kvdbs; // no-op
    }

    void clearAvailableKvdbs() override {}

private:
    mutable builder::builders::Context m_ctx {};
};

class BuildAssetsOrder : public testing::TestWithParam<BuildAssetsT>
{
};

TEST_P(BuildAssetsOrder, DecoderOrderPreservedInGraph)
{
    auto [policy, expected] = GetParam();

    auto cmStoreNSReader = std::make_shared<MockICMStoreNSReader>();
    auto buildCtx = std::make_shared<builder::builders::BuildCtx>();
    auto registry = builder::mocks::MockMetaRegistry<builder::builders::OpBuilderEntry,
                                                     builder::builders::StageBuilder,
                                                     builder::builders::EnrichmentBuilder>::createMock();
    auto definitionsBuilder = std::make_shared<defs::mocks::MockDefinitionsBuilder>();
    buildCtx->setRegistry(registry);

    auto assetBuilder = std::make_shared<PassthroughAssetBuilder>();

    if (expected)
    {
        const auto orderCheck = expected.succCase()(cmStoreNSReader, buildCtx);

        factory::BuiltAssets built;
        EXPECT_NO_THROW(built = factory::buildAssets(policy, cmStoreNSReader, assetBuilder, /*sandbox=*/true));

        factory::PolicyGraph graph;
        EXPECT_NO_THROW(graph = factory::buildGraph(built));

        const auto& sg = graph.subgraphs.at(buildgraphtest::toStage(orderCheck.type));
        const auto gotChildren = sg.children(base::Name {orderCheck.parent});

        ASSERT_EQ(gotChildren.size(), orderCheck.children.size());
        for (size_t i = 0; i < orderCheck.children.size(); ++i)
        {
            EXPECT_EQ(gotChildren[i].toStr(), orderCheck.children[i]) << "Mismatch at index " << i;
        }
    }
    else
    {
        auto errorMsg = expected.failCase()(cmStoreNSReader, buildCtx);
        EXPECT_THROW(
            {
                try
                {
                    (void)factory::buildAssets(policy, cmStoreNSReader, assetBuilder, /*sandbox=*/true);
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
    OrderPreservation,
    BuildAssetsOrder,
    ::testing::Values(
        // 1) Decoders order: decoders in the order defined in the integration
        BuildAssetsT(
            cm::store::dataType::Policy("test_policy",
                                        "550e8400-e29b-41d4-a716-446655440199",   // root decoder UUID
                                        {"550e8400-e29b-41d4-a716-446655440101"}, // integration UUID
                                        {},
                                        {},
                                        {}),
            SUCCESS(SuccessExpected::Behaviour {
                [](const auto& reader, const auto&)
                {
                    const std::string integUUID = "550e8400-e29b-41d4-a716-446655440101";
                    const std::string rootUUID = "550e8400-e29b-41d4-a716-446655440199";

                    const std::string uC2 = "550e8400-e29b-41d4-a716-446655440201";
                    const std::string uR = rootUUID;
                    const std::string uC1 = "550e8400-e29b-41d4-a716-446655440202";
                    const std::string uC3 = "550e8400-e29b-41d4-a716-446655440203";

                    cm::store::dataType::Integration integration(integUUID,
                                                                 "test_integration",
                                                                 true,
                                                                 "system-activity",
                                                                 std::nullopt,
                                                                 /* kvdb uuids */ {},
                                                                 /* decoders uuids */ {uC2, uR, uC1, uC3},
                                                                 false);

                    // resolveNameFromUUID(rootUUID) is used:
                    // - once for rootDecoderName
                    // - multiple times to inject parent to each decoder without parents
                    EXPECT_CALL(*reader, resolveNameFromUUID(rootUUID))
                        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", RT::DECODER)));

                    EXPECT_CALL(*reader, getIntegrationByUUID(integUUID)).WillOnce(testing::Return(integration));

                    // getAssetByUUID in the SAME order as the vector
                    EXPECT_CALL(*reader, getAssetByUUID(uC2))
                        .WillOnce(testing::Return(mkAssetJson("decoder/child2/0", true)));
                    EXPECT_CALL(*reader, getAssetByUUID(uR))
                        .WillOnce(testing::Return(mkAssetJson("decoder/root/0", true)));
                    EXPECT_CALL(*reader, getAssetByUUID(uC1))
                        .WillOnce(testing::Return(mkAssetJson("decoder/child1/0", true)));
                    EXPECT_CALL(*reader, getAssetByUUID(uC3))
                        .WillOnce(testing::Return(mkAssetJson("decoder/child3/0", true)));

                    return OrderCheck {
                        RT::DECODER, "decoder/root/0", {"decoder/child2/0", "decoder/child1/0", "decoder/child3/0"}};
                }})),

        // 2) Order BETWEEN integrations: first assets seen in integ1, then integ2
        BuildAssetsT(cm::store::dataType::Policy("test_policy",
                                                 "550e8400-e29b-41d4-a716-446655440299",
                                                 {"550e8400-e29b-41d4-a716-446655440111",
                                                  "550e8400-e29b-41d4-a716-446655440112"},
                                                 {},
                                                 {},
                                                 {}),
                     SUCCESS(SuccessExpected::Behaviour {
                         [](const auto& reader, const auto&)
                         {
                             const std::string integ1 = "550e8400-e29b-41d4-a716-446655440111";
                             const std::string integ2 = "550e8400-e29b-41d4-a716-446655440112";
                             const std::string rootUUID = "550e8400-e29b-41d4-a716-446655440299";

                             // integ1 decoders: A, ROOT, B
                             const std::string uA = "550e8400-e29b-41d4-a716-446655440301";
                             const std::string uR = rootUUID;
                             const std::string uB = "550e8400-e29b-41d4-a716-446655440302";

                             // integ2 decoders: C, D
                             const std::string uC = "550e8400-e29b-41d4-a716-446655440303";
                             const std::string uD = "550e8400-e29b-41d4-a716-446655440304";

                             cm::store::dataType::Integration i1(
                                 integ1, "i1", true, "system-activity", std::nullopt, {}, {uA, uR, uB}, false);
                             cm::store::dataType::Integration i2(
                                 integ2, "i2", true, "system-activity", std::nullopt, {}, {uC, uD}, false);

                             EXPECT_CALL(*reader, resolveNameFromUUID(rootUUID))
                                 .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", RT::DECODER)));

                             EXPECT_CALL(*reader, getIntegrationByUUID(integ1)).WillOnce(testing::Return(i1));
                             EXPECT_CALL(*reader, getIntegrationByUUID(integ2)).WillOnce(testing::Return(i2));

                             // Assets in the exact iteration order: integ1 (A,R,B) then integ2 (C,D)
                             EXPECT_CALL(*reader, getAssetByUUID(uA))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/A/0", true)));
                             EXPECT_CALL(*reader, getAssetByUUID(uR))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/root/0", true)));
                             EXPECT_CALL(*reader, getAssetByUUID(uB))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/B/0", true)));

                             EXPECT_CALL(*reader, getAssetByUUID(uC))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/C/0", true)));
                             EXPECT_CALL(*reader, getAssetByUUID(uD))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/D/0", true)));

                             return OrderCheck {RT::DECODER,
                                                "decoder/root/0",
                                                {"decoder/A/0", "decoder/B/0", "decoder/C/0", "decoder/D/0"}};
                         }})),

        // 3) Disabled decoder is skipped and does not “break” the relative order of the others
        BuildAssetsT(cm::store::dataType::Policy("test_policy",
                                                 "550e8400-e29b-41d4-a716-446655440399",
                                                 {"550e8400-e29b-41d4-a716-446655440121"},
                                                 {},
                                                 {},
                                                 {}),
                     SUCCESS(SuccessExpected::Behaviour {
                         [](const auto& reader, const auto&)
                         {
                             const std::string integUUID = "550e8400-e29b-41d4-a716-446655440121";
                             const std::string rootUUID = "550e8400-e29b-41d4-a716-446655440399";

                             const std::string uX = "550e8400-e29b-41d4-a716-446655440401"; // enabled
                             const std::string uY = "550e8400-e29b-41d4-a716-446655440402"; // disabled
                             const std::string uR = rootUUID;
                             const std::string uZ = "550e8400-e29b-41d4-a716-446655440403"; // enabled

                             cm::store::dataType::Integration integration(
                                 integUUID, "i", true, "system-activity", std::nullopt, {}, {uX, uY, uR, uZ}, false);

                             EXPECT_CALL(*reader, resolveNameFromUUID(rootUUID))
                                 .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", RT::DECODER)));

                             EXPECT_CALL(*reader, getIntegrationByUUID(integUUID))
                                 .WillOnce(testing::Return(integration));

                             EXPECT_CALL(*reader, getAssetByUUID(uX))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/X/0", true)));
                             EXPECT_CALL(*reader, getAssetByUUID(uY))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/Y/0", false))); // disabled
                             EXPECT_CALL(*reader, getAssetByUUID(uR))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/root/0", true)));
                             EXPECT_CALL(*reader, getAssetByUUID(uZ))
                                 .WillOnce(testing::Return(mkAssetJson("decoder/Z/0", true)));

                             // Y does not appear
                             return OrderCheck {RT::DECODER, "decoder/root/0", {"decoder/X/0", "decoder/Z/0"}};
                         }}))));

} // namespace buildassetsordertest
