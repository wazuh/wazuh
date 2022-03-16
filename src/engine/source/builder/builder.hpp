/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDER_H
#define _BUILDER_H

#include <functional>
#include <stdexcept>
#include <variant>
#include <vector>

#include "builderTypes.hpp"
#include "graph.hpp"
#include "registry.hpp"
#include <profile/profile.hpp>

namespace builder
{

/**
 * @brief The builder class is the responsible to transform and environment
 * definition into a graph of RXCPP operations.
 *
 * @tparam Catalog type of the catalog for dependency injection.
 */
template<class Catalog>
class Builder
{
private:
    const Catalog &m_catalog;

    /**
     * @brief Builds a graph of asset types, graph returned only contains a node (connectable) for
     * each asset, without edges or root/end nodes.
     *
     * @param atype asset type to be built
     * @param v json Value with the list of assets
     * @param make builder of assets
     * @return internals::Graph not connected.
     */
    internals::Graph assetBuilder(std::string atype, const json::Value & v, internals::types::AssetBuilder make)
    {
        internals::Graph g;
        if (v.IsArray())
        {
            for (auto & m : v.GetArray())
            {
                json::Document asset = m_catalog.getAsset(atype, m.GetString());
                g.addNode(make(asset));
            }
        }

        return g;
    }

public:
    /**
     * @brief Construct a new Builder object
     *
     * @param c Catalog
     */
    Builder(const Catalog & c) : m_catalog(c){};

    /**
     * @brief An environment might have decoders, rules, filters and outputs,
     * but only an output is mandatory. All of them are arranged into a graph.
     * Each graph leaf is connected with the root of the next tree.
     *
     * If the environment has other stages, they're ignored. The order of the
     *  tree is:
     *  server · router · decoders · ---------------> · outputs
     *                             \---> · rules · --/
     *
     * Filters can be connected to decoders and rules leaves, to discard some
     * events. They cannot attach themselves between two decoders or two rules.
     *
     * @param name name of the environment
     * @return Graph_t execution graph
     */
    internals::Graph build(const std::string & name)
    {
        json::Document asset = m_catalog.getAsset("environment", name);
        // TODO: Parametrize - define constextp string
        // TODO: make it trully dynamic
        // Input, graph, output
        std::vector<std::tuple<std::string, internals::Graph, std::string>> subGraphs;
        // Build decoder subgraph
        if (asset.exists("/decoders"))
        {
            auto decoderGraph = this->assetBuilder(
                "decoder", asset.get("/decoders"),
                std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("decoder")));
            // decoderGraph.addParentEdges("INPUT_DECODER", "OUTPUT_DECODER");
            subGraphs.push_back(std::make_tuple("INPUT_DECODER", decoderGraph, "OUTPUT_DECODER"));
        }

        // Build rule subgraph
        if (asset.exists("/rules"))
        {
            auto ruleGraph =
                this->assetBuilder("rule", asset.get("/rules"),
                                   std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("rule")));
            //ruleGraph.addParentEdges("INPUT_RULE", "OUTPUT_RULE");
            subGraphs.push_back(std::make_tuple("INPUT_RULE", ruleGraph, "OUTPUT_RULE"));
        }

        // Build output subgraph
        if (asset.exists("/outputs"))
        {
            auto outputGraph =
                this->assetBuilder("output", asset.get("/outputs"),
                                   std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("output")));
            //outputGraph.addParentEdges("INPUT_OUTPUT", "OUTPUT_OUTPUT");
            subGraphs.push_back(std::make_tuple("INPUT_OUTPUT", outputGraph, "OUTPUT_OUTPUT"));
        }

        // Join and connect subgraphs, handle first outside loop
        if (subGraphs.empty())
        {
            throw std::runtime_error("Error building graph, atleast one subgraph must be defined");
        }
        auto graphTuple = subGraphs[0];
        internals::Graph g = std::get<1>(graphTuple);
        g.addParentEdges(std::get<0>(graphTuple), std::get<2>(graphTuple));
        for (auto it = ++subGraphs.begin(); it != subGraphs.end(); ++it)
        {
            // Connect current subgraph
            std::get<1>(*it).addParentEdges(std::get<0>(*it), std::get<2>(*it));

            // Join it
            g = g.join(std::get<1>(*it), std::get<2>(graphTuple), std::get<0>(*it));

            // Update prev
            graphTuple = *it;
        }

        // Filters are not joined, are injected
        // Build filter subgraph
        if (asset.exists("/filters"))
        {
            auto filterGraph =
                this->assetBuilder("filter", asset.get("/filters"),
                                   std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("filter")));
            g = g.inject(filterGraph);
        }

        // Multiple outputs are manual
        if (asset.exists("/decoders") && asset.exists("/rules") && asset.exists("/outputs"))
        {
            g.addEdge("OUTPUT_DECODER", "INPUT_OUTPUT");
            g.m_nodes["INPUT_OUTPUT"].m_parents.push_back("OUTPUT_DECODER");
        }

        return g;
    }

    /**
     * @brief Lifter of the whole execution graph.
     * Calls all connectable lifters in the order defined by the graph, ensuring
     * all connectables all connected when all inputs are defined.
     *
     * @param name Environment name to build/lift
     * @return internals::types::Lifter
     */
    internals::types::Lifter operator()(const std::string & name)
    {
        // Lifter
        return [=](internals::types::Observable o) -> internals::types::Observable
        {
            // Build the graph
            // TODO: move build outside of lift, its declared here because if passed by capture
            // value it becames inmutable
            auto g = this->build(name);

            internals::types::Observable last;
            std::vector<decltype(last.publish())> toConnect;

            // Recursive visitor function to call all connectable lifters and build the whole rxcpp
            // pipeline
            auto visit = [&g, &last, &toConnect](internals::types::Observable source, std::string root,
                                                 auto & visit_ref) -> void
            {
                // Only must be executed one, graph input
                if (g[root].m_inputs.size() == 0)
                {
                    g[root].addInput(source);
                }

                // Call connect.publish only if this connectable has more than one child
                auto obs = [&toConnect, &g, root]() -> internals::types::Observable
                {
                    if (g.m_edges[root].size() > 1)
                    {
                        auto o = g[root].connect().publish();
                        toConnect.push_back(o);
                        return o;
                    }
                    else
                    {
                        return g[root].connect();
                    }
                }();

                // Add obs as an input to the childs
                for (auto & n : g.m_edges[root])
                {
                    g[n].addInput(obs);
                }

                // TODO: merge both fors?
                // Visit childs only if all child inputs have been passed
                for (auto & n : g.m_edges[root])
                {
                    if (g[n].m_inputs.size() == g[n].m_parents.size())
                        visit_ref(obs, n, visit_ref);
                }

                // Only executed one, graph output
                if (g.m_edges[root].size() == 0)
                {
                    last = obs;
                }
            };

            // Start recursive visitor
            visit(o, "INPUT_DECODER", visit);

            // Call observables.connect in inverse order of connectable.publish calls
            for (auto it = toConnect.rbegin(); it != toConnect.rend(); ++it)
            {
                it->connect();
            }

            // Finally return output
            return last;
        };
    }
};

} // namespace builder

#endif // _BUILDER_H
