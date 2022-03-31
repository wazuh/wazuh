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
#include <vector>

#include "builderTypes.hpp"
#include "graph.hpp"
#include "registry.hpp"

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
     * @brief Builds a graph of asset types, graph returned only contains a node
     * (connectable) for each asset, without edges or root/end nodes.
     *
     * @param atype asset type to be built
     * @param v json Value with the list of assets
     * @param make builder of assets
     * @return internals::Graph not connected.
     */
    internals::Graph assetBuilder(std::string atype,
                                  const json::Value &v,
                                  internals::types::AssetBuilder make)
    {
        internals::Graph g;
        if (v.IsArray())
        {
            for (auto &m : v.GetArray())
            {
                json::Document asset = m_catalog.getAsset(atype, m.GetString());
                g.addNode(make(asset));
            }
        }

        return g;
    }

    // Needed by router as a return type by operator()
    // TODO: only used by operator(), we could use an unnamed struct instead
    struct envBuilder
    {
        internals::types::Lifter m_lifter;
        std::map<std::string, rxcpp::observable<std::string>> m_traceSinks;
        internals::types::Lifter getLifter() const
        {
            return m_lifter;
        }
        std::map<std::string, rxcpp::observable<std::string>>
        getTraceSinks() const
        {
            return m_traceSinks;
        }
    };

public:
    /**
     * @brief Construct a new Builder object
     *
     * @param c Catalog
     */
    Builder(const Catalog &c)
        : m_catalog(c) {};

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
    internals::Graph build(const std::string &name)
    {
        json::Document asset = m_catalog.getAsset("environment", name);
        // TODO: Parametrize - define constextp string
        // TODO: make it trully dynamic
        // Input, graph, output
        std::vector<std::tuple<std::string, internals::Graph, std::string>>
            subGraphs;
        // Build decoder subgraph
        if (asset.exists("/decoders"))
        {
            auto decoderGraph = this->assetBuilder(
                "decoder",
                asset.get("/decoders"),
                std::get<internals::types::AssetBuilder>(
                    internals::Registry::getBuilder("decoder")));
            subGraphs.push_back(std::make_tuple(
                "INPUT_DECODER", decoderGraph, "OUTPUT_DECODER"));
        }

        // Build rule subgraph
        if (asset.exists("/rules"))
        {
            auto ruleGraph = this->assetBuilder(
                "rule",
                asset.get("/rules"),
                std::get<internals::types::AssetBuilder>(
                    internals::Registry::getBuilder("rule")));
            // TODO: proper implement that rules are the first choice.
            // As it is a set ordered by name, to check rules before
            // outputs an A has been added to the name
            subGraphs.push_back(
                std::make_tuple("INPUT_ARULE", ruleGraph, "OUTPUT_RULE"));
        }

        // Build output subgraph
        if (asset.exists("/outputs"))
        {
            auto outputGraph = this->assetBuilder(
                "output",
                asset.get("/outputs"),
                std::get<internals::types::AssetBuilder>(
                    internals::Registry::getBuilder("output")));
            subGraphs.push_back(
                std::make_tuple("INPUT_OUTPUT", outputGraph, "OUTPUT_OUTPUT"));
        }

        // Join and connect subgraphs, handle first outside loop
        if (subGraphs.empty())
        {
            throw std::runtime_error(
                "Error building graph, atleast one subgraph must be defined");
        }
        auto graphTuple = subGraphs[0]; // input graph output
        internals::Graph g = std::get<1>(graphTuple);
        g.addParentEdges(std::get<0>(graphTuple), std::get<2>(graphTuple));
        for (auto it = ++subGraphs.begin(); it != subGraphs.end(); ++it)
        {
            // Connect current subgraph
            std::get<1>(*it).addParentEdges(std::get<0>(*it), std::get<2>(*it));

            // Join it
            g = g.join(
                std::get<1>(*it), std::get<2>(graphTuple), std::get<0>(*it));

            // Update prev
            graphTuple = *it;
        }

        // Filters are not joined, are injected
        // Build filter subgraph
        if (asset.exists("/filters"))
        {
            auto filterGraph = this->assetBuilder(
                "filter",
                asset.get("/filters"),
                std::get<internals::types::AssetBuilder>(
                    internals::Registry::getBuilder("filter")));
            g = g.inject(filterGraph);
        }

        // Multiple outputs are manual
        // TODO: hardcoded
        if (asset.exists("/decoders") && asset.exists("/rules") &&
            asset.exists("/outputs"))
        {
            g.addEdge("OUTPUT_DECODER", "INPUT_OUTPUT");
            g.m_nodes["INPUT_OUTPUT"].m_parents.insert("OUTPUT_DECODER");
        }

        return g;
    }

    /**
     * @brief Return an struct with the lifter for the given enviroment name and
     * with all assets debug sinks.
     *
     * @param name Environment name to build/lift
     * @return envBuilder
     */
    envBuilder operator()(const std::string &name)
    {
        envBuilder ret;
        std::shared_ptr<internals::Graph> g =
            std::make_shared<internals::Graph>(this->build(name));

        // Debug sinks
        g->visit([&](auto node)
                 { ret.m_traceSinks[node.m_name] = node.m_tracer.m_out; });

        // Lifter
        ret.m_lifter =
            [g](internals::types::Observable o) -> internals::types::Observable
        {
            internals::types::Observable last;

            // Recursive visitor function to call all connectable lifters and
            // build the whole rxcpp pipeline
            auto visit = [&g, &last](internals::types::Observable source,
                                     std::string root,
                                     auto &visit_ref) -> void
            {
                // Only must be executed one, graph input
                if (g->m_nodes[root].m_inputs.size() == 0)
                {
                    g->m_nodes[root].addInput(source);
                }

                // Call connect.publish only if this connectable has more than
                // one child
                auto obs = [&g, root]() -> internals::types::Observable
                {
                    if (g->m_edges[root].size() > 1)
                    {
                        auto o =
                            g->m_nodes[root].connect().publish().ref_count();
                        return o;
                    }
                    else
                    {
                        return g->m_nodes[root].connect();
                    }
                }();

                // Add obs as an input to the childs
                for (auto &n : g->m_edges[root])
                {
                    g->m_nodes[n].addInput(obs);
                    if (g->m_nodes[n].m_inputs.size() ==
                        g->m_nodes[n].m_parents.size())
                        visit_ref(obs, n, visit_ref);
                }

                // Only executed one, graph output
                if (g->m_edges[root].size() == 0)
                {
                    last = obs;
                }
            };

            // Start recursive visitor
            visit(o, "INPUT_DECODER", visit);

            // Finally return output
            return last;
        };

        return ret;
    }
};

} // namespace builder

#endif // _BUILDER_H
