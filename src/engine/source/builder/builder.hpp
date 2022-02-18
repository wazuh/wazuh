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

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include "builderTypes.hpp"
#include "graph.hpp"
#include "registry.hpp"

namespace builder
{
// The type of the graph which will connect all the connectables into a
// graph
using Graph_t = graph::Graph<internals::types::ConnectableT>;

/**
 * @brief The builder class is the responsible to transform and environment
 * definition into a graph of RXCPP operations.
 *
 * @tparam Catalog type of the catalog for dependency injection.
 */
template <class Catalog> class Builder
{
private:
    const Catalog & m_catalog;

    /**
     * @brief Connects the provided graph single nodes into a connected
     * graph defined by its parents. Nodes with no parent will be connected to
     * the input node, and nodes with no childs will be connected to the output
     * node
     *
     * @param g graph
     * @param in input node
     * @param out output node
     */
    void connectGraph(Graph_t & g, internals::types::ConnectableT in, internals::types::ConnectableT out)
    {

        g.addNode(in);

        g.visit(
            [&](auto edges)
            {
                internals::types::ConnectableT node = edges.first;

                // TODO: do not relay on special names with input and output in the name
                if (node == in || node == out || node.m_name.find("INPUT") != std::string::npos ||
                    node.m_name.find("OUTPUT") != std::string::npos)
                    return;

                if (node.m_parents.size() == 0 && edges.second.size() == 0)
                {
                    g.addEdge(in, node);
                }

                for (auto p : node.m_parents)
                {
                    g.addEdge(internals::types::ConnectableT(p), node);
                }
            });

        g.addNode(out);

        g.leaves(
            [&](internals::types::ConnectableT leaf)
            {
                if (leaf != out)
                {
                    g.addEdge(leaf, out);
                }
            });
    }

    /**
     * @brief Build a a list of asset and add them as connectable value into
     * the given graph. It will ask the catalog the definition of each asset
     * in the list to build them.
     *
     * @param g the graph to which the value must be added
     * @param atype the type of the asset
     * @param v the asset list into a json::Value array
     * @param make the maker function which will convert a single asset into
     * a connectable.
     */
    void assetBuilder(Graph_t & g, std::string atype, const json::Value * v, internals::types::AssetBuilder make)
    {

        if (v && v->IsArray())
        {
            for (auto & m : v->GetArray())
            {
                json::Document asset = m_catalog.getAsset(atype, m.GetString());
                g.addNode(make(asset));
            }
        }
    }

    /**
     * @brief Inject filters into its positions in the graph.
     *
     * @param g graph to filter
     * @param filters graph of filters
     */
    void filterGraph(Graph_t & g, Graph_t & filters)
    {
        filters.visit(
            [&](auto edges)
            {
                internals::types::ConnectableT filter = edges.first;
                for (auto & p : filter.m_parents)
                {
                    g.addNode(filter);
                    g.injectEdge(internals::types::ConnectableT(p), filter);
                }
            });
    }

public:
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
    Graph_t build(const std::string & name)
    {
        Graph_t g;
        Graph_t filters;
        json::Document asset = m_catalog.getAsset("environment", name);

        this->assetBuilder(g, "decoder", asset.get(".decoders"),
                           std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("decoder")));
        this->connectGraph(g, internals::types::ConnectableT("DECODERS_INPUT"),
                           internals::types::ConnectableT("DECODERS_OUTPUT"));

        g.addNode(internals::types::ConnectableT("RULES_INPUT"));
        g.addEdge(internals::types::ConnectableT("DECODERS_OUTPUT"), internals::types::ConnectableT("RULES_INPUT"));

        this->assetBuilder(g, "rule", asset.get(".rules"),
                           std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("rule")));
        this->connectGraph(g, internals::types::ConnectableT("RULES_INPUT"),
                           internals::types::ConnectableT("RULES_OUTPUT"));

        g.addNode(internals::types::ConnectableT("OUTPUTS_INPUT"));
        g.addEdge(internals::types::ConnectableT("DECODERS_OUTPUT"), internals::types::ConnectableT("OUTPUTS_INPUT"));
        g.addEdge(internals::types::ConnectableT("RULES_OUTPUT"), internals::types::ConnectableT("OUTPUTS_INPUT"));

        this->assetBuilder(g, "output", asset.get(".outputs"),
                           std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("output")));
        this->connectGraph(g, internals::types::ConnectableT("OUTPUTS_INPUT"),
                           internals::types::ConnectableT("OUTPUTS_OUTPUT"));

        this->assetBuilder(filters, "filter", asset.get(".filters"),
                           std::get<internals::types::AssetBuilder>(internals::Registry::getBuilder("filter")));
        this->filterGraph(g, filters);

        std::cerr << g.print().str();
        return g;
    }

    internals::types::Lifter operator()(const std::string & name)
    {

        auto g = this->build(name);
        auto edges = g.get();
        return [=](internals::types::Observable o) -> internals::types::Observable
        {
            internals::types::Observable last;
            // This algorithm builds the RXCPP based graph of operations
            // every time the closure is called. The whole graph is captured
            // by value by the parent closure.
            auto visit = [&](internals::types::Observable source, internals::types::ConnectableT root,
                             auto & visit_ref) -> void
            {
                auto itr = edges.find(root);
                if (itr == edges.end())
                {
                    throw std::invalid_argument("Value root is not in the graph");
                }

                // Visit node
                internals::types::ConnectableT node = itr->first;
                if (node.m_inputs.size() == 0)
                {
                    node.addInput(source);
                }
                internals::types::Observable obs = node.connect();

                // Add obs as an input to the childs
                for (internals::types::ConnectableT n : itr->second)
                {
                    n.addInput(obs);
                }

                // Visit childs
                for (auto & n : itr->second)
                {
                    visit_ref(obs, n, visit_ref);
                }

                if (itr->second.size() == 0)
                {
                    last = obs;
                }
            };

            visit(o, internals::types::ConnectableT("DECODERS_INPUT"), visit);
            return last;
        };
    }
};

} // namespace builder

#endif // _BUILDER_H
