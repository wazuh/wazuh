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

#include "rxcpp/rx.hpp"

#include "connectable.hpp"
#include "graph.hpp"
#include "include_builders.hpp"
#include "json.hpp"

namespace builder
{

/**
 * @brief The builder class is the responsible to transform and environment
 * definition into a graph of RXCPP operations.
 *
 * @tparam Catalog type of the catalog for dependency injection.
 */
template <class Catalog> class Builder
{
    // The type of the event which will flow through the stream
    using Event_t = json::Document;
    // The type of the observable which will compose the processing graph
    using Obs_t = rxcpp::observable<Event_t>;
    // The type of the connectables whisch will help us connect the assets ina graph
    using Con_t = builder::internals::Connectable<Obs_t>;
    // The type of a connectable operation
    using Op_t = std::function<Obs_t(const Obs_t &)>;
    // The signature of a maker function which will build an asset into a`
    // connectable.
    using Maker_t = std::function<Con_t(const json::Document &)>;
    // The signature of a builder function which will build an operation from
    // a piece of an asset description.
    using Builder_t = std::function<Op_t(const json::Value &)>;
    // The type of the graph which will connect all the connectables into a
    // graph
    using Graph_t = graph::Graph<Con_t>;

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
    void connectGraph(Graph_t & g, Con_t in, Con_t out)
    {

        g.addNode(in);

        g.visit(
            [&](auto edges)
            {
                Con_t node = edges.first;

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
                    g.addEdge(Con_t(p), node);
                }
            });

        g.addNode(out);

        g.leaves(
            [&](Con_t leaf)
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
    void assetBuilder(Graph_t & g, std::string atype, const json::Value * v, Maker_t make)
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
                Con_t filter = edges.first;
                for (auto & p : filter.m_parents)
                {
                    g.addNode(filter);
                    g.injectEdge(Con_t(p), filter);
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

        this->assetBuilder(g, "decoder", asset.get(".decoders"), internals::builders::buildDecoder);
        this->connectGraph(g, Con_t("DECODERS_INPUT"), Con_t("DECODERS_OUTPUT"));

        g.addNode(Con_t("RULES_INPUT"));
        g.addEdge(Con_t("DECODERS_OUTPUT"), Con_t("RULES_INPUT"));

        this->assetBuilder(g, "rule", asset.get(".rules"), internals::builders::buildRule);
        this->connectGraph(g, Con_t("RULES_INPUT"), Con_t("RULES_OUTPUT"));

        g.addNode(Con_t("OUTPUTS_INPUT"));
        g.addEdge(Con_t("DECODERS_OUTPUT"), Con_t("OUTPUTS_INPUT"));
        g.addEdge(Con_t("RULES_OUTPUT"), Con_t("OUTPUTS_INPUT"));

        this->assetBuilder(g, "output", asset.get(".outputs"), internals::builders::buildOutput);
        this->connectGraph(g, Con_t("OUTPUTS_INPUT"), Con_t("OUTPUTS_OUTPUT"));

        this->assetBuilder(filters, "filter", asset.get(".filters"), internals::builders::buildFilter);
        this->filterGraph(g, filters);

        return g;
    }

    Op_t operator()(const std::string & name)
    {

        auto g = this->build(name);
        auto edges = g.get();
        return [=](Obs_t o) -> Obs_t
        {
            Obs_t last;
            // This algorithm builds the RXCPP based graph of operations 
            // every time the closure is called. The whole graph is captured
            // by value by the parent closure.
            auto visit = [&](Obs_t source, Con_t root, auto & visit_ref) -> void
            {
  
                auto itr = edges.find(root);
                if (itr == edges.end())
                {
                    throw std::invalid_argument("Value root is not in the graph");
                }

                // Visit node
                Con_t node = itr->first;
                if (node.m_inputs.size() == 0)
                {
                    node.addInput(source);
                }
                Obs_t obs = node.connect();

                // Add obs as an input to the childs
                for (Con_t n : itr->second)
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

            visit(o, Con_t("DECODERS_INPUT"), visit);
            return last;
        };
    }
};

} // namespace builder

#endif // _BUILDER_H
