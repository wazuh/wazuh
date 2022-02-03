#ifndef _BUILDER_H
#define _BUILDER_H

#include "graph.hpp"
#include "json.hpp"
#include <algorithm>

#include "connectable.hpp"
#include "include_builders.hpp"

namespace builder
{
using namespace builder::internals::builders;
template <class C> class Builder
{
    using Event_t = json::Document;
    using Asset_t = json::Document;

    using Con_t = builder::internals::Connectable;
    using pCon_t = std::shared_ptr<Con_t>;

    using AssetBuilder_t = std::function<Con_t(Asset_t)>;

    using Node_t = graph::Node<Con_t>;
    using pNode_t = std::shared_ptr<Node_t>;

    using NodeMap_t = std::map<std::string, pNode_t>;

private:
    const C * m_catalog;

    pNode_t newNode(std::string name)
    {
        auto pCon = std::make_shared<Con_t>(name);
        return std::make_shared<Node_t>(pCon);
    }

    pNode_t connectGraph(std::string atype, NodeMap_t & nodes, NodeMap_t & filters)
    {
        auto input = newNode(atype + "_input");
        auto output = newNode(atype + "_output");

        std::for_each(nodes.begin(), nodes.end(),
                      [&](const auto & pair)
                      {
                          auto node = pair.second;

                          auto f = filters.find(node->name());
                          if (f != filters.end())
                          {
                              node->connect(f->second);
                              // If a node is filtered, other nodes will be connected to
                              // the filter instead of the node itself
                              nodes.at(node->name()) = f->second;
                          }

                          auto parents = node->m_value->parents();
                          if (parents.size() == 0)
                          {
                              input->connect(node);
                          }
                          for (auto & p : parents)
                          {
                              auto parentNode = nodes.find(p);
                              if (parentNode != nodes.end())
                              {
                                  parentNode->second->connect(node);
                              }
                          }
                      });

        graph::visitLeaves<Con_t>(input, [&](auto leaf) { leaf->connect(output); });
        return input;
    }

    NodeMap_t assetsBuilder(std::string atype, const json::Value * v, AssetBuilder_t make)
    {

        NodeMap_t nodes;
        if (v && v->IsArray())
        {
            for (auto & m : v->GetArray())
            {
                auto asset = m_catalog->getAsset(atype, m.GetString());
                auto conPtr = std::make_shared<Con_t>(make(asset));
                auto pNode = std::make_shared<Node_t>(conPtr);
                nodes.insert(std::pair<std::string, pNode_t>(pNode->name(), pNode));
            }
        }
        return nodes;
    };

    NodeMap_t filterNodesBuild(std::string atype, const json::Value * v, AssetBuilder_t make)
    {

        NodeMap_t nodes;
        if (v && v->IsArray())
        {
            for (auto & m : v->GetArray())
            {
                auto asset = m_catalog->getAsset(atype, m.GetString());
                auto conPtr = std::make_shared<Con_t>(make(asset));
                auto pNode = std::make_shared<Node_t>(conPtr);
                auto parents = conPtr->parents();
                std::for_each(parents.begin(), parents.end(),
                              [&](auto parentName)
                              { nodes.insert(std::pair<std::string, pNode_t>(parentName, pNode)); });
            }
        };
        return nodes;
    }

public:
    Builder() = default;
    Builder(const C & catalog) : m_catalog(& catalog){};

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
     * @param name
     * @return node_ptr execution graph of an environment
     */
    pNode_t build(std::string name)
    {
        json::Document environment = this->m_catalog->getAsset("environment", name);

        auto filterNodes = this->filterNodesBuild("filter", environment.get("/filters"), filterBuilder);
        auto decNodes = this->assetsBuilder("decoder", environment.get("/decoders"), decoderBuilder);
        auto ruleNodes = this->assetsBuilder("rule", environment.get("/rules"), ruleBuilder);
        auto outputNodes = this->assetsBuilder("output", environment.get("/outputs"), outputBuilder);

        auto gDecoders = this->connectGraph("decoder", decNodes, filterNodes);
        auto gRules = this->connectGraph("rule", ruleNodes, filterNodes);
        auto gOutputs = this->connectGraph("output", outputNodes, filterNodes);

        graph::visitLeaves<Con_t>(gDecoders,
                                  [&](auto leaf)
                                  {
                                      leaf->connect(gOutputs);
                                      leaf->connect(gRules);
                                  });

        graph::visitLeaves<Con_t>(gRules, [&](auto leaf) { leaf->connect(gOutputs); });

        return gDecoders;
    }

    rxcpp::subjects::subject<Event_t> operator()(const std::string & environment)
    {
        pNode_t root = this->build(environment);
        return root->m_value->subject();
    }
};

} // namespace builder

#endif // _BUILDER_H
