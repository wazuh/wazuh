#ifndef _BUILDER_H
#define _BUILDER_H

#include "graph/graph.hpp"
#include "json/json.hpp"
#include <algorithm>

#include "connectable.hpp"
#include "include_builders.hpp"

namespace builder
{

template <class C> class Builder
{

    using event_t = json::Document;
    using asset_t = json::Document;
    using connectable_t = builder::internals::Connectable;
    using connectable_ptr = std::shared_ptr<connectable_t>;
    using node_t = graph::Node<connectable_t>;
    using node_ptr = std::shared_ptr<node_t>;
    using asset_builder_t = std::function<connectable_t(asset_t)>;

private:
    C m_catalog;

    node_ptr assets_builder(std::string atype, const json::Value * v, asset_builder_t make)
    {
        // check v is an array
        if (!v->IsArray())
        {
            throw std::invalid_argument("asset_builder did not get an array of assets to build!");
        }

        std::map<std::string, node_ptr> nodes;

        connectable_ptr con = std::make_shared<connectable_t>(atype + "_root");
        node_ptr root(std::make_shared<node_t>(node_t(con)));

        std::transform(v->Begin(), v->End(), std::inserter(nodes, nodes.begin()),
                       [=](const auto & m)
                       {
                           auto asset = m_catalog.getAsset(atype, m.GetString());
                           auto con_ptr = std::make_shared<connectable_t>(make(asset));
                           auto pNode = std::make_shared<node_t>(con_ptr);
                           return std::make_pair(pNode->name(), pNode);
                       });

        // connect all nodes
        std::for_each(nodes.begin(), nodes.end(),
                      [&](const auto & pair)
                      {
                          auto parents = pair.second->m_value->parents();
                          if (parents.empty())
                              root->connect(pair.second);
                          else
                              std::for_each(parents.begin(), parents.end(),
                                            [&](const auto & p)
                                            {
                                                auto parent = nodes.find(p);
                                                if (parent != nodes.end())
                                                {
                                                    parent->second->connect(pair.second);
                                                }
                                            });
                      });

        return root;
    };

public:
    Builder(C catalog) : m_catalog(catalog){};

    node_ptr build(std::string name)
    {
        json::Document environment = this->m_catalog.getAsset("environment", name);

        std::vector<node_ptr> nodes;

        connectable_ptr con = std::make_shared<connectable_t>("environment_root");
        node_ptr root(std::make_shared<node_t>(node_t(con)));

        std::transform(environment.begin(), environment.end(), std::back_inserter(nodes),
                       [&](const auto & m)
                       {
                           std::string key;
                           key = m.name.GetString();
                           if (key == "decoders")
                               return this->assets_builder("decoder", environment.get(std::string("/") + key),
                                                           builder::internals::builders::decoderBuilder);
                           else if (key == "rules")
                               return this->assets_builder("rule", environment.get(std::string("/") + key),
                                                           builder::internals::builders::ruleBuilder);
                           else if (key == "filters")
                               return this->assets_builder("filter", environment.get(std::string("/") + key),
                                                           builder::internals::builders::filterBuilder);
                           else if (key == "outputs")
                               return this->assets_builder("output", environment.get(std::string("/") + key),
                                                           builder::internals::builders::outputBuilder);
                           else
                               throw std::runtime_error("Environment " + name + " has an unknown member: " + key);
                       });

        return root;
    }

    template <class E> std::function<bool(E)> filter(json::Document filter)
    {
    }
};

} // namespace builder

#endif // _BUILDER_H
