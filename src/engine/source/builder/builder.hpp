#ifndef _BUILDER_H
#define _BUILDER_H

#include <algorithm>
#include "graph/graph.hpp"
#include "json/json.hpp"
#include "registry.hpp"

#include "connectable.hpp"
#include "asset_builder.hpp"
#include "templcheck/templcheck.hpp"

namespace builder
{

template <class C> class Builder
{
    // static_assert(utils::has_method<C, utils::existent_caller , json::Document(const std::string, const
    // std::string)>::value, "catalog of type C must have a getAsset method"); static_assert(utils::has_method<C,
    // utils::existent_caller, std::vector<std::string>(const std::string)>::value, "catalog of type C must have a
    // getAssetList method");

    using event_t = json::Document;
    using connectable_t = Connectable<event_t>;
    using connectable_ptr = std::shared_ptr<connectable_t>;
    using node_t = graph::Node<connectable_t>;
    using node_ptr = std::shared_ptr<node_t>;

    using builder_t = builder::internals::AssetBuilder<connectable_ptr(json::Document)>;

private:
    C m_catalog;

    node_ptr assets_builder(std::string atype, const json::Value *v)
    {
        // check v is an array
        if(! v->IsArray()) {
          throw std::invalid_argument("asset_builder did not get an array of assets to build!");
        }
        std::map<std::string, node_ptr> nodes;

        connectable_ptr con = std::make_shared<connectable_t>(connectable_t(atype+"_root"));
        node_ptr root( std::make_shared<node_t>(node_t(con)));

        std::transform(v->Begin(), v->End(), std::inserter(nodes, nodes.end()), [=](const auto & m) {
            auto asset = m_catalog.getAsset(atype, m.GetString());
            auto make = builder::internals::Registry::instance().builder<builder_t>(atype);
            auto pNode = std::make_shared<node_t>(node_t(make(asset)));
            return std::make_pair(pNode->name(), pNode );
        });

        // connect all nodes
        std::for_each(nodes.begin(), nodes.end(), [&](const auto &pair) {
            auto parents = pair.second->m_value->parents();
            std::for_each(parents.begin(), parents.end(), [&](const auto & p) {
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

        connectable_ptr con = std::make_shared<connectable_t>(connectable_t("environment_root"));
        node_ptr root( std::make_shared<node_t>(node_t(con)));

        std::transform(environment.begin(), environment.end(), nodes.begin(), [&](const auto & m) {
            return this->assets_builder(m.name.GetString(), environment.get('/'+m.name.GetString()));
        });

        return root;
    }

    template <class E> std::function<bool(E)> filter(json::Document filter)
    {
    }
};

} // namespace builder

#endif // _BUILDER_H