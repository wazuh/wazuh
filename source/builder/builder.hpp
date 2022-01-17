#include "graph/graph.hpp"
#include "json/json.hpp"
#include "registry.hpp"

#include "connectable.hpp"
#include "component_builder.hpp"
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
    using node_t = graph::Node<connectable_t>;

    using builder_t = builder::internals::ComponentBuilder<node_t>(json::Value);

private:
    C m_catalog;

    node_t assets_builder(std::string atype, json::Value v)
    {
        // check v is an array
        if(! v.IsArray()) {
          throw std::invalid_argument("asset_builder did not get an array of assets to build!");
        }
        std::map<std::string, node_t> nodes;

        std::transform(v.Begin(), v.End(), std::inserter(nodes, nodes.end()), [=](auto & m) {
            auto asset = m_catalog.getAsset(atype, m.name.GetString());
            auto make = builder::internals::Registry::instance().builder<builder_t>(atype);
            auto con = std::make_shared<connectable_t>(make(asset));
            return std::make_pair(con->name(), node_t(con));
        });

        // connect all nodes
        std::for_each(nodes.begin(), nodes.end(), [&](auto & child) {
            auto parents = child.parents();
            std::for_each(parents.begin(), parents.end(), [&](auto & p) {
                auto parent = nodes.find(p);
                if (parent != nodes.end())
                {
                    parent.connect(child);
                }
            });
        });

        return nodes[0];
    };

public:
    Builder(C catalog) : m_catalog(catalog){};

    node_t build(std::string name)
    {
        auto environment = this->m_catalog.getAsset("environment", name);

        std::vector<node_t> nodes;

        std::transform(environment.begin(), environment.end(), nodes.begin(), [&](auto & m) {
            return this->asset_builder(m->name.GetString(), m);
        });
    }

    template <class E> std::function<bool(E)> filter(json::Document filter)
    {
    }
};

} // namespace builder
