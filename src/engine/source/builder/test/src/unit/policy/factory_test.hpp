#ifndef _BUILDER_TEST_POLICY_FACTORY_TEST_HPP
#define _BUILDER_TEST_POLICY_FACTORY_TEST_HPP

#include "policy/factory.hpp"
#include "syntax.hpp"

using namespace builder::policy;

namespace buildgraphtest
{

inline base::Expression assetExpr(const base::Name& name)
{
    return base::And::create(name, {base::Term<int>::create("fake", 0)});
}

class AssetData
{
public:
    factory::BuiltAssets builtAssets;

    AssetData() { builtAssets = factory::BuiltAssets {}; }

    template<typename... Parents>
    AssetData& operator()(cm::store::ResourceType type, const base::Name& name, Parents&&... parents)
    {
        auto nameCpy = name;

        // Filter out "Input" parents as they should be implicit (empty parents list)
        // buildSubgraph will automatically connect assets with empty parents to the subgraph root
        std::vector<base::Name> parentVec;
        for (auto& parent : {parents...})
        {
            std::string parentStr(parent);
            // Skip parents that end with "Input" - buildSubgraph handles these automatically
            if (parentStr.find("Input") == std::string::npos)
            {
                parentVec.push_back(base::Name(parent));
            }
        }

        auto asset = Asset {std::move(nameCpy), assetExpr(name), std::move(parentVec)};

        if (builtAssets.find(type) == builtAssets.end())
        {
            builtAssets.emplace(type, factory::SubgraphData {});
        }
        builtAssets.at(type).orderedAssets.push_back(name);
        builtAssets.at(type).assets.emplace(name, asset);

        return *this;
    };
};
} // namespace buildgraphtest

#endif // _BUILDER_TEST_POLICY_FACTORY_TEST_HPP
