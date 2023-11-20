#ifndef _BUILDER_TEST_POLICY_FACTORY_TEST_HPP
#define _BUILDER_TEST_POLICY_FACTORY_TEST_HPP

#include "policy/factory.hpp"
#include "syntax.hpp"

using namespace builder::policy;

namespace buildgraphtest
{

class AssetData
{
public:
    factory::PolicyData policyData;
    factory::BuiltAssets builtAssets;
    factory::PolicyGraph policyGraph;

    AssetData()
    {
        policyData = factory::PolicyData({.name = "policy/testname", .hash = "hash"});
        builtAssets = factory::BuiltAssets {};
        policyGraph = factory::PolicyGraph {};
    }

    template<typename... Parents>
    AssetData& operator()(factory::PolicyData::AssetType type, const base::Name& name, Parents&&... parents)
    {
        auto nameCpy = name;
        auto asset = Asset {std::move(nameCpy), base::And::create("fakeAssetExpr", {}), {parents...}};
        if (builtAssets.find(type) == builtAssets.end())
        {
            builtAssets.emplace(type, std::unordered_map<base::Name, Asset> {});
        }
        builtAssets.at(type).emplace(name, std::move(asset));
        policyData.add(type, "fakeNs", name);

        if (type != factory::PolicyData::AssetType::FILTER)
        {
            if (policyGraph.subgraphs.find(type) == policyGraph.subgraphs.end())
            {
                auto rootName = base::Name(factory::PolicyData::assetTypeStr(type)) + "Input";
                Graph<base::Name, Asset> subgraph {rootName, Asset {}};
                policyGraph.subgraphs.emplace(type, std::move(subgraph));
            }

            policyGraph.subgraphs.at(type).addNode(name, asset);
            (policyGraph.subgraphs.at(type).addEdge(base::Name(parents), name), ...);
        }
        else
        {
            for (auto& parent : {parents...})
            {
                factory::PolicyData::AssetType parentType;
                base::Name parentName(parent);
                if (builder::syntax::name::isDecoder(parentName))
                {
                    parentType = factory::PolicyData::AssetType::DECODER;
                }
                else if (builder::syntax::name::isRule(parentName))
                {
                    parentType = factory::PolicyData::AssetType::RULE;
                }
                else if (builder::syntax::name::isOutput(parentName))
                {
                    parentType = factory::PolicyData::AssetType::OUTPUT;
                }

                policyGraph.subgraphs.at(parentType).injectNode(name, asset, parentName);
            }
        }

        return *this;
    };
};
} // namespace buildgraphtest

#endif // _BUILDER_TEST_POLICY_FACTORY_TEST_HPP
