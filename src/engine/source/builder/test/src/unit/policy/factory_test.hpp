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

// Helper function to map ResourceType to AssetPipelineStage
inline factory::AssetPipelineStage resourceTypeToStage(cm::store::ResourceType type)
{
    switch (type)
    {
        case cm::store::ResourceType::DECODER: return factory::AssetPipelineStage::DECODERS_TREE;
        case cm::store::ResourceType::OUTPUT: return factory::AssetPipelineStage::OUTPUTS_TREE;
        case cm::store::ResourceType::FILTER:
            // Default to POST_FILTERS_TREE for filters (can be refined if needed)
            return factory::AssetPipelineStage::POST_FILTERS_TREE;
        default: throw std::runtime_error("Unsupported ResourceType for AssetPipelineStage conversion");
    }
}

class AssetData
{
public:
    factory::BuiltAssets builtAssets;

    AssetData() { builtAssets = factory::BuiltAssets {}; }

    template<typename... Parents>
    AssetData& operator()(cm::store::ResourceType type, const base::Name& name, Parents&&... parents)
    {
        // Filters are completely ignored in buildGraph tests - they're internal to assets
        // Only standalone filters with UUIDs in the policy are injected into PRE/POST_FILTERS_TREE
        if (type == cm::store::ResourceType::FILTER)
        {
            return *this;
        }

        auto nameCpy = name;
        auto stage = resourceTypeToStage(type);

        // Convert old-style "decoder/Input" parent names to new stage-based names like "DecodersTree/Input"
        std::vector<base::Name> parentVec;
        for (auto& parent : {parents...})
        {
            std::string parentStr(parent);

            // Check if parent ends with "/Input" - these need to be converted to stage names
            if (parentStr.find("/Input") != std::string::npos)
            {
                // Extract the prefix (decoder, output, filter)
                std::string prefix = parentStr.substr(0, parentStr.find("/"));

                // Map old prefixes to new stage names
                std::string newPrefix;
                if (prefix == "decoder")
                {
                    newPrefix = "DecodersTree";
                }
                else if (prefix == "output")
                {
                    newPrefix = "OutputsTree";
                }
                else if (prefix == "filter")
                {
                    // Use POST_FILTERS_TREE by default for filters
                    newPrefix = "PostFiltersTree";
                }
                else
                {
                    // Unknown prefix, keep as-is
                    newPrefix = prefix;
                }

                parentVec.push_back(base::Name(newPrefix + "/Input"));
            }
            else
            {
                // Regular parent (not an Input node)
                parentVec.push_back(base::Name(parent));
            }
        }

        auto asset = Asset {std::move(nameCpy), assetExpr(name), std::move(parentVec)};

        if (builtAssets.find(stage) == builtAssets.end())
        {
            builtAssets.emplace(stage, factory::SubgraphData {});
        }
        builtAssets.at(stage).orderedAssets.push_back(name);
        builtAssets.at(stage).assets.emplace(name, asset);

        return *this;
    };
};

// Helper function to convert ResourceType to AssetPipelineStage for graph access
inline factory::AssetPipelineStage toStage(cm::store::ResourceType type)
{
    return resourceTypeToStage(type);
}

} // namespace buildgraphtest

#endif // _BUILDER_TEST_POLICY_FACTORY_TEST_HPP
