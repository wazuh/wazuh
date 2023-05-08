#ifndef _BUILDER_POLICY_HPP
#define _BUILDER_POLICY_HPP

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include <json/json.hpp>
#include <store/istore.hpp>

#include "asset.hpp"
#include "expression.hpp"
#include "graph.hpp"

#include "registry.hpp"

namespace builder
{

constexpr const char* const DECODERS = "decoders";
constexpr const char* const RULES = "rules";
constexpr const char* const OUTPUTS = "outputs";
constexpr const char* const FILTERS = "filters";
constexpr const char* const INTEGRATIONS = "integrations";

/**
 * @brief Get the Asset Type object from the string
 *
 * @param name
 * @return Asset::Type
 * @throws std::runtime_error if the name is not supported
 */
Asset::Type getAssetType(const std::string& name);

/**
 * @brief Intermediate representation of the policy.
 *
 * The policy contains the following information:
 * - The name of the policy.
 * - All assests (decoders, rules, outputs, filters) of the policy stored in a map.
 * - Each asset subgraph (decoders, rules, outputs) stored in a map of graphs.
 */
class Policy
{
private:
    std::string m_name;
    std::unordered_map<std::string, std::shared_ptr<Asset>> m_assets;
    std::vector<std::tuple<std::string, Graph<std::string, std::shared_ptr<Asset>>>> m_graphs;

    /**
     * @brief Build specific subgraph from the provided map of jsons.
     *
     * Build each asset and add it to the graph.
     *
     * @param assetsDefinitons Map of jsons for each asset.
     * @param graphName Name of the subgraph.
     * @param type Type of the assets in the subgraph.
     * @throws std::runtime_error if the asset cannot be built.
     */
    void buildGraph(const std::vector<std::shared_ptr<Asset>>& assets, const std::string& graphName);

    /**
     * @brief Inject Filters into specific subgraph.
     *
     * If a filter references an asset, it is added as child of the asset, and the asset's
     * children are added as children of the filter.
     * Otherwise nohting is done.
     *
     * @param graphName Name of the subgraph.
     */
    void addFilters(const std::string& graphName);

    void saveGraph(const std::vector<std::shared_ptr<Asset>>& assets, const std::string& name)
    {
        // Add input asset
        m_graphs.push_back(std::make_pair<std::string, Graph<std::string, std::shared_ptr<Asset>>>(
            std::string {name},
            {std::string(name + "Input"), std::make_shared<Asset>(name + "Input", getAssetType(name))}));

        // Save assets
        std::transform(assets.begin(),
                       assets.end(),
                       std::inserter(m_assets, m_assets.begin()),
                       [&](auto& asset) { return std::make_pair(asset->m_name, asset); });

        buildGraph(assets, name);

        // Add filters
        addFilters(name);

        // Check integrity
        auto graphPos = std::find_if(
            m_graphs.begin(), m_graphs.end(), [&name](const auto& graph) { return std::get<0>(graph) == name; });
        for (auto& [parent, children] : std::get<1>(*graphPos).m_edges)
        {
            if (!std::get<1>(*graphPos).hasNode(parent))
            {
                std::string childrenNames;
                for (auto& child : children)
                {
                    childrenNames += child + " ";
                }
                throw std::runtime_error(fmt::format("Error building policy \"{}\". Asset \"{}\" requested for "
                                                     "parent \"{}\" which could not be found",
                                                     name,
                                                     parent,
                                                     childrenNames));
            }
            for (auto& child : children)
            {
                if (!std::get<1>(*graphPos).hasNode(child))
                {
                    throw std::runtime_error(fmt::format("Asset \"{}\" could not be found", child));
                }
            }
        }
    }

public:
    Policy() = default;

    /**
     * @brief Construct a new Policy object
     *
     * @param jsonDefinition Json definition of the policy.
     * @param storeRead Store read interface.
     * @param registry Registry interface.
     * @throws std::runtime_error if the policy cannot be built.
     */
    Policy(const json::Json& jsonDefinition,
                std::shared_ptr<const store::IStoreRead> storeRead,
                std::shared_ptr<internals::Registry<internals::Builder>> registry)

    {
        // Get name
        auto nameOpt = jsonDefinition.getString("/name");
        if (!nameOpt)
        {
            if (jsonDefinition.exists("/name"))
            {
                throw std::runtime_error("Policy /name is not a string");
            }
            else
            {
                throw std::runtime_error("Policy /name is not defined");
            }
        }
        m_name = nameOpt.value();

        // Get all asset lists
        auto assets = getManifestAssets(jsonDefinition, storeRead, registry);

        // Merge all assets of the integrations if any
        std::string integrationsPath {INTEGRATIONS};
        integrationsPath.insert(integrationsPath.begin(), 1, '/');
        if (jsonDefinition.exists(integrationsPath))
        {
            auto integrations = jsonDefinition.getArray(integrationsPath);
            if (!integrations)
            {
                if (jsonDefinition.exists(integrationsPath))
                {
                    throw std::runtime_error("Field /integrations is not an array");
                }
                else
                {
                    throw std::runtime_error("Field /integrations is not defined");
                }
            }

            for (auto& integration : integrations.value())
            {
                if (!integration.isString())
                {
                    throw std::runtime_error("Integration name is not a string");
                }

                auto integrationDef = storeRead->get(integration.getString().value());
                if (std::holds_alternative<base::Error>(integrationDef))
                {
                    throw std::runtime_error(fmt::format("Error loading {}: ",
                                                         integration.getString().value(),
                                                         std::get<base::Error>(integrationDef).message));
                }

                auto integrationAssets = getManifestAssets(std::get<json::Json>(integrationDef), storeRead, registry);
                for (auto& [key, value] : integrationAssets)
                {
                    assets[key].insert(assets[key].end(), value.begin(), value.end());
                }
            }
        }

        // Filters are not graphs, its treated as a special case.
        // We just add them to the asset map and then inject them into each
        // graph.
        if (assets.count(FILTERS) > 0)
        {
            std::transform(assets[FILTERS].begin(),
                           assets[FILTERS].end(),
                           std::inserter(m_assets, m_assets.begin()),
                           [&](auto& asset) { return std::make_pair(asset->m_name, asset); });
            assets.erase(FILTERS);
        }

        // Build graphs in order decoders->rules->outputs
        // We need at least one graph to build the policy.
        if (assets.empty())
        {
            throw std::runtime_error("Policy needs at least one asset (decoder, rule or output) to build a graph");
        }

        if (assets.count(DECODERS) > 0)
        {
            saveGraph(assets[DECODERS], DECODERS);
            assets.erase(DECODERS);
        }

        if (assets.count(RULES) > 0)
        {
            saveGraph(assets[RULES], RULES);
            assets.erase(RULES);
        }

        if (assets.count(OUTPUTS) > 0)
        {
            saveGraph(assets[OUTPUTS], OUTPUTS);
            assets.erase(OUTPUTS);
        }
    }

    /**
     * @brief Get the name of the policy.
     *
     * @return const std::string& Name of the policy.
     */
    std::string name() const;

    /**
     * @brief Get the map of assets.
     *
     * @return std::unordered_map<std::string, std::shared_ptr<Asset>>&
     */
    std::unordered_map<std::string, std::shared_ptr<Asset>>& assets();

    /**
     * @brief Get the map of assets.
     *
     * @return std::unordered_map<std::string, std::shared_ptr<Asset>>&
     */
    const std::unordered_map<std::string, std::shared_ptr<Asset>>& assets() const;

    /**
     * @brief Get the Graphivz Str object
     *
     * @return std::string
     */
    std::string getGraphivzStr();

    /**
     * @brief Build and Get the Expression from the policy.
     *
     * @return base::Expression Root expression of the policy.
     * @throws std::runtime_error If the expression cannot be built.
     */
    base::Expression getExpression() const;

    static std::unordered_map<std::string, std::vector<std::shared_ptr<Asset>>>
    getManifestAssets(const json::Json& jsonDefinition,
                      std::shared_ptr<const store::IStoreRead> storeRead,
                      std::shared_ptr<internals::Registry<internals::Builder>> registry);
};

} // namespace builder

#endif // _BUILDER_POLICY_HPP
