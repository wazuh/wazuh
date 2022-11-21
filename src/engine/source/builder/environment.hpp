#ifndef _ENVIRONMENT_H
#define _ENVIRONMENT_H

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

/**
 * @brief Get the Asset Type object from the string
 *
 * @param name
 * @return Asset::Type
 * @throws std::runtime_error if the name is not supported
 */
Asset::Type getAssetType(const std::string& name);

/**
 * @brief Intermediate representation of the environment.
 *
 * The environment contains the following information:
 * - The name of the environment.
 * - All assests (decoders, rules, outputs, filters) of the environment stored in a map.
 * - Each asset subgraph (decoders, rules, outputs) stored in a map of graphs.
 */
class Environment
{
private:
    std::string m_name;
    std::unordered_map<std::string, std::shared_ptr<Asset>> m_assets;
    std::vector<std::tuple<std::string, Graph<std::string, std::shared_ptr<Asset>>>>
        m_graphs;

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
    void buildGraph(const std::unordered_map<std::string, json::Json>& assetsDefinitons,
                    const std::string& graphName,
                    Asset::Type type,
                    std::shared_ptr<internals::Registry> registry);

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

public:
    Environment() = default;

    // TODO: Remove injected catalog dependencies ?
    /**
     * @brief Construct a new Environment object
     *
     * @tparam T Injected catalog type.
     * @param name Name of the environment.
     * @param jsonDefinition Json definition of the environment.
     * @param catalog Injected catalog.
     * @throws std::runtime_error if the environment cannot be built.
     */
    Environment(const json::Json& jsonDefinition,
                std::shared_ptr<const store::IStoreRead> storeRead,
                std::shared_ptr<internals::Registry> registry)

    {
        auto envObj = jsonDefinition.getObject().value();

        // Get name
        auto nameIt =
            std::find_if(envObj.begin(),
                         envObj.end(),
                         [](const auto& tuple) { return std::get<0>(tuple) == "name"; });
        if (nameIt == envObj.end())
        {
            throw std::runtime_error("Environment name is missing");
        }
        auto nameOpt = std::get<1>(*nameIt).getString();
        if (!nameOpt)
        {
            throw std::runtime_error("Environment name is not a string");
        }
        m_name = nameOpt.value();

        envObj.erase(nameIt);

        // Filters are not graphs, its treated as a special case.
        // We just add them to the asset map and then inject them into each
        // graph.
        auto filtersPos =
            std::find_if(envObj.begin(),
                         envObj.end(),
                         [](auto& tuple) { return std::get<0>(tuple) == FILTERS; });

        if (envObj.end() != filtersPos)
        {
            auto filtersList = std::get<1>(*filtersPos).getArray().value();
            std::transform(
                filtersList.begin(),
                filtersList.end(),
                std::inserter(m_assets, m_assets.begin()),
                [&](auto& json)
                {
                    const auto assetType = Asset::Type::FILTER;
                    const auto assetName = json.getString().value();
                    auto assetJson = storeRead->get(base::Name {assetName});
                    if (std::holds_alternative<base::Error>(assetJson))
                    {
                        throw std::runtime_error(
                            fmt::format("Filter \"{}\" could not be obtained: {}",
                                        assetName,
                                        std::get<base::Error>(assetJson).message));
                    }
                    return std::make_pair(
                        assetName,
                        std::make_shared<Asset>(
                            std::get<json::Json>(assetJson), assetType, registry));
                });
            envObj.erase(filtersPos);
        }

        // Build graphs
        // We need at least one graph to build the environment.
        if (envObj.empty())
        {
            throw std::runtime_error(
                fmt::format("Environment \"{}\" needs at least one asset (decoder, rule "
                            "or output) to build a graph",
                            m_name));
        }
        for (auto& [name, json] : envObj)
        {
            auto assetNames = json.getArray().value();

            m_graphs.push_back(
                std::make_pair<std::string, Graph<std::string, std::shared_ptr<Asset>>>(
                    std::string {name},
                    {std::string(name + "Input"),
                     std::make_shared<Asset>(name + "Input", getAssetType(name))}));

            // Obtain assets jsons
            auto assetsDefinitions = std::unordered_map<std::string, json::Json>();
            std::transform(
                assetNames.begin(),
                assetNames.end(),
                std::inserter(assetsDefinitions, assetsDefinitions.begin()),
                [&](auto& json)
                {
                    auto assetType = getAssetType(name);
                    auto assetName = json.getString().value();
                    auto assetJson = storeRead->get(base::Name {assetName});
                    if (std::holds_alternative<base::Error>(assetJson))
                    {
                        throw std::runtime_error(
                            fmt::format("Asset \"{}\" cannot be obtained: {}",
                                        assetName,
                                        std::get<base::Error>(assetJson).message));
                    }
                    return std::make_pair(assetName, std::get<json::Json>(assetJson));
                });

            // Build graph
            buildGraph(assetsDefinitions, name, getAssetType(name), registry);

            // Add filters
            addFilters(name);

            // Check integrity
            auto graphPos = std::find_if(m_graphs.begin(),
                                         m_graphs.end(),
                                         [&name](const auto& graph)
                                         { return std::get<0>(graph) == name; });
            for (auto& [parent, children] : std::get<1>(*graphPos).m_edges)
            {
                if (!std::get<1>(*graphPos).hasNode(parent))
                {
                    std::string childrenNames;
                    for (auto& child : children)
                    {
                        childrenNames += child + " ";
                    }
                    throw std::runtime_error(fmt::format(
                        "Error building environment \"{}\". Asset \"{}\" requested for "
                        "parent \"{}\" which could not be found",
                        name,
                        parent,
                        childrenNames));
                }
                for (auto& child : children)
                {
                    if (!std::get<1>(*graphPos).hasNode(child))
                    {
                        throw std::runtime_error(
                            fmt::format("Asset \"{}\" could not be found", child));
                    }
                }
            }
        }
    }

    /**
     * @brief Get the name of the environment.
     *
     * @return const std::string& Name of the environment.
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
     * @brief Build and Get the Expression from the environment.
     *
     * @return base::Expression Root expression of the environment.
     * @throws std::runtime_error If the expression cannot be built.
     */
    base::Expression getExpression() const;
};

} // namespace builder

#endif // _ENVIRONMENT_H
