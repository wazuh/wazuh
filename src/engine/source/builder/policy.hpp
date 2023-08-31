#ifndef _BUILDER_POLICY_HPP
#define _BUILDER_POLICY_HPP

#include <builder/ipolicy.hpp>

#include <memory>
#include <unordered_map>

#include <fmt/format.h>

#include <graph.hpp>
#include <store/istore.hpp>

#include "asset.hpp"

namespace builder
{
class Policy : public IPolicy
{
private:
    using AssetPtr = std::shared_ptr<Asset>;
    using Subgraph = Graph<base::Name, AssetPtr>;

    base::Name m_name;                                      ///< Name of the policy
    std::unordered_map<base::Name, AssetPtr> m_assets;      ///< Assets of the policy
    std::vector<std::pair<std::string, Subgraph>> m_graphs; ///< Graphs of the policy

    /**
     * @brief Insert subgraph
     *
     * @param name Name of the subgraph
     * @param graph
     */
    inline void insertGraph(const std::string& name, Subgraph&& graph)
    {
        m_graphs.emplace_back(std::pair {name, std::move(graph)});
    }

    /**
     * @brief Build the specified subgraph.
     * @pre Specified assets must be already built in the policy.
     *
     * The building algorithm is:
     * 1. Add input node of the subgraph
     * 2. For each asset in the set:
     * 2.1. Add asset node
     * 2.2. If no parents, connect to input node
     * 2.3. If parents, connect to parents
     * 3. Add filters:
     * 3.1. For each filter in the policy:
     * 3.1.1. If the parent is present in the subgraph, inject the filter between the asset and the children
     * 4. Integrity check
     *
     * @param subgraph
     * @param assets
     * @param type Asset type of the subgraph
     */
    void buildGraph(const std::string& subgraph, const std::unordered_set<base::Name>& assets, Asset::Type type);

public:
    /**
     * @copydoc IPolicy::name
     */
    inline base::Name name() const override { return m_name; }

    /**
     * @copydoc IPolicy::assets
     */
    std::unordered_set<base::Name> assets() const override;

    /**
     * @copydoc IPolicy::expression
     */
    base::Expression expression() const override;

    /**
     * @copydoc IPolicy::getGraphivzStr
     */
    std::string getGraphivzStr() const override;

    Policy() = default;

    /**
     * @brief Construct a new Policy object
     *
     * @param jsonDefinition Json definition of the policy.
     * @param store Store interface.
     * @param registry Registry interface.
     * @throws std::runtime_error if the policy cannot be built.
     */
    Policy(const json::Json& jsonDefinition,
           std::shared_ptr<const store::IStore> store,
           std::shared_ptr<internals::Registry<internals::Builder>> registry);

    static std::unordered_map<Asset::Type, std::vector<std::shared_ptr<Asset>>>
    getManifestAssets(const json::Json& jsonDefinition,
                      std::shared_ptr<const store::IStoreReader> storeRead,
                      std::shared_ptr<internals::Registry<internals::Builder>> registry);
};
} // namespace builder

#endif // _BUILDER_POLICY_HPP
