#ifndef _BUILDDER_POLICY_IASSETBUILDER_HPP
#define _BUILDDER_POLICY_IASSETBUILDER_HPP

#include "asset.hpp"
#include "builders/buildCtx.hpp"

namespace builder::policy
{

/**
 * @brief Interface for asset builders. Responsible for building assets from store documents.
 *
 */
class IAssetBuilder
{
public:
    virtual ~IAssetBuilder() = default;

    /**
     * @brief Build the asset from a store document.
     *
     * @param document Store document containing the asset data.
     *
     * @return Asset
     *
     * @throw std::runtime_error If any error occurs while building the asset.
     */
    virtual Asset operator()(const json::Json& document) const = 0;

    /**
     * @brief Get the context of the asset builder.
     *
     * @return Context&
     */
    virtual builder::builders::Context& getContext() const = 0;

    /**
     * @brief Set the available KVDBs for validation during asset building.
     *
     * @param kvdbs Map of KVDB names to their enabled/disabled status (moved).
     */
    virtual void setAvailableKvdbs(std::unordered_map<std::string, bool>&& kvdbs) = 0;

    /**
     * @brief Clear the available KVDBs (disables KVDB validation).
     */
    virtual void clearAvailableKvdbs() = 0;
};

} // namespace builder::policy

#endif // _BUILDDER_POLICY_IASSETBUILDER_HPP
