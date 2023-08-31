#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <builder/ivalidator.hpp>
#include <json/json.hpp>
#include <name.hpp>
#include <store/utils.hpp>
#include <utils/getExceptionStack.hpp>

#include "asset.hpp"
#include "policy.hpp"
#include "registry.hpp"

namespace builder
{

class Builder : public IValidator
{
private:
    std::shared_ptr<store::IStore> m_storeRead;                    ///< Store reader interface
    std::shared_ptr<internals::Registry<internals::Builder>> m_registry; ///< Registry of builders

public:

    /**
     * @brief Construct a new Builder
     *
     * @param storeRead Store reader interface to manipulate the Asset, Policy and Schema files
     * @param registry Registry of builders to build the assets
     */
    Builder(std::shared_ptr<store::IStore> storeRead, std::shared_ptr<internals::Registry<internals::Builder>> registry)
        : m_storeRead {storeRead}
        , m_registry {registry}
    {
    }

    Policy buildPolicy(const base::Name& name) const
    {
        auto policyDoc = m_storeRead->readInternalDoc(name);
        if (base::isError(policyDoc))
        {
            throw std::runtime_error(base::getError(policyDoc).message);
        }

        return Policy {base::getResponse<store::Doc>(policyDoc), m_storeRead, m_registry};
    }

    /**
     * @brief Build a asset route from the store.
     *
     * @param name Name of the route.
     * @return The route.
     * @throws std::runtime_error if the route could not be obtained from the store or if the route definition is
     * invalid.
     */
    Asset buildFilter(const base::Name& name) const
    {
        auto routeJson = store::utils::get(m_storeRead, name);
        if (base::isError(routeJson))
        {
            throw std::runtime_error(base::getError(routeJson).message);
        }

        return Asset {base::getResponse<store::Doc>(routeJson), Asset::Type::FILTER, m_registry};
    }

    std::optional<base::Error> validatePolicy(const json::Json& json) const override
    {
        try
        {
            Policy policy {json, m_storeRead, m_registry};
            policy.expression();
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }

    std::optional<base::Error> validateIntegration(const json::Json& json) const override
    {
        try
        {
            Policy::getManifestAssets(json, m_storeRead, m_registry);
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }

    std::optional<base::Error> validateAsset(const json::Json& json) const override
    {
        try
        {
            // TODO: Remove asset type in Asset
            Asset asset {json, Asset::Type::DECODER, m_registry};
            asset.getExpression();
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }
};

} // namespace builder

#endif // _BUILDER_H
