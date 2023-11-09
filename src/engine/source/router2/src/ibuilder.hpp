#ifndef _ROUTER2_IBUILDER_HPP
#define _ROUTER2_IBUILDER_HPP

#include <memory>

#include <builder/asset.hpp>
#include <builder/ipolicy.hpp>
#include <builder/policy.hpp>
#include <builder/registry.hpp>
#include <error.hpp>
#include <expression.hpp>
#include <name.hpp>
#include <store/utils.hpp>

namespace router
{

class IBuilder
{
public:
    /**
     * @brief Build a policy from the store.
     *
     * @param name Name of the policy.
     * @return base::RespOrError<std::shared_ptr<IPolicy>> The policy or an error.
     */
    virtual base::RespOrError<std::shared_ptr<builder::IPolicy>> buildPolicy(const base::Name& name) const = 0;

    /**
     * @brief Build an asset expression from the store.
     * @attention This method ignores the parents of the asset.
     *
     * @param name Name of the asset.
     * @return base::RespOrError<base::Expression> The asset expression or an error.
     */
    virtual base::RespOrError<base::Expression> buildAsset(const base::Name& name) const = 0;
};

/**
 * @brief Concrete implementation of the IBuilder interface.
 *
 */
class ConcreteBuilder : public IBuilder
{
private:
    std::shared_ptr<store::IStore> m_storeRead; /**< The store to retrieve internal documents. */
    std::shared_ptr<builder::internals::Registry<builder::internals::Builder>> m_registry; /**< The registry for builder internals. */

public:

    /**
     * @brief Construct a ConcreteBuilder object.
     *
     * @param store The store to retrieve internal documents.
     * @param registry The registry for builder internals.
     */
    ConcreteBuilder(std::shared_ptr<store::IStore> store,
                    std::shared_ptr<builder::internals::Registry<builder::internals::Builder>> registry)
        : m_storeRead(store)
        , m_registry(registry)
    {
    }

    /**
     * @copydoc IBuilder::buildPolicy
     */
    base::RespOrError<std::shared_ptr<builder::IPolicy>> buildPolicy(const base::Name& name) const override
    {
        auto policyDoc = m_storeRead->readInternalDoc(name);
        if (base::isError(policyDoc))
        {
            return base::getError(policyDoc);
        }

        return std::make_shared<builder::Policy>(base::getResponse<store::Doc>(policyDoc), m_storeRead, m_registry);
    }

    /**
     * @copydoc IBuilder::buildAsset
     */
    base::RespOrError<base::Expression> buildAsset(const base::Name& name) const override
    {
        auto routeJson = store::utils::get(m_storeRead, name);
        if (base::isError(routeJson))
        {
            return base::getError(routeJson);
        }
        builder::Asset asset(base::getResponse<store::Doc>(routeJson), builder::Asset::Type::FILTER, m_registry);
        return asset.getExpression();
    }
};

} // namespace router

#endif //_ROUTER2_IBUILDER_HPP
