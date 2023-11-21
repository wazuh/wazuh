#ifndef _ROUTER_IBUILDER_HPP
#define _ROUTER_IBUILDER_HPP

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
    std::weak_ptr<store::IStore> m_storeRead; /**< The store to retrieve internal documents. */
    std::weak_ptr<builder::internals::Registry<builder::internals::Builder>> m_registry; /**< The registry for builder internals. */

public:

    /**
     * @brief Construct a ConcreteBuilder object.
     *
     * @param store The store to retrieve internal documents.
     * @param registry The registry for builder internals.
     */
    ConcreteBuilder(std::weak_ptr<store::IStore> store,
                    std::weak_ptr<builder::internals::Registry<builder::internals::Builder>> registry)
        : m_storeRead(store)
        , m_registry(registry)
    {
    }

    /**
     * @copydoc IBuilder::buildPolicy
     */
    base::RespOrError<std::shared_ptr<builder::IPolicy>> buildPolicy(const base::Name& name) const override
    {
        auto storeRead = m_storeRead.lock();
        if (!storeRead)
        {
            return base::Error{"Store is not available"};
        }

        auto policyDoc = storeRead->readInternalDoc(name);
        if (base::isError(policyDoc))
        {
            return base::getError(policyDoc);
        }

        auto registry = m_registry.lock();
        if (!registry)
        {
            return base::Error{"Registry is not available"};
        }

        return std::make_shared<builder::Policy>(base::getResponse<store::Doc>(policyDoc), storeRead, registry);
    }

    /**
     * @copydoc IBuilder::buildAsset
     */
    base::RespOrError<base::Expression> buildAsset(const base::Name& name) const override
    {
        auto storeRead = m_storeRead.lock();
        if (!storeRead)
        {
            return base::Error{"Store is not available"};
        }
        auto registry = m_registry.lock();
        if (!registry)
        {
            return base::Error{"Registry is not available"};
        }

        auto routeJson = store::utils::get(storeRead, name);
        if (base::isError(routeJson))
        {
            return base::getError(routeJson);
        }
        builder::Asset asset(base::getResponse<store::Doc>(routeJson), builder::Asset::Type::FILTER, registry);
        return asset.getExpression();
    }
};

} // namespace router

#endif //_ROUTER_IBUILDER_HPP
