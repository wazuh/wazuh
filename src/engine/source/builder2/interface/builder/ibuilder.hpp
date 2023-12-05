#ifndef _BUILDER2_IBUILDER_HPP
#define _BUILDER2_IBUILDER_HPP

#include <memory>

#include <builder/ipolicy.hpp>
#include <error.hpp>
#include <expression.hpp>
#include <name.hpp>

namespace builder
{

/**
 * @brief Builder Interface for building Policies and Assets.
 *
 */
class IBuilder
{
public:
    virtual ~IBuilder() = default;

    /**
     * @brief Build a policy from the store.
     *
     * @param name Name of the policy.
     * @return base::RespOrError<std::shared_ptr<IPolicy>> The policy or an error.
     */
    virtual std::shared_ptr<IPolicy> buildPolicy(const base::Name& name) const = 0;

    /**
     * @brief Build an asset expression from the store.
     * @attention This method ignores the parents of the asset.
     *
     * @param name Name of the asset.
     * @return base::RespOrError<base::Expression> The asset expression or an error.
     */
    virtual base::Expression buildAsset(const base::Name& name) const = 0;
};

} // namespace builder

#endif // _BUILDER2_IBUILDER_HPP
