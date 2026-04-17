#ifndef _BUILDER2_IBUILDER_HPP
#define _BUILDER2_IBUILDER_HPP

#include <memory>

#include <base/error.hpp>
#include <base/expression.hpp>
#include <builder/ipolicy.hpp>
#include <cmstore/types.hpp>

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
     * @param namespaceId Namespace identifier for the policy.
     * @param isTestMode Whether to build the policy in test mode.
     * @return std::shared_ptr<IPolicy> The built policy.
     */
    virtual std::shared_ptr<IPolicy>
    buildPolicy(const cm::store::NamespaceId& namespaceId, bool isTestMode) const = 0;

};

} // namespace builder

#endif // _BUILDER2_IBUILDER_HPP
