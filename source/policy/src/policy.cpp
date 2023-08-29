#include <policy/policy.hpp>

#include "policyRep.hpp"

namespace api::policy
{
base::RespOrError<Policy::PolicyRep> Policy::read(const base::Name& policyName) const
{
    auto resp = m_store->readInternalDoc(policyName.fullName());
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    return PolicyRep::fromDoc(base::getResponse<store::Doc>(resp));
}

base::OptError Policy::upsert(PolicyRep policy)
{
    auto resp = m_store->upsertInternalDoc(policy.name().fullName(), policy.toDoc());
    return resp;
}

base::OptError Policy::create(const base::Name& policyName)
{
    // TODO: add exists to internal store interface
    return upsert(PolicyRep {policyName});
}

base::OptError Policy::del(const base::Name& policyName)
{
    return m_store->deleteInternalDoc(policyName.fullName());
}

base::OptError
Policy::addAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName)
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    auto error = policy.addAsset(namespaceId, assetName);
    if (base::isError(error))
    {
        return error;
    }

    return upsert(policy);
}

base::OptError
Policy::delAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName)
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    auto error = policy.delAsset(namespaceId, assetName);
    if (base::isError(error))
    {
        return error;
    }

    return upsert(policy);
}

base::RespOrError<std::list<base::Name>> Policy::listAssets(const base::Name& policyName,
                                                            const store::NamespaceId& namespaceId) const
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    return policy.listAssets(namespaceId);
}

} // namespace api::policy
