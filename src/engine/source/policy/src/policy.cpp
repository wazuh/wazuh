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
    // Check if policyName is valid
    if (policyName.parts().size() != 3)
    {
        return base::Error {fmt::format("Invalid policy name: {}, expected 3 parts", policyName.fullName())};
    }
    else if (policyName.parts()[0] != "policy")
    {
        return base::Error {
            fmt::format("Invalid policy name: {}, expected 'policy' as first part", policyName.fullName())};
    }

    if (m_store->existsInternalDoc(policyName))
    {
        return base::Error {fmt::format("Policy already exists: {}", policyName.fullName())};
    }

    return upsert(PolicyRep {policyName});
}

base::OptError Policy::del(const base::Name& policyName)
{
    return m_store->deleteInternalDoc(policyName.fullName());
}


base::RespOrError<std::vector<base::Name>> Policy::list() const
{
    const auto basePolicy = base::Name {"policy"};
    auto col = m_store->readInternalCol(basePolicy);
    if (base::isError(col))
    {
        return base::getError(col);
    }

    std::vector<base::Name> policies;
    // Get all versions of each policy
    for (const auto& subCol : base::getResponse<store::Col>(col))
    {
        auto versions = m_store->readInternalCol(subCol);
        if (base::isError(versions))
        {
            return base::getError(versions);
        }
        for (const auto& version : base::getResponse<store::Col>(versions))
        {
            policies.emplace_back(version);
        }
    }

    return policies;
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
