#include <api/policy/policy.hpp>

#include "policyRep.hpp"

namespace
{
/**
 * @brief Validates the namespace name of a policy.
 *
 * @param policyName The name of the policy to validate.
 * @return An optional error if the policy name is invalid, otherwise std::nullopt.
 */
base::OptError vaidateNsName(const base::Name& policyName)
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

    return std::nullopt;
}
} // namespace

namespace api::policy
{
base::RespOrError<Policy::PolicyRep> Policy::read(const base::Name& policyName) const
{
    // Check if policyName is valid
    if (auto error = vaidateNsName(policyName); base::isError(error))
    {
        return *error;
    }
    auto resp = m_store->readInternalDoc(policyName.fullName());
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    return PolicyRep::fromDoc(base::getResponse<store::Doc>(resp), m_store);
}

base::RespOrError<std::string> Policy::upsert(const PolicyRep& policy, bool ignoreValidation)
{

    if (auto error = vaidateNsName(policy.name()); base::isError(error))
    {
        return base::getError(error);
    }

    auto doc = policy.toDoc();
    auto error = m_validator->validatePolicy(doc);
    std::string warning;
    if (base::isError(error))
    {
        if (!ignoreValidation)
        {
            return base::getError(error);
        }
        else
        {
            warning = fmt::format("Saved invalid policy: {}", base::getError(error).message);
        }
    }

    auto resp = m_store->upsertInternalDoc(policy.name().fullName(), doc);

    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    return warning;
}

base::OptError Policy::create(const base::Name& policyName)
{
    // Check if policyName is valid
    if (auto error = vaidateNsName(policyName); base::isError(error))
    {
        return error;
    }

    if (m_store->existsInternalDoc(policyName))
    {
        return base::Error {fmt::format("Policy already exists: {}", policyName.fullName())};
    }

    auto upsertResp = upsert(PolicyRep {policyName});

    if (base::isError(upsertResp))
    {
        return base::getError(upsertResp);
    }

    return base::noError();
}

base::OptError Policy::del(const base::Name& policyName)
{
    // Check if policyName is valid
    if (auto error = vaidateNsName(policyName); base::isError(error))
    {
        return error;
    }
    return m_store->deleteInternalDoc(policyName.fullName());
}

base::RespOrError<std::string> Policy::get(const base::Name& policyName,
                                           const std::vector<store::NamespaceId>& namespaceIds) const
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    return policy.print(namespaceIds);
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

base::RespOrError<std::string>
Policy::addAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName)
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);

    auto assetNamespace = m_store->getNamespace(assetName);
    if (assetNamespace.has_value() && assetNamespace.value() != namespaceId)
    {
        return base::Error {fmt::format("Asset {} does not belong to namespace {}", assetName, namespaceId.name())};
    }

    auto error = policy.addAsset(namespaceId, assetName);
    if (base::isError(error))
    {
        return base::getError(error);
    }

    return upsert(policy, true);
}

base::RespOrError<std::string>
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
        return base::getError(error);
    }

    return upsert(policy, true);
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

base::RespOrError<std::list<base::Name>> Policy::getDefaultParent(const base::Name& policyName,
                                                                  const store::NamespaceId& namespaceId) const
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    return policy.getDefaultParent(namespaceId);
}

base::RespOrError<std::string> Policy::setDefaultParent(const base::Name& policyName,
                                                        const store::NamespaceId& namespaceId,
                                                        const base::Name& parentName)
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    auto error = policy.setDefaultParent(namespaceId, parentName);
    if (base::isError(error))
    {
        return base::getError(error);
    }

    return upsert(policy, true);
}

base::RespOrError<std::string> Policy::delDefaultParent(const base::Name& policyName,
                                                        const store::NamespaceId& namespaceId,
                                                        const base::Name& parentName)
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    auto error = policy.delDefaultParent(namespaceId, parentName);
    if (base::isError(error))
    {
        return base::getError(error);
    }

    return upsert(policy, true);
}

base::RespOrError<std::list<store::NamespaceId>> Policy::listNamespaces(const base::Name& policyName) const
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    return policy.listNs();
}

base::RespOrError<std::string> Policy::getHash(const base::Name& policyName) const
{
    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    return policy.getHash();
}

base::OptError Policy::copy(const base::Name& policyName, const base::Name& newPolicyName)
{
    // Validate newPolicyName
    if (auto error = vaidateNsName(newPolicyName); base::isError(error))
    {
        return error;
    }

    auto resp = read(policyName);
    if (base::isError(resp))
    {
        return base::getError(resp);
    }

    auto policy = base::getResponse<PolicyRep>(resp);
    policy.setName(newPolicyName);

    auto upsertResp = upsert(policy);
    if (base::isError(upsertResp))
    {
        return base::getError(upsertResp);
    }

    return base::noError();
}

base::RespOrError<std::string> Policy::cleanDeleted(const base::Name& policyName)
{
    // Check if policyName is valid
    if (auto error = vaidateNsName(policyName); base::isError(error))
    {
        return *error;
    }
    auto resp = m_store->readInternalDoc(policyName.fullName());
    if (base::isError(resp))
    {
        return base::getError(resp);
    }
    auto doc = base::getResponse<store::Doc>(resp);

    auto deletedAssets = PolicyRep::getDeletedAssets(doc, m_store);

    if (deletedAssets.empty())
    {
        return base::Error {"No deleted assets to clean"};
    }

    auto policyResp = PolicyRep::fromDoc(doc, m_store, true);
    if (base::isError(policyResp))
    {
        return base::getError(policyResp);
    }

    auto policy = base::getResponse<PolicyRep>(policyResp);

    // Save the policy
    auto upsertResp = upsert(policy, true);

    if (base::isError(upsertResp))
    {
        return base::getError(upsertResp);
    }

    auto response = base::getResponse(upsertResp);
    response += fmt::format("\nDeleted assets: {}", fmt::join(deletedAssets, ", "));

    return response;
}

} // namespace api::policy
