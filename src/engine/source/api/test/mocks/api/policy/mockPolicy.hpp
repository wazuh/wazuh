#ifndef _API_POLICY_MOCK_POLICY_HPP
#define _API_POLICY_MOCK_POLICY_HPP

#include <gmock/gmock.h>

#include <api/policy/ipolicy.hpp>

namespace api::policy::mocks
{
class MockPolicy : public IPolicy
{
public:
    MOCK_METHOD(base::OptError, create, (const base::Name& policyName), (override));
    MOCK_METHOD(base::OptError, del, (const base::Name& policyName), (override));
    MOCK_METHOD(base::RespOrError<std::string>,
                get,
                (const base::Name& policyName, const std::vector<store::NamespaceId>& namespaceIds),
                (const, override));
    MOCK_METHOD(base::RespOrError<std::vector<base::Name>>, list, (), (const, override));
    MOCK_METHOD(base::RespOrError<std::string>,
                addAsset,
                (const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName),
                (override));
    MOCK_METHOD(base::RespOrError<std::string>,
                delAsset,
                (const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName),
                (override));
    MOCK_METHOD(base::RespOrError<std::list<base::Name>>,
                listAssets,
                (const base::Name& policyName, const store::NamespaceId& namespaceId),
                (const, override));
    MOCK_METHOD(base::RespOrError<std::list<base::Name>>,
                getDefaultParent,
                (const base::Name& policyName, const store::NamespaceId& namespaceId),
                (const, override));
    MOCK_METHOD(base::RespOrError<std::string>,
                setDefaultParent,
                (const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName),
                (override));
    MOCK_METHOD(base::RespOrError<std::string>,
                delDefaultParent,
                (const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName),
                (override));
    MOCK_METHOD(base::RespOrError<std::list<store::NamespaceId>>,
                listNamespaces,
                (const base::Name& policyName),
                (const, override));
    MOCK_METHOD(base::RespOrError<std::string>, getHash, (const base::Name& policyName), (const, override));
    MOCK_METHOD(base::OptError, copy, (const base::Name& policyName, const base::Name& newPolicyName), (override));
    MOCK_METHOD(base::RespOrError<std::string>, cleanDeleted, (const base::Name& policyName), (override));
};
} // namespace api::policy::mocks

#endif // _API_POLICY_MOCK_POLICY_HPP
