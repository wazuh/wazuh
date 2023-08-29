#ifndef _API_POLICY_MOCK_POLICY_HPP
#define _API_POLICY_MOCK_POLICY_HPP

#include <gmock/gmock.h>

#include <policy/ipolicy.hpp>

namespace api::policy::mocks
{
class MockPolicy : public IPolicy
{
public:
    MOCK_METHOD(base::OptError, create, (const base::Name& policyName), (override));
    MOCK_METHOD(base::OptError, del, (const base::Name& policyName), (override));
    MOCK_METHOD(base::OptError,
                addAsset,
                (const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName),
                (override));
    MOCK_METHOD(base::OptError,
                delAsset,
                (const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName),
                (override));
    MOCK_METHOD(base::RespOrError<std::list<base::Name>>,
                listAssets,
                (const base::Name& policyName, const store::NamespaceId& namespaceId),
                (const, override));
};
} // namespace api::policy::mocks

#endif // _API_POLICY_MOCK_POLICY_HPP