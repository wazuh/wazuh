#ifndef BUILDER2_TEST_SRC_MOCKS_MOCKVALIDATOR_HPP
#define BUILDER2_TEST_SRC_MOCKS_MOCKVALIDATOR_HPP

#include <gmock/gmock.h>

#include <builder/ivalidator.hpp>

namespace builder::mocks
{

inline base::OptError validateError()
{
    return base::Error {"Mocked validator error"};
}

inline base::OptError validateOk()
{
    return std::nullopt;
}

class MockValidator : public IValidator
{
public:
    MOCK_METHOD(base::OptError,
                validateIntegration,
                (const base::Name& name, const cm::store::NamespaceId& namespaceId),
                (const, override));
    MOCK_METHOD(base::OptError,
                validateAsset,
                (const base::Name& name, const cm::store::NamespaceId& namespaceId),
                (const, override));
    MOCK_METHOD(base::OptError, validatePolicy, (const cm::store::NamespaceId namespaceId), (const, override));
};
} // namespace builder::mocks

#endif // BUILDER2_TEST_SRC_MOCKS_MOCKVALIDATOR_HPP
