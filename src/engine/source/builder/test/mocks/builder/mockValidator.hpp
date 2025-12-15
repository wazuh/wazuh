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
                softIntegrationValidate,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                 const cm::store::dataType::Integration& integration),
                (const, override));
    MOCK_METHOD(base::OptError,
                validateAsset,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader, const json::Json& assetJson),
                (const, override));
    MOCK_METHOD(base::OptError,
                softPolicyValidate,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                 const cm::store::dataType::Policy& policy),
                (const, override));
};
} // namespace builder::mocks

#endif // BUILDER2_TEST_SRC_MOCKS_MOCKVALIDATOR_HPP
