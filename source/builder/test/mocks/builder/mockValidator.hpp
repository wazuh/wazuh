#ifndef _BUILDER_MOCK_VALIDATOR_HPP
#define _BUILDER_MOCK_VALIDATOR_HPP

#include <gmock/gmock.h>

#include <builder/ivalidator.hpp>

namespace builder::mocks
{

/******************************************************************************/
// Helper functions to mock method responses
/******************************************************************************/
inline base::OptError validateError()
{
    return base::Error {"Mocked validator error"};
}

class MockValidator : public IValidator
{
public:
    MOCK_METHOD(base::OptError, validatePolicy, (const json::Json& json), (const, override));
    MOCK_METHOD(base::OptError, validateIntegration, (const json::Json& json), (const, override));
    MOCK_METHOD(base::OptError, validateAsset, (const json::Json& json), (const, override));
};

} // namespace builder::mocks

#endif // _BUILDER_MOCK_VALIDATOR_HPP
