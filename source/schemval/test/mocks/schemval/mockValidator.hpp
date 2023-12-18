#ifndef _SCHEMVAL_MOCKVALIDATOR_HPP
#define _SCHEMVAL_MOCKVALIDATOR_HPP

#include <gmock/gmock.h>

#include <schemval/ivalidator.hpp>

namespace schemval::mocks
{

class MockValidator : public IValidator
{
public:
    MOCK_METHOD(json::Json::Type, getJsonType, (schemf::Type), (const, override));
    MOCK_METHOD(base::OptError, validate, (const DotPath&, const ValidationToken&), (const, override));
    MOCK_METHOD(base::OptError, validateArray, (const DotPath&, const ValidationToken&), (const, override));
    MOCK_METHOD(base::RespOrError<RuntimeValidator>, getRuntimeValidator, (const DotPath&, bool), (const, override));
    MOCK_METHOD(ValidationToken, createToken, (json::Json::Type), (const, override));
    MOCK_METHOD(ValidationToken, createToken, (schemf::Type), (const, override));
    MOCK_METHOD(ValidationToken, createToken, (const json::Json&), (const, override));
    MOCK_METHOD(ValidationToken, createToken, (const DotPath&), (const, override));
    MOCK_METHOD(ValidationToken, createToken, (), (const, override));
};

} // namespace schemval::mocks

#endif // _SCHEMVAL_MOCKVALIDATOR_HPP
