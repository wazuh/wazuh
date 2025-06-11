#ifndef _SCHEMF_MOCK_SCHEMA_HPP
#define _SCHEMF_MOCK_SCHEMA_HPP

#include <gmock/gmock.h>

#include <schemf/ischema.hpp>
#include <schemf/ivalidator.hpp>

namespace schemf::mocks
{
class MockSchema : public IValidator
{
public:
    MOCK_METHOD(Type, getType, (const DotPath& name), (const, override));
    MOCK_METHOD(bool, hasField, (const DotPath& name), (const, override));
    MOCK_METHOD(bool, isArray, (const DotPath& name), (const, override));
    MOCK_METHOD(json::Json::Type, getJsonType, (const DotPath& name), (const, override));
    MOCK_METHOD(base::RespOrError<ValidationResult>,
                validate,
                (const DotPath& name, const ValidationToken& token),
                (const, override));
};
} // namespace schemf::mocks

#endif // _SCHEMF_MOCK_SCHEMA_HPP
