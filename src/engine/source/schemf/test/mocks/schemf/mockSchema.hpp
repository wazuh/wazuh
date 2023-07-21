#ifndef _SCHEMF_MOCK_SCHEMA_HPP
#define _SCHEMF_MOCK_SCHEMA_HPP

#include <gmock/gmock.h>

#include <schemf/ischema.hpp>

namespace schemf::mocks
{
class MockSchema : public ISchema
{
public:
    MOCK_METHOD(json::Json::Type, getType, (const DotPath& name), (const, override));
    MOCK_METHOD(bool, hasField, (const DotPath& name), (const, override));
    MOCK_METHOD(std::optional<base::Error>,
                validate,
                (const DotPath& target, const json::Json& value),
                (const, override));
    MOCK_METHOD(std::optional<base::Error>,
                validate,
                (const DotPath& target, const DotPath& reference),
                (const, override));
    MOCK_METHOD(RuntimeValidator, getRuntimeValidator, (const DotPath& target), (const, override));
};
} // namespace schemf::mocks

#endif // _SCHEMF_MOCK_SCHEMA_HPP
