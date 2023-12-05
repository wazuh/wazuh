#ifndef _SCHEMF_MOCK_SCHEMA_HPP
#define _SCHEMF_MOCK_SCHEMA_HPP

#include <gmock/gmock.h>

#include <schemf/ischema.hpp>

namespace schemf::mocks
{
class MockSchema : public ISchema
{
public:
    MOCK_METHOD(Type, getType, (const DotPath& name), (const, override));
    MOCK_METHOD(bool, hasField, (const DotPath& name), (const, override));
    MOCK_METHOD(bool, isArray, (const DotPath& name), (const, override));
};
} // namespace schemf::mocks

#endif // _SCHEMF_MOCK_SCHEMA_HPP
