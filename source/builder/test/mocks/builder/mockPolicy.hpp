#ifndef _BUILDER_MOCK_POLICY_HPP
#define _BUILDER_MOCK_POLICY_HPP

#include <gmock/gmock.h>

#include <builder/ipolicy.hpp>

namespace builder::mocks
{

class MockPolicy : public IPolicy
{
public:
    MOCK_METHOD(base::Name, name, (), (const, override));
    MOCK_METHOD(std::unordered_set<base::Name>, assets, (), (const, override));
    MOCK_METHOD(base::Expression, expression, (), (const, override));
    MOCK_METHOD(std::string, getGraphivzStr, (), (const, override));
};

} // namespace builder::mocks

#endif // _BUILDER_MOCK_POLICY_HPP
