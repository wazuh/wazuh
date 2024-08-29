#ifndef BUILDER2_TEST_SRC_MOCKS_MOCKPOLICY_HPP
#define BUILDER2_TEST_SRC_MOCKS_MOCKPOLICY_HPP

#include <gmock/gmock.h>

#include <builder/ipolicy.hpp>

namespace builder::mocks
{
class MockPolicy : public IPolicy
{
public:
    MOCK_METHOD(const base::Name&, name, (), (const, override));
    MOCK_METHOD(const std::string&, hash, (), (const, override));
    MOCK_METHOD(const std::unordered_set<base::Name>&, assets, (), (const, override));
    MOCK_METHOD(const base::Expression&, expression, (), (const, override));
    MOCK_METHOD(std::string, getGraphivzStr, (), (const, override));
};
} // namespace builder::mocks

#endif // BUILDER2_TEST_SRC_MOCKS_MOCKPOLICY_HPP
