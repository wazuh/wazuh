#ifndef _BUILDER_TEST_UNIT_REGISTRY_MOCKREGISTRY_HPP
#define _BUILDER_TEST_UNIT_REGISTRY_MOCKREGISTRY_HPP

#include <gmock/gmock.h>

#include "builders/iregistry.hpp"

namespace builder::builders::mocks
{

template<typename T>
base::RespOrError<T> getError()
{
    return base::RespOrError<T>(base::Error {"Error"});
}

template<typename T>
class MockRegistry : public IRegistry<T>
{
public:
    MOCK_METHOD(base::OptError, add, (const std::string& name, const T& entry), (override));
    MOCK_METHOD(base::RespOrError<T>, get, (const std::string& name), (const, override));
};

} // namespace builder::registry::mock

#endif // _BUILDER_TEST_UNIT_REGISTRY_MOCKREGISTRY_HPP
