#include <gmock/gmock.h>

#include "registry/iregistry.hpp"

namespace builder::registry::mock
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

} // namespace builder::detail::mock
