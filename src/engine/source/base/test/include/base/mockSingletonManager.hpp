#ifndef _BASE_TEST_SINGLETONMANAGER_HPP
#define _BASE_TEST_SINGLETONMANAGER_HPP

#include <gmock/gmock.h>

#include <base/utils/singletonLocator.hpp>

namespace base::test
{

template<typename T>
class MockSingletonManager : public ISingletonManager<T>
{

public:
    ~MockSingletonManager() override = default;

    MOCK_METHOD(T&, instance, (), (override));
};

} // namespace base::test

#endif // _BASE_TEST_SINGLETONMANAGER_HPP
