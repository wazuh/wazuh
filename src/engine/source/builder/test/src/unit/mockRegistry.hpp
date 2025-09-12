#ifndef _BUILDER_TEST_UNIT_REGISTRY_MOCKREGISTRY_HPP
#define _BUILDER_TEST_UNIT_REGISTRY_MOCKREGISTRY_HPP

#include <gmock/gmock.h>

#include "iregistry.hpp"

namespace builder::mocks
{

template<typename T>
base::RespOrError<T> getError()
{
    return base::RespOrError<T>(base::Error {"Error"});
}

template<typename T>
class MockRegistry final : public IRegistry<T>
{
public:
    MOCK_METHOD(base::OptError, add, (const std::string& name, const T& entry), (override));
    MOCK_METHOD(base::RespOrError<T>, get, (const std::string& name), (const, override));
};

template<typename... Builders>
class MockMetaRegistry final : public MetaRegistry<Builders...>
{
public:
    [[nodiscard]] static constexpr std::shared_ptr<MockMetaRegistry<Builders...>> createMock()
    {
        return std::static_pointer_cast<MockMetaRegistry<Builders...>>(
            MetaRegistry<Builders...>::template create<MockRegistry>());
    }

    template<typename Builder>
    const MockRegistry<Builder>& getRegistry()
    {
        auto regTuple = this->getRegistryTuple();
        auto ptr =
            std::static_pointer_cast<MockRegistry<Builder>>(std::get<std::shared_ptr<IRegistry<Builder>>>(regTuple));
        return *ptr;
    }
};

} // namespace builder::mocks

#endif // _BUILDER_TEST_UNIT_REGISTRY_MOCKREGISTRY_HPP
