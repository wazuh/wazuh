#ifndef _KVDBIOC_MOCK_READONLY_HANDLER_HPP
#define _KVDBIOC_MOCK_READONLY_HANDLER_HPP

#include <gmock/gmock.h>
#include <kvdbioc/iReadOnlyHandler.hpp>

namespace kvdb
{

class MockReadOnlyKVDBHandler : public IReadOnlyKVDBHandler
{
public:
    MOCK_METHOD(const DbName&, name, (), (const, noexcept, override));

    MOCK_METHOD(json::Json, get, (std::string_view key), (const, override));

    MOCK_METHOD(std::shared_ptr<const DbInstance>, load, (), (const, noexcept, override));

    MOCK_METHOD(void, store, (std::shared_ptr<const DbInstance> next), (noexcept, override));

    MOCK_METHOD(bool, hasInstance, (), (const, noexcept, override));
};

} // namespace kvdb

#endif // _KVDBIOC_MOCK_READONLY_HANDLER_HPP
