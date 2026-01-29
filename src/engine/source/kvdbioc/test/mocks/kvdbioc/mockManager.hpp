#ifndef _KVDBIOC_MOCK_MANAGER_HPP
#define _KVDBIOC_MOCK_MANAGER_HPP

#include <gmock/gmock.h>
#include <kvdbioc/iManager.hpp>

namespace kvdb
{

class MockKVDBManager : public IKVDBManager
{
public:
    MOCK_METHOD(void, add, (std::string_view name), (override));

    MOCK_METHOD(void, put, (std::string_view name, std::string_view key, std::string_view value), (override));

    MOCK_METHOD(void, hotSwap, (std::string_view name), (override));

    MOCK_METHOD(std::shared_ptr<IReadOnlyKVDBHandler>, openReadOnly, (std::string_view name), (override));

    MOCK_METHOD(void, remove, (std::string_view name), (override));
};

} // namespace kvdb

#endif // _KVDBIOC_MOCK_MANAGER_HPP
