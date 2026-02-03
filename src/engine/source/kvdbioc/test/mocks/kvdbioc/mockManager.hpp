#ifndef _KVDBIOC_MOCK_MANAGER_HPP
#define _KVDBIOC_MOCK_MANAGER_HPP

#include <gmock/gmock.h>
#include <kvdbioc/iManager.hpp>

namespace kvdbioc
{

class MockKVDBManager : public IKVDBManager
{
public:
    MOCK_METHOD(void, add, (std::string_view name), (override));

    MOCK_METHOD(void, put, (std::string_view name, std::string_view key, std::string_view value), (override));

    MOCK_METHOD(void, hotSwap, (std::string_view sourceDb, std::string_view targetDb), (override));

    MOCK_METHOD(std::optional<json::Json>, get, (std::string_view db, std::string_view key), (const, override));

    MOCK_METHOD(std::vector<std::optional<json::Json>>,
                multiGet,
                (std::string_view db, const std::vector<std::string_view>& keys),
                (const, override));

    MOCK_METHOD(void, remove, (std::string_view name), (override));
};

} // namespace kvdbioc

#endif // _KVDBIOC_MOCK_MANAGER_HPP
