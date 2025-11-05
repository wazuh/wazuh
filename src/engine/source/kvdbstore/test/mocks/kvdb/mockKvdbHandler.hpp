#ifndef _KVDBSTORE_MOCK_KVDB_HANDLER_HPP
#define _KVDBSTORE_MOCK_KVDB_HANDLER_HPP

#include <optional>
#include <string>
#include <string_view>

#include <gmock/gmock.h>

#include <kvdb/ikvdbhandler.hpp>

namespace kvdbStore::mocks
{

class MockKVDBHandler : public kvdbStore::IKVDBHandler
{
public:
    MOCK_METHOD((std::optional<std::string_view>), get, (const std::string& key), (const, noexcept, override));
    MOCK_METHOD(bool, contains, (const std::string& key), (const, noexcept, override));
};

} // namespace kvdbStore::mocks

#endif // _KVDBSTORE_MOCK_KVDB_HANDLER_HPP
