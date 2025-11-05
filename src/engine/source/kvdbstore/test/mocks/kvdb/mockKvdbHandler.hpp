#ifndef _MOCKS_KVDBSTORE_KVDB_HANDLER_HPP
#define _MOCKS_KVDBSTORE_KVDB_HANDLER_HPP

#include <string>

#include <gmock/gmock.h>

#include <base/json.hpp>
#include <kvdb/ikvdbhandler.hpp>

namespace kvdbStore::mocks
{

class MockKVDBHandler : public kvdbStore::IKVDBHandler
{
public:
    MOCK_METHOD(const json::Json&, get, (const std::string& key), (const, override));
    MOCK_METHOD(bool, contains, (const std::string& key), (const, noexcept, override));
};

} // namespace kvdbStore::mocks

#endif // _MOCKS_KVDBSTORE_KVDB_HANDLER_HPP
