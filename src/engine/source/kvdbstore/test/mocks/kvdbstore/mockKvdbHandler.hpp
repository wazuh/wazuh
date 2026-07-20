#ifndef _MOCKS_KVDBSTORE_KVDB_HANDLER_HPP
#define _MOCKS_KVDBSTORE_KVDB_HANDLER_HPP

#include <string>

#include <gmock/gmock.h>

#include <base/json.hpp>
#include <kvdbstore/ikvdbhandler.hpp>

namespace kvdbstore::mocks
{

class MockIKVDBHandler : public kvdbstore::IKVDBHandler
{
public:
    MOCK_METHOD(const json::Json&, get, (const std::string& key), (const, override));
    MOCK_METHOD(bool, contains, (const std::string& key), (const, noexcept, override));
};

} // namespace kvdbstore::mocks

#endif // _MOCKS_KVDBSTORE_KVDB_HANDLER_HPP
