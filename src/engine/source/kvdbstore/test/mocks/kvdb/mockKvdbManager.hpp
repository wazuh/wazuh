#ifndef _MOCKS_KVDBSTORE_KVDB_MANAGER_HPP
#define _MOCKS_KVDBSTORE_KVDB_MANAGER_HPP

#include <memory>
#include <string>

#include <gmock/gmock.h>

#include <cmstore/icmstore.hpp>

#include <kvdb/ikvdbhandler.hpp>
#include <kvdb/ikvdbmanager.hpp>

namespace kvdbStore::mocks
{

class MockKVDBManager : public kvdbStore::IKVDBManager
{
public:
    MOCK_METHOD(std::shared_ptr<IKVDBHandler>,
                getKVDBHandler,
                (const cm::store::ICMStoreNSReader& nsReader, const std::string& dbName),
                (override));
};

} // namespace kvdbStore::mocks

#endif // _MOCKS_KVDBSTORE_KVDB_MANAGER_HPP
