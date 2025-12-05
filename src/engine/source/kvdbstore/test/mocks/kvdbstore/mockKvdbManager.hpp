#ifndef _MOCKS_KVDBSTORE_KVDB_MANAGER_HPP
#define _MOCKS_KVDBSTORE_KVDB_MANAGER_HPP

#include <memory>
#include <string>

#include <gmock/gmock.h>

#include <cmstore/icmstore.hpp>

#include <kvdbstore/ikvdbhandler.hpp>
#include <kvdbstore/ikvdbmanager.hpp>

namespace kvdbstore::mocks
{

class MockIKVDBManager : public kvdbstore::IKVDBManager
{
public:
    MOCK_METHOD(std::shared_ptr<IKVDBHandler>,
                getKVDBHandler,
                (const cm::store::ICMStoreNSReader& nsReader, const std::string& dbName),
                (override));
};

} // namespace kvdbstore::mocks

#endif // _MOCKS_KVDBSTORE_KVDB_MANAGER_HPP
