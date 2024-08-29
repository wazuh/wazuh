#ifndef _KVDB_MOCK_KVDB_HANDLER_COLLECTION_HPP
#define _KVDB_MOCK_KVDB_HANDLER_COLLECTION_HPP

#include <gmock/gmock.h>

#include <kvdb/ikvdbhandler.hpp>
#include <kvdb/ikvdbhandlercollection.hpp>

namespace kvdb::mocks
{

/******************************************************************************/
// Mock classes
/******************************************************************************/
class MockKVDBHandlerCollection : public kvdbManager::IKVDBHandlerCollection
{
public:
    MOCK_METHOD((void), addKVDBHandler, (const std::string& dbName, const std::string& scopeName), (override));
    MOCK_METHOD((void), removeKVDBHandler, (const std::string& dbName, const std::string& scopeName), (override));
};

} // namespace kvdb::mocks

#endif // _KVDB_MOCK_KVDB_HANDLER_COLLECTION_HPP
