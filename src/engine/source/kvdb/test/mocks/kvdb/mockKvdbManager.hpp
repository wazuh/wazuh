#ifndef _KVDB_MOCK_KVDB_MANAGER_HPP
#define _KVDB_MOCK_KVDB_MANAGER_HPP

#include <gmock/gmock.h>

#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/ikvdbhandler.hpp>
#include <kvdb/ikvdbmanager.hpp>

namespace kvdb::mocks
{

/******************************************************************************/
// Helper functions to mock method responses
/******************************************************************************/
inline base::OptError kvdbError(const std::string error)
{
    return base::Error {error};
}

inline base::OptError kvdbOk()
{
    return std::nullopt;
}

inline base::RespOrError<std::shared_ptr<kvdbManager::IKVDBHandler>> kvdbGetKVDBHandlerOk()
{
    return std::make_shared<MockKVDBHandler>();
}

inline base::RespOrError<std::shared_ptr<kvdbManager::IKVDBHandler>> kvdbGetKVDBHandlerError(const std::string& error)
{
    return base::Error {error};
}

inline std::vector<std::string> kvdbListDBsEmpty()
{
    return std::vector<std::string>();
}

/******************************************************************************/
// Mock classes
/******************************************************************************/
class MockKVDBManager : public kvdbManager::IKVDBManager
{
public:
    MOCK_METHOD((void), initialize, (), (override));
    MOCK_METHOD((void), finalize, (), (override));
    MOCK_METHOD((std::vector<std::string>), listDBs, (const bool loaded), (override));
    MOCK_METHOD((base::OptError), deleteDB, (const std::string& name), (override));
    MOCK_METHOD((base::OptError), createDB, (const std::string& name), (override));
    MOCK_METHOD((base::OptError), createDB, (const std::string& name, const std::string& path), (override));
    MOCK_METHOD((base::OptError), loadDBFromJson, (const std::string& name, const json::Json& content), (override));
    MOCK_METHOD((bool), existsDB, (const std::string& name), (override));
    MOCK_METHOD((std::map<std::string, kvdbManager::RefInfo>), getKVDBScopesInfo, (), ());
    MOCK_METHOD((std::map<std::string, kvdbManager::RefInfo>), getKVDBHandlersInfo, (), (const));
    MOCK_METHOD((base::RespOrError<std::shared_ptr<kvdbManager::IKVDBHandler>>),
                getKVDBHandler,
                (const std::string& dbName, const std::string& scopeName),
                (override));
    MOCK_METHOD((uint32_t), getKVDBHandlersCount, (const std::string& dbName), (const));
};

} // namespace kvdb::mocks

#endif // _KVDB_MOCK_KVDB_MANAGER_HPP
