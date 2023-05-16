#ifndef _API_KVDB_HANDLERS_HPP
#define _API_KVDB_HANDLERS_HPP

#include <memory>

#include <api/api.hpp>
// TODO: KVDB: remove when refactor ut
#include <kvdb/kvdbManager.hpp>
#include <kvdb2/iKVDBManager.hpp>

namespace api::kvdb::handlers
{

// New commands
api::Handler managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::Handler managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::Handler managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::Handler managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

api::Handler dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);
api::Handler dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);
api::Handler dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope);

void registerHandlers(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope, std::shared_ptr<api::Api>);
} // namespace api::kvdb::handlers

#endif // _API_KVDB_HANDLERS_HPP
