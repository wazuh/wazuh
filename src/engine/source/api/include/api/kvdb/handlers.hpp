#ifndef _API_KVDB_HANDLERS_HPP
#define _API_KVDB_HANDLERS_HPP

#include <memory>

#include <api/api.hpp>
#include <kvdb/iKVDBManager.hpp>

namespace api::kvdb::handlers
{

const uint32_t DEFAULT_HANDLER_PAGE = 1;
const uint32_t DEFAULT_HANDLER_RECORDS = 50;

api::Handler managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::Handler managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::Handler managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::Handler managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

api::Handler dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
api::Handler dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
api::Handler dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
api::Handler dbSearch(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

void registerHandlers(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                      const std::string& kvdbScopeName,
                      std::shared_ptr<api::Api>);
} // namespace api::kvdb::handlers

#endif // _API_KVDB_HANDLERS_HPP
