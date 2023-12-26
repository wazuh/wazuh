#ifndef _API_KVDB_HANDLERS_HPP
#define _API_KVDB_HANDLERS_HPP

#include <memory>

#include <api/api.hpp>
#include <kvdb/ikvdbmanager.hpp>

namespace api::kvdb::handlers
{

const uint32_t DEFAULT_HANDLER_PAGE = 1;
const uint32_t DEFAULT_HANDLER_RECORDS = 50;

api::HandlerSync managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::HandlerSync managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::HandlerSync managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
api::HandlerSync managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

api::HandlerSync dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
api::HandlerSync dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
api::HandlerSync dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
api::HandlerSync dbSearch(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);

void registerHandlers(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                      const std::string& kvdbScopeName,
                      std::shared_ptr<api::Api>);
} // namespace api::kvdb::handlers

#endif // _API_KVDB_HANDLERS_HPP
