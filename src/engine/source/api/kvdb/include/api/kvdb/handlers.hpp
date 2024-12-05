#ifndef _API_KVDB_HANDLERS_HPP
#define _API_KVDB_HANDLERS_HPP

#include <memory>

#include <api/adapter/adapter.hpp>
#include <kvdb/ikvdbmanager.hpp>

namespace api::kvdb::handlers
{

const uint32_t DEFAULT_HANDLER_PAGE = 1;
const uint32_t DEFAULT_HANDLER_RECORDS = 50;

adapter::RouteHandler managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
adapter::RouteHandler managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
adapter::RouteHandler managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager);
adapter::RouteHandler managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                                  const std::string& kvdbScopeName);

adapter::RouteHandler dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
adapter::RouteHandler dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                               const std::string& kvdbScopeName);
adapter::RouteHandler dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName);
adapter::RouteHandler dbSearch(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                               const std::string& kvdbScopeName);

} // namespace api::kvdb::handlers

#endif // _API_KVDB_HANDLERS_HPP
