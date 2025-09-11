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

inline void registerHandlers(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/kvdb/manager/get", managerGet(kvdbManager));
    server->addRoute(httpsrv::Method::POST, "/kvdb/manager/post", managerPost(kvdbManager));
    server->addRoute(httpsrv::Method::POST, "/kvdb/manager/delete", managerDelete(kvdbManager));
    server->addRoute(httpsrv::Method::POST, "/kvdb/manager/dump", managerDump(kvdbManager, "kvdb"));

    server->addRoute(httpsrv::Method::POST, "/kvdb/db/get", dbGet(kvdbManager, "kvdb"));
    server->addRoute(httpsrv::Method::POST, "/kvdb/db/delete", dbDelete(kvdbManager, "kvdb"));
    server->addRoute(httpsrv::Method::POST, "/kvdb/db/put", dbPut(kvdbManager, "kvdb"));
    server->addRoute(httpsrv::Method::POST, "/kvdb/db/search", dbSearch(kvdbManager, "kvdb"));
}

} // namespace api::kvdb::handlers

#endif // _API_KVDB_HANDLERS_HPP
