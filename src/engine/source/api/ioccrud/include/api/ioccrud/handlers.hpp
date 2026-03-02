#ifndef _API_IOCCRUD_HANDLERS_HPP
#define _API_IOCCRUD_HANDLERS_HPP

#include <kvdbioc/iManager.hpp>

#include <api/adapter/adapter.hpp>

namespace api::ioccrud::handlers
{

adapter::RouteHandler syncIoc(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager);

inline void registerHandlers(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/content/ioc/update", syncIoc(kvdbManager));
}

} // namespace api::ioccrud::handlers

#endif // _API_IOCCRUD_HANDLERS_HPP
