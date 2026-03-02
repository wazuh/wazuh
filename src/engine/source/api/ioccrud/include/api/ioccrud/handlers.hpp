#ifndef _API_IOCCRUD_HANDLERS_HPP
#define _API_IOCCRUD_HANDLERS_HPP

#include <kvdbioc/iManager.hpp>
#include <scheduler/ischeduler.hpp>
#include <store/istore.hpp>

#include <api/adapter/adapter.hpp>

namespace api::ioccrud::handlers
{

adapter::RouteHandler syncIoc(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager,
                               const std::shared_ptr<scheduler::IScheduler>& scheduler,
                                 const std::shared_ptr<store::IStore>& store);

inline void registerHandlers(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager,
                             const std::shared_ptr<scheduler::IScheduler>& scheduler,
                             const std::shared_ptr<store::IStore>& store,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/content/ioc/update", syncIoc(kvdbManager, scheduler, store));
}

} // namespace api::ioccrud::handlers

#endif // _API_IOCCRUD_HANDLERS_HPP
