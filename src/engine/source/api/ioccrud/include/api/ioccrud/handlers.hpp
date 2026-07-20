#ifndef API_IOCCRUD_HANDLERS_HPP
#define API_IOCCRUD_HANDLERS_HPP

#include <atomic>
#include <memory>
#include <string_view>

#include <iockvdb/iManager.hpp>
#include <scheduler/ischeduler.hpp>
#include <store/istore.hpp>

#include <api/adapter/adapter.hpp>

namespace api::ioccrud::handlers
{

adapter::RouteHandler syncIoc(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbManager,
                              const std::shared_ptr<scheduler::IScheduler>& scheduler,
                              const std::shared_ptr<store::IStore>& store);

adapter::RouteHandler getIocState(const std::shared_ptr<store::IStore>& store);

// Internal implementation details exposed for testing
namespace detail
{
extern std::atomic<bool> g_syncInProgress;
extern const base::Name IOC_STATUS_DOC;

void performIOCSync(const std::weak_ptr<ioc::kvdb::IKVDBManager>& weakKvdbManager,
                    const std::weak_ptr<store::IStore>& weakStore,
                    const std::string& filePath,
                    const std::string& fileHash);
} // namespace detail

inline void registerHandlers(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbManager,
                             const std::shared_ptr<scheduler::IScheduler>& scheduler,
                             const std::shared_ptr<store::IStore>& store,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/content/ioc/update", syncIoc(kvdbManager, scheduler, store));
    server->addRoute(httpsrv::Method::GET, "/content/ioc/state", getIocState(store));
}

} // namespace api::ioccrud::handlers

#endif // API_IOCCRUD_HANDLERS_HPP
