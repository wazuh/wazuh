#ifndef API_IOCCRUD_HANDLERS_HPP
#define API_IOCCRUD_HANDLERS_HPP

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <string_view>

#include <iockvdb/iManager.hpp>
#include <scheduler/ischeduler.hpp>
#include <store/istore.hpp>

#include <api/adapter/adapter.hpp>

namespace api::ioccrud::handlers
{

/**
 * @brief Handler for POST /content/ioc/update
 *
 * @param inputRoot Directory the requested file must live in. Any path that does not resolve to a regular file
 * inside it is rejected.
 */
adapter::RouteHandler syncIoc(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbManager,
                              const std::shared_ptr<scheduler::IScheduler>& scheduler,
                              const std::shared_ptr<store::IStore>& store,
                              const std::filesystem::path& inputRoot);

adapter::RouteHandler getIocState(const std::shared_ptr<store::IStore>& store);

// Internal implementation details exposed for testing
namespace detail
{
extern std::atomic<bool> g_syncInProgress;
extern const base::Name IOC_STATUS_DOC;

/**
 * @brief Resolve a requested path and confine it to the input root
 *
 * Both paths are resolved with every symlink followed, the result must be strictly inside the root
 * (compared component by component) and must be a regular file.
 *
 * @return The resolved path, or std::nullopt when the request is rejected
 */
std::optional<std::filesystem::path> resolveInputFile(const std::filesystem::path& inputRoot,
                                                      const std::string& requestedPath);

void performIOCSync(const std::weak_ptr<ioc::kvdb::IKVDBManager>& weakKvdbManager,
                    const std::weak_ptr<store::IStore>& weakStore,
                    const std::string& filePath,
                    const std::string& fileHash);
} // namespace detail

inline void registerHandlers(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbManager,
                             const std::shared_ptr<scheduler::IScheduler>& scheduler,
                             const std::shared_ptr<store::IStore>& store,
                             const std::shared_ptr<httpsrv::Server>& server,
                             const std::filesystem::path& inputRoot)
{
    server->addRoute(httpsrv::Method::POST, "/content/ioc/update", syncIoc(kvdbManager, scheduler, store, inputRoot));
    server->addRoute(httpsrv::Method::GET, "/content/ioc/state", getIocState(store));
}

} // namespace api::ioccrud::handlers

#endif // API_IOCCRUD_HANDLERS_HPP
