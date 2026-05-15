#pragma once

#include "container_connector.h"
#include "container_connector_impl.hpp"

#include <memory>
#include <mutex>

#ifdef _WIN32
#  ifdef WIN_EXPORT
#    define EXPORTED __declspec(dllexport)
#  else
#    define EXPORTED __declspec(dllimport)
#  endif
#elif __GNUC__ >= 4
#  define EXPORTED __attribute__((visibility("default")))
#else
#  define EXPORTED
#endif

namespace wazuh::container_connector {

/// @brief Façade singleton — the single entry point invoked by the C glue.
///
/// Holds a unique_ptr to ContainerConnectorImpl which is the real owner of
/// every runtime resource. The singleton exists only because the C API needs
/// an anchor; the impl itself is a regular object created on Init() and
/// destroyed by Stop(). Re-Init() after Stop() is allowed.
///
/// All public methods are thread-safe under a coarse mutex. The mutex never
/// covers a blocking operation: it only guards the impl pointer mutation;
/// the actual work happens inside the impl which has its own concurrency.
class EXPORTED ContainerConnector final
{
public:
    static ContainerConnector& Instance();

    void Init(ModuleConfig config, LogCallback log);
    void Start();
    void Stop();
    void WaitForShutdown();

private:
    ContainerConnector() = default;
    ~ContainerConnector() = default;

    ContainerConnector(const ContainerConnector&)            = delete;
    ContainerConnector& operator=(const ContainerConnector&) = delete;

    std::mutex                              mutex_;
    std::unique_ptr<ContainerConnectorImpl> impl_;
};

} // namespace wazuh::container_connector
