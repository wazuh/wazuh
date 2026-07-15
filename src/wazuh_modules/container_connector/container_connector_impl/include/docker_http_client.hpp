#pragma once

#include "container_connector_impl.hpp"
#include "stop_controller.hpp"

#include <functional>
#include <memory>
#include <string>

namespace wazuh::container_connector {

/// @brief Minimal HTTP/1.1 client over the Docker Unix-domain socket.
///
/// Get() performs a one-shot request and returns the full response body.
/// StreamGet() opens a long-lived connection and calls the callback for each
/// newline-delimited JSON event line (Docker GET /events). Both modes handle
/// chunked transfer encoding transparently via an inline decoder.
class DockerHttpClient
{
public:
    DockerHttpClient(std::string socket_path, LogCallback log);

    /// One-shot GET. Returns response body or throws on HTTP error / connection failure.
    std::string Get(const std::string& path);

    /// Streaming GET. Calls on_line for each '\n'-terminated event, until stop is
    /// signaled, on_line returns false, or the connection drops.
    void StreamGet(const std::string&                              path,
                   const std::function<bool(const std::string&)>& on_line,
                   const std::shared_ptr<StopController>&          stop);

private:
    int  Connect() const;
    void SendRequest(int fd, const std::string& path) const;
    void Log(int level, const std::string& msg) const;

    std::string socket_path_;
    LogCallback log_;
};

} // namespace wazuh::container_connector
