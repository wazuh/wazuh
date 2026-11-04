// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _HTTPSRV_APISERVER_HPP
#define _HTTPSRV_APISERVER_HPP

#include <cstddef>
#include <memory>
#include <string>

#include <httpsrv/irouteregistrar.hpp>
#include <httpsrv/server.hpp>

namespace httpsrv
{

/// Body cap of the API's liveness routes (GET /status): their requests are a few bytes, if any.
constexpr std::size_t API_LIVENESS_BODY_CAP {4096};

/**
 * @brief The documented 413 text of the engine API for a body over @p maxBytes.
 *
 * "Payload too large. Max allowed: <n> bytes (<n/1024> KiB)."; "Payload too large." when @p maxBytes is 0.
 */
std::string payloadTooLargeText(std::size_t maxBytes);

/// Seconds the API waits for a request body before answering 400, as it did on cpp-httplib.
constexpr std::size_t API_BODY_TIMEOUT_SEC {10};

/// Fewest API request workers. A tester or logtest request holds its worker until the single tester worker
/// answers, up to analysisd.server_api_timeout, so a few concurrent tests must not hold every worker.
constexpr std::size_t API_MIN_WORKERS {4};
/// Most API request workers: the ceiling of the cpp-httplib pool the API used to run on.
constexpr std::size_t API_MAX_WORKERS {16};

/**
 * @brief The API's request workers for @p cpus processors: one fewer than the processors, as the
 * cpp-httplib pool the API used to run on, clamped to [API_MIN_WORKERS, API_MAX_WORKERS].
 */
std::size_t apiWorkerCount(unsigned int cpus);

/**
 * @brief The engine API server's options: apiWorkerCount() request workers with a 64-request queue, no
 * in-flight byte budget (no API route charges it, so the request body is bounded only by the route caps),
 * interim "100 Continue" answers, and a body that does not arrive within API_BODY_TIMEOUT_SEC answered 400.
 */
ServerOptions apiServerOptions();

/**
 * @brief Builds the engine API server from apiServerOptions(), with its stats published as server.api.*
 * metrics.
 */
std::shared_ptr<Server> makeApiServer();

/**
 * @brief Registers the API modules' routes on the API server with the API's body limits.
 *
 * A Control route that does not set its own cap gets the configured payload limit (0: none) and, when capped,
 * the documented 413 text; a Liveness route is capped at API_LIVENESS_BODY_CAP with the same text.
 */
class ApiRouteRegistrar : public IRouteRegistrar
{
public:
    /**
     * @param server The API server the routes go to.
     * @param payloadMaxBytes analysisd.server_api_payload_max_bytes; 0 means unlimited.
     */
    ApiRouteRegistrar(std::shared_ptr<Server> server, std::size_t payloadMaxBytes);

    void addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options = {}) override;

private:
    std::shared_ptr<Server> m_server;
    std::size_t m_payloadMaxBytes;
};

} // namespace httpsrv

#endif // _HTTPSRV_APISERVER_HPP
