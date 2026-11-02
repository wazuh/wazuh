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

/// Body cap of the API's liveness routes (/status, /metrics/*): their requests are a few bytes of JSON.
constexpr std::size_t API_LIVENESS_BODY_CAP {4096};

/**
 * @brief The documented 413 text of the engine API for a body over @p maxBytes.
 *
 * "Payload too large. Max allowed: <n> bytes (<n/1024> KiB)."; "Payload too large." when @p maxBytes is 0.
 */
std::string payloadTooLargeText(std::size_t maxBytes);

/**
 * @brief Builds the engine API server: 4 request workers with a 64-request queue, no in-flight byte budget
 * (no API route charges it, so the request body is bounded only by the route caps), interim
 * "100 Continue" answers, and its stats published as server.api.* metrics.
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
