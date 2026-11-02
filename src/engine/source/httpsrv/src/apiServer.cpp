// SPDX-License-Identifier: AGPL-3.0-or-later
#include <httpsrv/apiServer.hpp>

#include <utility>

#include <fmt/format.h>

namespace httpsrv
{

std::string payloadTooLargeText(std::size_t maxBytes)
{
    if (maxBytes == 0)
    {
        return "Payload too large.";
    }
    return fmt::format("Payload too large. Max allowed: {} bytes ({} KiB).", maxBytes, maxBytes / 1024);
}

std::shared_ptr<UdsServer> makeApiServer()
{
    UdsServerOptions options;
    options.name = "API services";
    options.logTag = "wazuh-manager-analysisd:api-server";
    options.byteBudget = false;
    options.executorThreads = 4;
    options.executorQueue = 64;
    options.expectContinue = true;
    options.detailedLogging = true;

    auto server = std::make_shared<UdsServer>(std::move(options));
    registerMetrics(server, "api");
    return server;
}

ApiRouteRegistrar::ApiRouteRegistrar(std::shared_ptr<UdsServer> server, std::size_t payloadMaxBytes)
    : m_server {std::move(server)}
    , m_payloadMaxBytes {payloadMaxBytes}
{
}

void ApiRouteRegistrar::addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options)
{
    if (options.maxBodyBytes == 0)
    {
        switch (options.cls)
        {
            case RouteClass::Liveness: options.maxBodyBytes = API_LIVENESS_BODY_CAP; break;
            case RouteClass::Control:
                options.maxBodyBytes = m_payloadMaxBytes == 0 ? UNLIMITED_BODY : m_payloadMaxBytes;
                break;
            default: break;
        }
    }
    if (options.maxBodyBytes != 0 && options.maxBodyBytes != UNLIMITED_BODY && options.payloadTooLargeBody.empty())
    {
        options.payloadTooLargeBody = payloadTooLargeText(options.maxBodyBytes);
        options.payloadTooLargeContentType = "text/plain";
    }
    m_server->addRoute(method, path, std::move(handler), std::move(options));
}

} // namespace httpsrv
