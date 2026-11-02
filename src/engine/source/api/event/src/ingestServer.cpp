// SPDX-License-Identifier: AGPL-3.0-or-later
#include <api/event/ingestServer.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>

#include <api/event/handlers.hpp>
#include <proc.hpp>

namespace api::event
{
namespace
{
constexpr std::size_t MIB {1024U * 1024U};
constexpr std::size_t MIN_BODY_BYTES {32U * MIB};
constexpr std::size_t MAX_BODY_BYTES {1024U * MIB};
constexpr std::size_t MIN_CONNECTIONS {16};
constexpr std::size_t MAX_CONNECTIONS {65536};
constexpr std::uint64_t MAX_INFLIGHT_BYTES {std::uint64_t {8} * 1024U * MIB};

[[noreturn]] void outOfRange(const char* key, std::size_t value, const std::string& range)
{
    throw std::invalid_argument {std::string {key} + " is " + std::to_string(value) + "; it must be " + range};
}
} // namespace

IngestLimits validateIngestLimits(const IngestLimits& limits)
{
    if (limits.maxBodyBytes < MIN_BODY_BYTES || limits.maxBodyBytes > MAX_BODY_BYTES)
    {
        outOfRange("analysisd.server_enriched_events_max_body_bytes",
                   limits.maxBodyBytes,
                   "between " + std::to_string(MIN_BODY_BYTES) + " and " + std::to_string(MAX_BODY_BYTES));
    }
    if (limits.maxConnections < MIN_CONNECTIONS || limits.maxConnections > MAX_CONNECTIONS)
    {
        outOfRange("analysisd.server_enriched_events_max_connections",
                   limits.maxConnections,
                   "between " + std::to_string(MIN_CONNECTIONS) + " and " + std::to_string(MAX_CONNECTIONS));
    }
    if (limits.maxInFlightBytes < limits.maxBodyBytes
        || static_cast<std::uint64_t>(limits.maxInFlightBytes) > MAX_INFLIGHT_BYTES)
    {
        outOfRange("analysisd.server_enriched_events_max_inflight_bytes",
                   limits.maxInFlightBytes,
                   "at least analysisd.server_enriched_events_max_body_bytes (" + std::to_string(limits.maxBodyBytes)
                       + ") and at most " + std::to_string(MAX_INFLIGHT_BYTES));
    }
    return limits;
}

httpsrv::ServerOptions ingestServerOptions(const IngestLimits& limits)
{
    httpsrv::ServerOptions options;
    options.name = "Event ingest";
    options.logTag = "wazuh-manager-analysisd:ingest-server";
    options.maxConnections = limits.maxConnections;
    options.maxInFlightBytes = limits.maxInFlightBytes;
    options.maxBodySize = limits.maxBodyBytes;
    options.ioThreads = 2;
    options.executorThreads = std::max<std::size_t>(2, cpp_get_nproc() / 4);
    options.executorQueue = limits.maxConnections;
    options.expectContinue = true;
    options.budgetOptionHint = "analysisd.server_enriched_events_max_inflight_bytes";
    options.connectionCapOptionHint = "analysisd.server_enriched_events_max_connections";
    return options;
}

std::shared_ptr<httpsrv::Server> makeIngestServer(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                                  const std::shared_ptr<::dumper::IDumper>& dumper,
                                                  std::shared_ptr<agentcache::AgentMetadataCache> agentMetadataCache,
                                                  const IngestLimits& limits)
{
    auto server = std::make_shared<httpsrv::Server>(ingestServerOptions(limits));
    httpsrv::RouteOptions route;
    route.cls = httpsrv::RouteClass::Data;
    route.maxBodyBytes = limits.maxBodyBytes;
    server->addRoute(httpsrv::Method::POST,
                     INGEST_ROUTE,
                     handlers::pushEvent(orchestrator, dumper, std::move(agentMetadataCache)),
                     route);
    httpsrv::registerMetrics(server, "ingest");
    return server;
}

} // namespace api::event
