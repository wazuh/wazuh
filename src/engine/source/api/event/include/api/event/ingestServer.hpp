// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _API_EVENT_INGEST_SERVER_HPP
#define _API_EVENT_INGEST_SERVER_HPP

#include <cstddef>
#include <memory>

#include <agentcache/agentMetadataCache.hpp>
#include <dumper/idumper.hpp>
#include <httpsrv/server.hpp>
#include <router/iapi.hpp>

namespace api::event
{

/// Path of the enriched-events route.
constexpr auto INGEST_ROUTE = "/events/enriched";

/**
 * @brief Operator-tunable limits of the enriched-events ingest server.
 */
struct IngestLimits
{
    std::size_t maxBodyBytes {64U * 1024U * 1024U};      ///< analysisd.server_enriched_events_max_body_bytes
    std::size_t maxConnections {1024};                   ///< analysisd.server_enriched_events_max_connections
    std::size_t maxInFlightBytes {256U * 1024U * 1024U}; ///< analysisd.server_enriched_events_max_inflight_bytes
};

/**
 * @brief Checks the ingest limits; throws std::invalid_argument naming the setting that is out of range.
 *
 * Ranges: body 32 MiB to 1 GiB (at least remoted's default decoded-body cap, so its 413 stays the one
 * agents see); connections 16 to 65536; in-flight budget at least one maximum body and at most 8 GiB.
 *
 * @return The same limits, for chaining.
 */
IngestLimits validateIngestLimits(const IngestLimits& limits);

/**
 * @brief The ingest server's options for @p limits: its connection cap, byte budget and body cap, two I/O threads,
 * max(2, nproc/4) handlers with a queue as long as the connection cap, interim "100 Continue" answers, and
 * the settings that raise the budget and the connection cap named in the transport's 503 log lines.
 */
httpsrv::ServerOptions ingestServerOptions(const IngestLimits& limits);

/**
 * @brief Builds (without starting) the server for POST /events/enriched.
 *
 * The route is a Data route capped at limits.maxBodyBytes (a larger declared body is answered 413
 * before it is read); "Expect: 100-continue" is answered once a request is admitted. The transport
 * uses two I/O threads; the executor runs max(2, nproc/4) handlers with a queue as long as the connection cap.
 */
std::shared_ptr<httpsrv::Server> makeIngestServer(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                                  const std::shared_ptr<::dumper::IDumper>& dumper,
                                                  std::shared_ptr<agentcache::AgentMetadataCache> agentMetadataCache,
                                                  const IngestLimits& limits);

} // namespace api::event

#endif // _API_EVENT_INGEST_SERVER_HPP
