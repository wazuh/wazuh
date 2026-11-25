/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_STATEFUL_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_STATEFUL_ENDPOINT_HPP

#include "downstream/deferredForwarder.hpp" // DownstreamTarget, DownstreamError/DownstreamResponse, DeferredForwarder
#include "endpoint.hpp"                     // AuthenticatedHandler
#include "http_server/IHttpServer.hpp"      // HttpResponse

#include <chrono>
#include <string>

namespace remoted::endpoints::stateful
{

    /**
     * @brief Policy for the `POST /stateful` endpoint: inventory synchronization sessions.
     *
     * The body is the agent's FlatBuffer `Message{FullSession}` -- OPAQUE to remoted (never parsed
     * here); it is forwarded verbatim to modulesd's inventory sync server, which owns validation.
     * Unlike /stateless and /stats, the downstream result IS the session result, so postProcess()
     * passes the contract's status codes and bodies through instead of collapsing them.
     */

    /**
     * @brief The inventory-sync-server `POST /stateful` target reached over @p socketPath.
     *
     * Carries the authenticated agent id as `X-Wazuh-Agent-Id` (written by us from the identity the
     * gateway verified, never by the agent) -- the server cross-checks it against the FlatBuffer's
     * `Start.agentid` (403 on mismatch). @p responseTimeoutMs is the route's dedicated downstream
     * deadline (remoted.downstream_stateful_response_timeout): sessions are indexed and flushed
     * within the request, so it is deliberately longer than the global default.
     *
     * @p budgetMs is sent as `X-Wazuh-Response-Budget-Ms`: how long remoted will still listen for
     * the answer (see responseBudgetMs()). Like the agent id it is written by us, never relayed.
     */
    remoted::downstream::DownstreamTarget
    target(const std::string& socketPath, const std::string& agentId, int responseTimeoutMs, long long budgetMs);

    /**
     * @brief The HTTP server's request timeout, configured in seconds, as the millisecond cap
     * responseBudgetMs() expects. A non-positive timeout stays non-positive: no cap.
     */
    inline long long requestCapMs(int requestTimeoutSec)
    {
        return static_cast<long long>(requestTimeoutSec) * 1000;
    }

    /**
     * @brief How many milliseconds remoted will still listen for a `/stateful` answer.
     *
     * remoted stops listening at the earlier of two limits: its own response timer
     * (@p responseTimeoutMs, started when the request is forwarded) and the HTTP server's request
     * timeout (@p requestCapMs), which the server arms before the request reaches the worker pool.
     * Only the time since @p receivedAt -- stamped inside the worker, once auth begins -- is
     * discounted from that cap, so whatever the request waited in the pool queue is not, and the
     * result can overstate what is left when the cap governs. The result is the smaller remainder,
     * never below 1: the sync server uses it to avoid starting a session whose answer can no longer
     * be delivered, and a value of 0 or less would read as "no budget" rather than "almost none".
     *
     * @p requestCapMs <= 0 means the route has no request-timeout cap, so only the response timer
     * applies. A default (unstamped) @p receivedAt contributes no elapsed time.
     */
    long long responseBudgetMs(int responseTimeoutMs,
                               long long requestCapMs,
                               std::chrono::steady_clock::time_point receivedAt,
                               std::chrono::steady_clock::time_point now);

    /**
     * @brief Map the downstream result to the agent response: passthrough of the sync contract.
     *
     * The server's status codes and bodies ARE the agent contract (D2 -- 200 ok/noop, 400, 403
     * identity, 409 checksum mismatch, 413 over budget, 500 scan/apply failed, 503 not
     * ready/capacity), so those pass through verbatim -- the bodies are produced by the manager's
     * own server, never echoed agent input, which is what makes reflecting them safe. Of the
     * downstream headers only `Retry-After` is forwarded (on 503, digits-only), because it is the
     * one header in the contract; reflecting arbitrary downstream headers stays off the table.
     * Transport failures (send error / timeout / bad HTTP) and any status outside the contract
     * collapse to a neutral 503 (the agent retries). The response-timeout 503 alone carries its own
     * `Retry-After` (@p retryAfterSec, 0 for none): the sync server is still applying the session
     * after remoted stopped waiting, and without the delay the agent's re-send runs the same
     * session a second time against the first copy. Every other failure means nothing is running
     * downstream, so an immediate re-send is right.
     */
    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response,
                                            int retryAfterSec = 0);

    /**
     * @brief Builds the `/stateful` AuthenticatedHandler: reject empty bodies, then forward.
     *
     * No payload identity check here (unlike /stateless): the body is an opaque FlatBuffer and
     * parsing it is the sync server's job -- identity is enforced downstream against the
     * `X-Wazuh-Agent-Id` header target() injects (doc 05 §3). The only local check is non-emptiness:
     * an empty body cannot be a FullSession, and rejecting it saves a deferred-work slot and a UDS
     * round trip.
     *
     * @warning The returned handler stores a reference to @p forwarder. The caller must guarantee
     * forwarder outlives every route registered with it -- i.e. the HTTP server (which owns the route
     * table holding this handler) must be stopped/destroyed before forwarder is destroyed.
     * RemotedModuleFacade::stop() already orders teardown this way.
     *
     * @param retryAfterSec `Retry-After` of the 503 answered on the response timeout
     * (remoted.downstream_stateful_retry_after); 0 sends none.
     * @param metrics This endpoint's remoted.http.stateful.* metric set, or null for none. Must
     * point at storage that outlives the handler (a facade value member -- see
     * DownstreamTarget::httpMetrics). The handler counts its own empty-body 400 and hands the
     * pointer to the forwarder, which counts every delivered status and observes latency.
     * @param requestCapMs The HTTP server's request timeout in milliseconds, used to discount the
     * time already spent since the request was received from the forwarded response budget;
     * 0 means no cap. Deliberately without a default: a caller that forgot it would silently
     * forward an overstated budget.
     */
    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                                                         std::string socketPath,
                                                         int responseTimeoutMs,
                                                         int retryAfterSec,
                                                         const remoted::metrics::EndpointHttpMetrics* metrics,
                                                         long long requestCapMs);

} // namespace remoted::endpoints::stateful

#endif // _REMOTED_ENDPOINTS_STATEFUL_ENDPOINT_HPP
