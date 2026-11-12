/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "query/query.hpp"

#include "query/engine.hpp"
#include "query/pit.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "health/nodeSet.hpp"
#include "indexer_client/runtime.hpp"
#include "query/queryResponse.hpp"
#include "runtime/backoff.hpp"
#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"
#include "transport/transport.hpp"
#include "write/response.hpp"

// The query engine (stage E4a). NORMATIVE contract: query.hpp (I87 execution, clocks, verdicts, wake-up; I88 routes).

namespace indexer_client::detail::query
{
    namespace
    {
        std::atomic<std::uint64_t> g_requests {0};
        std::atomic<std::uint64_t> g_failovers {0};
        std::atomic<std::uint64_t> g_throttles {0};
        std::atomic<std::uint64_t> g_unavailable {0};
        std::atomic<std::uint64_t> g_tooLarge {0};
        std::atomic<std::uint64_t> g_conflictRetries {0};
        /// D48 (metrics.hpp QUERIES): body bytes of the HttpResults delivered to the engine and not yet returned.
        std::atomic<std::uint64_t> g_responseBytesInFlight {0};
        std::atomic<std::uint64_t> g_peakResponseBytesInFlight {0};

        /// Holds `bytes` in responseBytesInFlight (and raises its peak) for the life of one delivered HttpResult.
        class ResponseBytesInFlight final
        {
        public:
            explicit ResponseBytesInFlight(std::uint64_t bytes) noexcept
                : m_bytes(bytes)
            {
                const auto now = g_responseBytesInFlight.fetch_add(m_bytes, std::memory_order_relaxed) + m_bytes;
                auto peak = g_peakResponseBytesInFlight.load(std::memory_order_relaxed);
                while (now > peak &&
                       !g_peakResponseBytesInFlight.compare_exchange_weak(peak, now, std::memory_order_relaxed))
                {
                }
            }
            ~ResponseBytesInFlight()
            {
                g_responseBytesInFlight.fetch_sub(m_bytes, std::memory_order_relaxed);
            }
            ResponseBytesInFlight(const ResponseBytesInFlight&) = delete;
            ResponseBytesInFlight& operator=(const ResponseBytesInFlight&) = delete;

        private:
            const std::uint64_t m_bytes;
        };

        TimePoint now()
        {
            return std::chrono::steady_clock::now();
        }

        /// `from + span`, saturated at TimePoint::max().
        TimePoint addSaturated(TimePoint from, Duration span)
        {
            const auto room = std::chrono::duration_cast<Duration>(TimePoint::max() - from);
            return span >= room ? TimePoint::max() : from + span;
        }

        std::string bounded(std::string text)
        {
            if (text.size() > OpResult::MAX_REASON)
            {
                text.resize(OpResult::MAX_REASON);
            }
            return text;
        }

        template<class T>
        Outcome<T> fail(Cause cause, std::string reason, int status = 0)
        {
            return Outcome<T>::failure(cause, bounded(std::move(reason)), status);
        }

        template<class T, class U>
        Outcome<T> failFrom(const Outcome<U>& other)
        {
            auto out = Outcome<T>::failure(other.cause, other.reason, other.httpStatus);
            out.responseTooLarge = other.responseTooLarge;
            return out;
        }

        /// The state of one attempt, shared with the transport callback (which may land after the engine returned).
        /// `result` and `abandoned` are written and read under the gate's mutex.
        struct AttemptState final
        {
            std::optional<HttpResult> result;
            bool abandoned {false}; ///< The engine stopped waiting: the callback delivers the result as Late (E4b).
        };

        /// The last failure seen, for "deadline expired, last cause: ..." and RetryExhausted.
        struct LastCause final
        {
            Cause cause {Cause::None};
            int status {0};
            std::string text;

            void set(Cause c, int httpStatus, const std::string& reason)
            {
                cause = c;
                status = httpStatus;
                text = toString(c);
                if (!reason.empty())
                {
                    text += ": " + reason;
                }
            }
        };

        /// One I82 series: its attempts, its 429 count (the throttle exponent) and the time of its first attempt.
        struct Series final
        {
            std::uint32_t attempts {0};
            std::uint32_t throttles {0};
            std::optional<TimePoint> start;
        };

        /// v1 isSafeIndexName, plus: no name made only of dots ("." and ".." are path segments libcurl collapses, so
        /// the request would reach "/_search" or "/_delete_by_query" of every index) and none starting with '_' (an
        /// OpenSearch endpoint or "_all").
        bool safeIndex(std::string_view index)
        {
            if (index.empty() || index.front() == '_' || index.find_first_not_of('.') == std::string_view::npos)
            {
                return false;
            }
            return std::all_of(index.begin(),
                               index.end(),
                               [](char c)
                               {
                                   return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                          c == '_' || c == '.' || c == '*' || c == '-';
                               });
        }

        std::optional<std::string> invalidOptions(const QueryOptions& options)
        {
            if (options.retry.base <= Duration::zero())
            {
                return std::string("retry.base: must be > 0");
            }
            if (options.retry.cap < options.retry.base)
            {
                return std::string("retry.cap: must be >= retry.base");
            }
            if (!(options.retry.jitter >= 0.0 && options.retry.jitter <= 1.0)) // Also rejects NaN.
            {
                return std::string("retry.jitter: must be in [0, 1]");
            }
            if (options.retry.maxAttempts && *options.retry.maxAttempts == 0)
            {
                return std::string("retry.maxAttempts: must be > 0 (or unset for unlimited)");
            }
            if (options.retry.maxDuration && *options.retry.maxDuration <= Duration::zero())
            {
                return std::string("retry.maxDuration: must be > 0 (or unset for unlimited)");
            }
            if (options.pageDeadline <= Duration::zero())
            {
                return std::string("pageDeadline: must be > 0");
            }
            return std::nullopt;
        }

        std::optional<std::string> invalidIndex(std::string_view index, const std::string& field)
        {
            if (!safeIndex(index))
            {
                return field +
                       ": must be non-empty, only [A-Za-z0-9_.*-], not only dots, not starting with '_', got '" +
                       std::string(index.substr(0, 64)) + "'";
            }
            return std::nullopt;
        }

        std::optional<std::string> invalidIndices(const std::vector<std::string>& indices)
        {
            if (indices.empty())
            {
                return std::string("indices: must not be empty");
            }
            for (std::size_t i = 0; i < indices.size(); ++i)
            {
                if (auto why = invalidIndex(indices[i], "indices[" + std::to_string(i) + "]"))
                {
                    return why;
                }
            }
            return std::nullopt;
        }

        std::string joined(const std::vector<std::string>& indices)
        {
            std::string out;
            for (const auto& index : indices)
            {
                if (!out.empty())
                {
                    out += ',';
                }
                out += index;
            }
            return out;
        }

        /// "/<indices><route>[?p1&p2...]"; without indices, "<route>[?...]" (route starts with '/'; E4b's PIT routes).
        std::string
        targetImpl(const std::string& indices, std::string_view route, const std::vector<std::string>& params)
        {
            std::string out = indices.empty() ? std::string(route) : "/" + indices + std::string(route);
            for (std::size_t i = 0; i < params.size(); ++i)
            {
                out += (i == 0 ? '?' : '&');
                out += params[i];
            }
            return out;
        }

        std::string baseUrl(std::string host)
        {
            while (!host.empty() && host.back() == '/')
            {
                host.pop_back();
            }
            return host;
        }

        /// ClientClosed or Shutdown when the call must stop now (the gate is stopping, the client closed).
        std::optional<Cause> closing(const ClientState& client, QueryGate& gate)
        {
            {
                std::lock_guard<std::mutex> lock(gate.mutex);
                if (gate.stopping)
                {
                    return Cause::Shutdown;
                }
            }
            if (client.closeRequested.load())
            {
                return Cause::ClientClosed;
            }
            return std::nullopt;
        }

        Outcome<QueryResponse> closedOutcome(Cause cause)
        {
            return fail<QueryResponse>(
                cause, cause == Cause::Shutdown ? "the runtime is shutting down" : "the client was closed");
        }

        /// Sleeps on the gate until `until`, a close of the client or the gate stopping (whatever comes first).
        void sleepOnGate(const ClientState& client, QueryGate& gate, TimePoint until)
        {
            std::unique_lock<std::mutex> lock(gate.mutex);
            gate.cv.wait_until(lock, until, [&] { return gate.stopping || client.closeRequested.load(); });
        }

        void cancelAttempt(const ClientState& client, std::uint64_t id)
        {
            if (auto transport = runtimeTransport(client.runtime, client.epoch))
            {
                transport->cancel(id); // Resolves Cancelled, never node-attributable; the callback lands later.
            }
        }

        bool exhausted(const RetryPolicy& retry, const Series& series, TimePoint at)
        {
            const bool attemptsSpent = retry.maxAttempts && series.attempts >= *retry.maxAttempts;
            const bool durationSpent = retry.maxDuration && series.start && at - *series.start >= *retry.maxDuration;
            return attemptsSpent || durationSpent;
        }

        Duration conflictDelay(std::uint32_t conflicts)
        {
            RetryPolicy policy;
            const auto seam = seams::queryConflictBaseMs();
            policy.base = seam ? Duration {std::max<std::int64_t>(*seam, 0)} : CONFLICT_BASE;
            policy.cap = std::max(CONFLICT_CAP, policy.base);
            policy.jitter = 0.0;
            return backoffDelay(policy, conflicts, 0.0);
        }

        /// The I87 loop of one page: attempts, the three clocks, the I82 verdicts and the I86 conflict budget.
        /// Reusable by E4b (PIT create, delete and search build their RouteSpec and classifier).
        Outcome<QueryResponse> executeImpl(const std::shared_ptr<ClientState>& client,
                                           const QueryOptions& options,
                                           Deadline deadline,
                                           const RouteSpec& route,
                                           const Classifier& classify,
                                           const EngineHooks& hooks)
        {
            auto& gate = *client->queryGate;
            const auto& retry = options.retry;
            // The page's clock starts at its first attempt (I87): until then only the Deadline bounds the call.
            std::optional<TimePoint> pageEnd;
            TimePoint limit = deadline;
            const Duration fullBudget = std::min(client->requestTimeout, options.pageDeadline);

            Series series;
            std::uint32_t conflicts = 0;
            LastCause last;
            std::uint64_t attemptNo = 0;

            // E4b hooks (engine.hpp): the observer sees every admitted attempt once; never called under the gate.
            const auto notify = [&](AttemptEvent::Kind kind, const HttpResult* result)
            {
                if (hooks.observer)
                {
                    AttemptEvent event;
                    event.kind = kind;
                    event.attempt = attemptNo;
                    event.result = result;
                    hooks.observer(event);
                }
            };

            const auto expired = [&]() -> Outcome<QueryResponse>
            {
                g_unavailable.fetch_add(1, std::memory_order_relaxed);
                const bool pageFirst = pageEnd && *pageEnd < deadline;
                return fail<QueryResponse>(Cause::Unavailable,
                                           std::string(pageFirst ? "page deadline expired" : "deadline expired") +
                                               ", last cause: " + (last.text.empty() ? "none" : last.text),
                                           last.status);
            };
            const auto retriesExhausted = [&]()
            {
                return fail<QueryResponse>(Cause::RetryExhausted,
                                           "retries exhausted after " + std::to_string(series.attempts) +
                                               " attempts, last cause: " + last.text,
                                           last.status);
            };
            // retry.maxDuration bounds the series from its first attempt: no attempt starts at or past this end, and no
            // backoff is slept that would end there (the 5.0 connector checked `now + nextDelay` against its budget
            // before sleeping, too); the wait is useless, so the call ends RetryExhausted at once instead.
            const auto seriesEnd = [&]() -> std::optional<TimePoint>
            {
                if (!retry.maxDuration || !series.start)
                {
                    return std::nullopt;
                }
                return addSaturated(*series.start, *retry.maxDuration);
            };
            const auto backoffPastBudget = [&](TimePoint at, Duration wait)
            {
                const auto end = seriesEnd();
                return end && addSaturated(at, wait) >= *end;
            };

            for (;;)
            {
                if (const auto cause = closing(*client, gate))
                {
                    return closedOutcome(*cause);
                }
                // Before every send, also after a wait for a usable node (and before preAttempt takes a PIT slot).
                if (const auto end = seriesEnd(); end && now() >= *end)
                {
                    return retriesExhausted();
                }
                if (hooks.preAttempt)
                {
                    if (auto abort = hooks.preAttempt())
                    {
                        return fail<QueryResponse>(abort->cause, std::move(abort->reason));
                    }
                }
                const TimePoint start = now();
                if (start >= limit)
                {
                    return expired();
                }

                // One attempt: the transport and the node set of this epoch, held for the submit only.
                auto nodes = runtimeNodeSet(client->runtime, client->epoch);
                auto transport = runtimeTransport(client->runtime, client->epoch);
                if (!nodes || !transport)
                {
                    return closedOutcome(Cause::Shutdown);
                }
                const auto node = nodes->choose();
                if (!node)
                {
                    if (last.text.empty())
                    {
                        last.set(Cause::Unavailable, 0, "no usable node");
                    }
                    // I109: a node parked by a 429 Retry-After (not Down) ends this wait when its notBefore passes;
                    // without one the poll is today's. Either way `limit` bounds it (pageEnd is not set yet).
                    const auto parked = nodes->earliestNotBefore();
                    nodes.reset();
                    transport.reset();
                    const Duration wait = std::max(NO_NODE_WAIT_FLOOR, std::min(retry.base, client->probeInterval));
                    auto until = std::min(addSaturated(start, wait), limit);
                    if (parked)
                    {
                        until = std::min(until, *parked);
                    }
                    if (const auto end = seriesEnd())
                    {
                        until = std::min(until, *end); // Wakes for the RetryExhausted at the loop's top.
                    }
                    sleepOnGate(*client, gate, until);
                    continue;
                }

                HttpRequest request;
                request.method = route.method;
                request.url = baseUrl(nodes->host(*node)) + route.target;
                request.body = route.body;
                if (!pageEnd)
                {
                    pageEnd = addSaturated(start, options.pageDeadline);
                    limit = std::min(deadline, *pageEnd);
                }
                const auto pageLeft = std::chrono::ceil<Duration>(*pageEnd - start);
                request.timeout = std::max(Duration {1}, std::min(client->requestTimeout, pageLeft));
                // Node-attributable only when the attempt had the whole per-attempt budget: always the page's first
                // attempt; a later one whose budget the page cut short is not.
                const bool configuredTimeout = request.timeout == fullBudget;

                auto attempt = std::make_shared<AttemptState>();
                auto gateRef = client->queryGate;
                const std::uint64_t thisAttempt = attemptNo + 1;
                // The observer is copied into the callback: a Late result may land after execute() returned.
                const auto admission =
                    transport->submit(std::move(request),
                                      [attempt, gateRef, observer = hooks.observer, thisAttempt](HttpResult&& result)
                                      {
                                          bool late = false;
                                          {
                                              std::lock_guard<std::mutex> lock(gateRef->mutex);
                                              if (attempt->abandoned)
                                              {
                                                  late = true;
                                              }
                                              else
                                              {
                                                  attempt->result = std::move(result);
                                              }
                                          }
                                          if (!late)
                                          {
                                              gateRef->cv.notify_all();
                                              return;
                                          }
                                          if (observer)
                                          {
                                              AttemptEvent event;
                                              event.kind = AttemptEvent::Kind::Late;
                                              event.attempt = thisAttempt;
                                              event.result = &result;
                                              observer(event);
                                          }
                                      });
                transport.reset();
                nodes.reset();
                if (!admission.admitted)
                {
                    if (admission.cause == Cause::Shutdown)
                    {
                        return closedOutcome(Cause::Shutdown);
                    }
                    return fail<QueryResponse>(admission.cause, "the transport refused the request");
                }
                g_requests.fetch_add(1, std::memory_order_relaxed);
                attemptNo = thisAttempt;
                if (!series.start)
                {
                    series.start = start;
                }

                // Wait for the result on the gate, bounded by the deadline and the page. An attempt with the whole
                // budget ends with the page (the default pageDeadline < requestTimeout): it gets TIMEOUT_GRACE past the
                // page so curl's Timeout lands and reaches NodeSet::report instead of losing the race to this wait; the
                // consumer's deadline still bounds it.
                const TimePoint waitLimit =
                    configuredTimeout
                        ? std::min(deadline, std::max(limit, addSaturated(start, fullBudget + TIMEOUT_GRACE)))
                        : limit;
                std::optional<HttpResult> result;
                {
                    std::unique_lock<std::mutex> lock(gate.mutex);
                    gate.cv.wait_until(
                        lock,
                        waitLimit,
                        [&] { return attempt->result.has_value() || gate.stopping || client->closeRequested.load(); });
                    if (attempt->result)
                    {
                        result = std::move(attempt->result);
                    }
                    else
                    {
                        attempt->abandoned = true; // Its result, if any, goes to the observer as Late.
                    }
                }
                if (!result)
                {
                    notify(AttemptEvent::Kind::Abandoned, nullptr);
                    cancelAttempt(*client, admission.id);
                    if (const auto cause = closing(*client, gate))
                    {
                        return closedOutcome(*cause);
                    }
                    return expired();
                }
                const HttpResult& r = *result;
                // D48: from the delivery to the engine until this iteration ends (the response is returned or the
                // loop goes on); the classification and its DOM happen meanwhile.
                const ResponseBytesInFlight inFlight(r.body.size());

                if (r.cause == TransportCause::Timeout && !configuredTimeout)
                {
                    // The page's own clock fired, not the configured timeout: never node-attributable here.
                    notify(AttemptEvent::Kind::Failed, &r);
                    return expired();
                }
                if (auto set = runtimeNodeSet(client->runtime, client->epoch))
                {
                    set->report(*node, r);
                }

                const auto verdict = write::classifyRequest(r, 1);
                const bool answered = r.cause == TransportCause::None;
                std::optional<QueryResponse> classified;
                if (answered && ((r.status >= 200 && r.status < 300) || r.status == 404))
                {
                    classified = classify(r);
                }
                notify(answered ? AttemptEvent::Kind::Answered : AttemptEvent::Kind::Failed, &r);
                if (classified)
                {
                    auto response = std::move(*classified);
                    if (response.tooLarge)
                    {
                        g_tooLarge.fetch_add(1, std::memory_order_relaxed);
                    }
                    switch (response.verdict)
                    {
                        case QueryVerdict::Ok: return Outcome<QueryResponse>::success(std::move(response));
                        case QueryVerdict::Fail:
                        {
                            auto out = fail<QueryResponse>(response.cause,
                                                           std::move(response.reason),
                                                           response.httpStatus ? response.httpStatus
                                                                               : static_cast<int>(r.status));
                            out.responseTooLarge = response.tooLarge;
                            return out;
                        }
                        case QueryVerdict::Conflict:
                        {
                            ++conflicts;
                            last.set(Cause::VersionConflict,
                                     static_cast<int>(r.status),
                                     std::to_string(response.versionConflicts) + " version conflicts");
                            if (conflicts >= CONFLICT_ATTEMPTS)
                            {
                                return fail<QueryResponse>(
                                    Cause::VersionConflict,
                                    "version conflicts after " + std::to_string(conflicts) + " attempts (" +
                                        std::to_string(response.versionConflicts) + " in the last response)",
                                    static_cast<int>(r.status));
                            }
                            g_conflictRetries.fetch_add(1, std::memory_order_relaxed);
                            sleepOnGate(*client, gate, std::min(addSaturated(now(), conflictDelay(conflicts)), limit));
                            series = Series {}; // I86: a conflict retry opens a fresh I82 series.
                            continue;
                        }
                        case QueryVerdict::Retry:
                        {
                            last.set(response.cause == Cause::None ? Cause::ItemRetryable : response.cause,
                                     static_cast<int>(r.status),
                                     response.reason.empty() ? std::string("timed_out") : response.reason);
                            ++series.attempts;
                            const auto at = now();
                            const auto wait = backoffDelay(retry, series.attempts, jitterDraw());
                            if (exhausted(retry, series, at) || backoffPastBudget(at, wait))
                            {
                                return retriesExhausted();
                            }
                            sleepOnGate(*client, gate, std::min(addSaturated(at, wait), limit));
                            continue;
                        }
                    }
                }

                switch (verdict.verdict)
                {
                    case write::RequestVerdict::Failover:
                    {
                        g_failovers.fetch_add(1, std::memory_order_relaxed);
                        last.set(verdict.cause, verdict.httpStatus, verdict.reason);
                        if (verdict.mayHaveSent)
                        {
                            ++series.attempts;
                        }
                        if (exhausted(retry, series, now()))
                        {
                            return retriesExhausted();
                        }
                        continue; // Another node at once.
                    }
                    case write::RequestVerdict::Throttled:
                    {
                        g_throttles.fetch_add(1, std::memory_order_relaxed);
                        last.set(verdict.cause, verdict.httpStatus, verdict.reason);
                        ++series.throttles;
                        const auto at = now();
                        const Duration wait = std::max(verdict.retryAfter.value_or(Duration::zero()),
                                                       backoffDelay(retry, series.throttles, jitterDraw()));
                        if (exhausted(retry, series, at) || backoffPastBudget(at, wait))
                        {
                            return retriesExhausted();
                        }
                        sleepOnGate(*client, gate, std::min(addSaturated(at, wait), limit));
                        continue;
                    }
                    case write::RequestVerdict::Ignore:
                        if (r.cause == TransportCause::Shutdown)
                        {
                            return closedOutcome(Cause::Shutdown);
                        }
                        [[fallthrough]]; // A Cancelled the engine did not ask for: retried with an attempt.
                    case write::RequestVerdict::Retry:
                    {
                        last.set(verdict.cause == Cause::None ? Cause::Server5xx : verdict.cause,
                                 verdict.httpStatus,
                                 verdict.reason);
                        ++series.attempts;
                        const auto at = now();
                        const auto wait = backoffDelay(retry, series.attempts, jitterDraw());
                        if (exhausted(retry, series, at) || backoffPastBudget(at, wait))
                        {
                            return retriesExhausted();
                        }
                        sleepOnGate(*client, gate, std::min(addSaturated(at, wait), limit));
                        continue;
                    }
                    case write::RequestVerdict::Items: // A 2xx is settled above.
                    case write::RequestVerdict::Split: // Never with one op.
                    case write::RequestVerdict::FailBatch:
                    default:
                    {
                        std::string reason = verdict.reason;
                        if (answered && r.status >= 400 && r.status < 500)
                        {
                            auto quoted = errorReason(r.status, r.body);
                            if (!quoted.empty())
                            {
                                reason = std::move(quoted);
                            }
                        }
                        auto out = fail<QueryResponse>(verdict.cause == Cause::None ? Cause::Client4xx : verdict.cause,
                                                       std::move(reason),
                                                       verdict.httpStatus);
                        // Over maxResponseBytes on the wire (curl 23, one op ⇒ FailBatch ItemPermanent).
                        out.responseTooLarge = r.cause == TransportCause::ResponseTooLarge;
                        return out;
                    }
                }
            }
        }

        class QueryImpl final : public IQuery
        {
        public:
            explicit QueryImpl(std::shared_ptr<ClientState> client)
                : m_client(std::move(client))
            {
            }

            Outcome<nlohmann::json> search(std::string_view index,
                                           const nlohmann::json& body,
                                           const QueryOptions& options,
                                           Deadline deadline) override
            {
                if (auto refused = admit<nlohmann::json>(options, invalidIndex(index, "index"), "search()"))
                {
                    return *refused;
                }
                auto out = runSearch(std::string(index), body, options, deadline);
                if (!out.ok())
                {
                    return failFrom<nlohmann::json>(out);
                }
                return Outcome<nlohmann::json>::success(std::move(out.value.body));
            }

            Outcome<Unit> searchAfter(std::string_view index,
                                      nlohmann::json body,
                                      std::function<bool(const nlohmann::json&)> page,
                                      const QueryOptions& options,
                                      Deadline deadline) override
            {
                auto invalid = invalidIndex(index, "index");
                std::int64_t size = 0;
                if (!invalid)
                {
                    const auto sort = body.is_object() ? body.find("sort") : body.end();
                    const auto sizeIt = body.is_object() ? body.find("size") : body.end();
                    if (sort == body.end() || !sort->is_array() || sort->empty())
                    {
                        invalid = std::string("body.sort: must be a non-empty array");
                    }
                    else if (sizeIt == body.end() || !sizeIt->is_number_integer() ||
                             (sizeIt->is_number_unsigned() ? sizeIt->get<std::uint64_t>() == 0
                                                           : sizeIt->get<std::int64_t>() <= 0))
                    {
                        invalid = std::string("body.size: must be an integer > 0");
                    }
                    else
                    {
                        size = sizeIt->is_number_unsigned()
                                   ? static_cast<std::int64_t>(std::min<std::uint64_t>(
                                         sizeIt->get<std::uint64_t>(),
                                         static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
                                   : sizeIt->get<std::int64_t>();
                    }
                }
                if (!invalid && !page)
                {
                    invalid = std::string("page: must be callable");
                }
                if (auto refused = admit<Unit>(options, std::move(invalid), "searchAfter()"))
                {
                    return *refused;
                }
                const std::string name(index);
                for (;;)
                {
                    auto out = runSearch(name, body, options, deadline);
                    if (!out.ok())
                    {
                        return failFrom<Unit>(out);
                    }
                    const nlohmann::json& response = out.value.body;
                    if (!page(response)) // On the consumer thread; an exception propagates with nothing pending.
                    {
                        return Outcome<Unit>::success({});
                    }
                    const auto outer = response.is_object() ? response.find("hits") : response.end();
                    if (outer == response.end() || !outer->is_object())
                    {
                        return Outcome<Unit>::success({});
                    }
                    const auto hits = outer->find("hits");
                    if (hits == outer->end() || !hits->is_array() || hits->empty() ||
                        static_cast<std::int64_t>(hits->size()) < size)
                    {
                        return Outcome<Unit>::success({});
                    }
                    const auto& lastHit = hits->back();
                    const auto sort = lastHit.is_object() ? lastHit.find("sort") : lastHit.end();
                    if (sort == lastHit.end() || !sort->is_array() || sort->empty())
                    {
                        return Outcome<Unit>::success({});
                    }
                    body["search_after"] = *sort;
                }
            }

            Outcome<Pit> pit(std::vector<std::string> indices,
                             PitOptions pitOptions,
                             const QueryOptions& options,
                             Deadline deadline) override
            {
                // pit.hpp CREATE: Reentrancy, then indices, keepAlive and the QueryOptions (InvalidArgument).
                auto invalid = invalidIndices(indices);
                if (!invalid && pitOptions.keepAlive <= Duration::zero())
                {
                    invalid = std::string("pitOptions.keepAlive: must be > 0");
                }
                if (auto refused = admit<Pit>(options, std::move(invalid), "pit()"))
                {
                    return *refused;
                }
                return createPit(m_client, std::move(indices), pitOptions, options, deadline);
            }

            Outcome<nlohmann::json> deleteByQuery(std::vector<std::string> indices,
                                                  const nlohmann::json& query,
                                                  DbqOptions dbqOptions,
                                                  const QueryOptions& options,
                                                  Deadline deadline) override
            {
                if (auto refused = admit<nlohmann::json>(options, invalidIndices(indices), "deleteByQuery()"))
                {
                    return *refused;
                }
                std::vector<std::string> params;
                if (dbqOptions.proceedOnConflicts)
                {
                    params.emplace_back("conflicts=proceed");
                }
                return byQuery(indices, "/_delete_by_query", std::move(params), query, true, options, deadline);
            }

            Outcome<nlohmann::json> updateByQuery(std::vector<std::string> indices,
                                                  const nlohmann::json& query,
                                                  const QueryOptions& options,
                                                  Deadline deadline) override
            {
                if (auto refused = admit<nlohmann::json>(options, invalidIndices(indices), "updateByQuery()"))
                {
                    return *refused;
                }
                return byQuery(indices, "/_update_by_query", {"conflicts=proceed"}, query, false, options, deadline);
            }

            Outcome<bool> indexExists(std::string_view index, const QueryOptions& options, Deadline deadline) override
            {
                if (auto refused = admit<bool>(options, invalidIndex(index, "index"), "indexExists()"))
                {
                    return *refused;
                }
                RouteSpec route;
                route.method = HttpMethod::Head;
                route.target = target(std::string(index), "", wildcardParams(options, {}));
                auto out =
                    execute(m_client, options, deadline, route, [](const HttpResult& r) { return classifyExists(r); });
                if (!out.ok())
                {
                    return failFrom<bool>(out);
                }
                return Outcome<bool>::success(out.value.exists);
            }

        private:
            /// I87 steps 1-3: Reentrancy, then validation (InvalidArgument), then the client and its runtime.
            template<class T>
            std::optional<Outcome<T>>
            admit(const QueryOptions& options, std::optional<std::string> invalid, const char* operation) const
            {
                if (testing::onRuntimeThread())
                {
                    return fail<T>(Cause::Reentrancy, std::string(operation) + " called from a runtime thread");
                }
                if (!invalid)
                {
                    invalid = invalidOptions(options);
                }
                if (invalid)
                {
                    return fail<T>(Cause::InvalidArgument, std::move(*invalid));
                }
                if (m_client->closeRequested.load())
                {
                    return fail<T>(Cause::ClientClosed, "the client was closed");
                }
                if (!m_client->queryGate || !runtimeTransport(m_client->runtime, m_client->epoch))
                {
                    return fail<T>(Cause::Shutdown, "the runtime is shut down");
                }
                if (const auto cause = closing(*m_client, *m_client->queryGate))
                {
                    return failFrom<T>(closedOutcome(*cause));
                }
                return std::nullopt;
            }

            static std::vector<std::string> wildcardParams(const QueryOptions& options, std::vector<std::string> params)
            {
                if (options.expandWildcardsAll)
                {
                    params.emplace_back("expand_wildcards=all");
                }
                return params;
            }

            Outcome<QueryResponse> runSearch(const std::string& index,
                                             const nlohmann::json& body,
                                             const QueryOptions& options,
                                             Deadline deadline) const
            {
                RouteSpec route;
                route.method = HttpMethod::Post;
                route.target = target(index, "/_search", wildcardParams(options, {}));
                route.body = std::make_shared<const std::string>(body.dump());
                const auto cap = m_client->maxResponseBytes;
                return execute(
                    m_client, options, deadline, route, [cap](const HttpResult& r) { return classifySearch(r, cap); });
            }

            Outcome<nlohmann::json> byQuery(const std::vector<std::string>& indices,
                                            std::string_view route,
                                            std::vector<std::string> params,
                                            const nlohmann::json& query,
                                            bool isDelete,
                                            const QueryOptions& options,
                                            Deadline deadline) const
            {
                RouteSpec spec;
                spec.method = HttpMethod::Post;
                spec.target = target(joined(indices), route, wildcardParams(options, std::move(params)));
                spec.body = std::make_shared<const std::string>(query.dump());
                const auto cap = m_client->maxResponseBytes;
                auto out = execute(m_client,
                                   options,
                                   deadline,
                                   spec,
                                   [cap, isDelete](const HttpResult& r) { return classifyByQuery(r, isDelete, cap); });
                if (!out.ok())
                {
                    return failFrom<nlohmann::json>(out);
                }
                return Outcome<nlohmann::json>::success(std::move(out.value.body));
            }

            std::shared_ptr<ClientState> m_client;
        };
    } // namespace

    std::string target(const std::string& indices, std::string_view route, const std::vector<std::string>& params)
    {
        return targetImpl(indices, route, params);
    }

    Outcome<QueryResponse> execute(const std::shared_ptr<ClientState>& client,
                                   const QueryOptions& options,
                                   Deadline deadline,
                                   const RouteSpec& route,
                                   const Classifier& classify,
                                   const EngineHooks& hooks)
    {
        return executeImpl(client, options, deadline, route, classify, hooks);
    }

    std::shared_ptr<IQuery> makeQuery(std::shared_ptr<ClientState> client)
    {
        return std::make_shared<QueryImpl>(std::move(client));
    }

    QueryStats queryStats()
    {
        QueryStats stats;
        stats.requests = g_requests.load(std::memory_order_relaxed);
        stats.failovers = g_failovers.load(std::memory_order_relaxed);
        stats.throttles = g_throttles.load(std::memory_order_relaxed);
        stats.unavailable = g_unavailable.load(std::memory_order_relaxed);
        stats.tooLarge = g_tooLarge.load(std::memory_order_relaxed);
        stats.conflictRetries = g_conflictRetries.load(std::memory_order_relaxed);
        stats.responseBytesInFlight = g_responseBytesInFlight.load(std::memory_order_relaxed);
        stats.peakResponseBytesInFlight = g_peakResponseBytesInFlight.load(std::memory_order_relaxed);
        return stats;
    }
} // namespace indexer_client::detail::query
