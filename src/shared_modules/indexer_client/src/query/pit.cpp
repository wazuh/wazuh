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

#include "query/pit.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "query/engine.hpp"
#include "query/queryResponse.hpp"
#include "runtime/runtimeInternal.hpp"

// The managed PIT over the query engine (stage E4b, I93). NORMATIVE contract: pit.hpp (CREATE, STATE, SEARCH, EXPIRY,
// LIFETIME); the registry (slots, deletes, drain) is pitRegistry.cpp's.

namespace indexer_client::detail::query
{
    // Entry points of Pit and PitSession (tickets.cpp declares them too).
    std::shared_ptr<CursorState>
    openCursor(std::shared_ptr<PitState> pit, CursorQuery query, std::optional<Slice> slice);
    Outcome<PitPage> cursorNext(const std::shared_ptr<CursorState>& cursor, Deadline deadline);
    Outcome<nlohmann::json>
    pitSearch(const std::shared_ptr<PitState>& pit, const nlohmann::json& body, Deadline deadline);

    namespace
    {
        std::atomic<std::uint64_t> g_expired {0};
        std::atomic<std::uint64_t> g_stale {0};
        /// PitState::generation: monotonic for the process, so two Pits never share one (0 = no PIT).
        std::atomic<std::uint64_t> g_generation {0};

        TimePoint now()
        {
            return std::chrono::steady_clock::now();
        }

        std::string keepAliveText(Duration keepAlive)
        {
            return std::to_string(keepAlive.count()) + "ms";
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

        template<class T>
        Outcome<T> failFrom(const Outcome<QueryResponse>& other)
        {
            auto out = Outcome<T>::failure(other.cause, other.reason, other.httpStatus);
            out.responseTooLarge = other.responseTooLarge;
            return out;
        }

        /// The cause a request on this PIT ends with before being sent, if any (pit.hpp EXPIRY and SHUTDOWN).
        std::optional<PreAttemptAbort> unusable(const PitState& pit)
        {
            if (pit.drained.load())
            {
                return PreAttemptAbort {Cause::Shutdown, "the runtime shut down and deleted the PIT"};
            }
            if (pit.expired.load())
            {
                return PreAttemptAbort {Cause::PitExpired, "the PIT expired"};
            }
            return std::nullopt;
        }

        void markExpired(PitState& pit)
        {
            if (!pit.expired.exchange(true))
            {
                g_expired.fetch_add(1, std::memory_order_relaxed);
            }
        }

        nlohmann::json pitField(PitState& pit)
        {
            std::lock_guard<std::mutex> lock(pit.mutex);
            return nlohmann::json {{"id", pit.id}, {"keep_alive", keepAliveText(pit.keepAlive)}};
        }

        /// pit.hpp LIFETIME: when the last handle goes, {id, keepAlive, lastUse} to the registry (never blocks).
        class RegistryHandoff final : public PitHandoff
        {
        public:
            explicit RegistryHandoff(PitState& pit)
                : m_pit(pit)
            {
            }

            ~RegistryHandoff() override
            {
                // `handoff` is PitState's last member: destroyed first, while the others still hold their values.
                if (m_pit.drained.load())
                {
                    return;
                }
                auto registry = m_pit.registry.lock();
                if (!registry)
                {
                    return; // The runtime is gone: keep_alive frees the PIT.
                }
                try
                {
                    PitRegistry::Pending pending;
                    {
                        std::lock_guard<std::mutex> lock(m_pit.mutex);
                        pending.id = m_pit.id;
                        pending.lastUse = m_pit.lastUse;
                    }
                    pending.keepAlive = m_pit.keepAlive;
                    if (!pending.id.empty())
                    {
                        registry->release(std::move(pending));
                    }
                }
                catch (...) // NOLINT(bugprone-empty-catch): a destructor; the PIT lapses with its keep_alive.
                {
                }
            }

            RegistryHandoff(const RegistryHandoff&) = delete;
            RegistryHandoff& operator=(const RegistryHandoff&) = delete;

        private:
            PitState& m_pit;
        };

        /// The slot of the creation attempt in flight (pit.hpp CREATE). Touched by preAttempt, the classifier and the
        /// observer's Answered/Failed/Abandoned, all on the consumer thread; Late never touches it.
        struct CreateSlots final
        {
            bool held {false};     ///< An acquired slot no attempt has settled yet.
            bool accepted {false}; ///< The classifier took the last 2xx (non-empty pit_id).
            /// The pit_id of the last 2xx the classifier refused although it names a PIT (a partial one): the observer
            /// hands it to the registry to be deleted, and clears it.
            std::string refusedId;
            /// The last 2xx the classifier refused without a usable pit_id (over the response cap, unparsable, no
            /// pit_id): a PIT may exist that nobody can address, so the observer reserves the slot, and clears it.
            bool refused2xx {false};
        };

        /// One search request on the PIT (next() page or search()): POST /_search?allow_partial_search_results=false
        /// under the pit() QueryOptions, with the expiry, staleness and pit_id renewal of pit.hpp.
        Outcome<QueryResponse>
        runOnPit(const std::shared_ptr<PitState>& pit, const std::string& body, Deadline deadline)
        {
            RouteSpec route;
            route.method = HttpMethod::Post;
            route.target = target("", "/_search", {"allow_partial_search_results=false"});
            route.body = std::make_shared<const std::string>(body);

            EngineHooks hooks;
            // Every attempt, the first and the one after a backoff included: an expired PIT sends nothing more.
            hooks.preAttempt = [pit]()
            {
                return unusable(*pit);
            };
            // lastUse: when the last request that may have reached the indexer was seen (never earlier than sent).
            hooks.observer = [weak = std::weak_ptr<PitState>(pit)](const AttemptEvent& event)
            {
                if (event.kind == AttemptEvent::Kind::Late ||
                    (event.kind == AttemptEvent::Kind::Failed && (!event.result || !event.result->mayHaveSent)))
                {
                    return;
                }
                if (auto state = weak.lock())
                {
                    const auto at = now();
                    std::lock_guard<std::mutex> lock(state->mutex);
                    state->lastUse = std::max(state->lastUse, at);
                }
            };

            const auto cap = pit->client->maxResponseBytes;
            const Classifier classify = [pit, cap](const HttpResult& result)
            {
                auto response = classifyPitSearch(result, cap, pit->wholeResponseCap);
                if (response.verdict == QueryVerdict::Fail && response.cause == Cause::PitExpired)
                {
                    markExpired(*pit);
                    return response;
                }
                if (response.verdict != QueryVerdict::Ok)
                {
                    return response;
                }
                if (pit->expired.load())
                {
                    // Another cursor saw the expiry while this answer was in flight: never a page (T19).
                    g_stale.fetch_add(1, std::memory_order_relaxed);
                    QueryResponse stale;
                    stale.verdict = QueryVerdict::Fail;
                    stale.cause = Cause::PitExpired;
                    stale.httpStatus = static_cast<int>(result.status);
                    stale.reason = "the PIT expired; response discarded";
                    return stale;
                }
                const auto id = response.body.find("pit_id");
                if (id != response.body.end() && id->is_string() && !id->get_ref<const std::string&>().empty())
                {
                    std::lock_guard<std::mutex> lock(pit->mutex);
                    if (pit->id != id->get_ref<const std::string&>())
                    {
                        pit->id = id->get<std::string>(); // Last arrival wins: every id addresses the same contexts.
                    }
                }
                return response;
            };
            return execute(pit->client, pit->options, deadline, route, classify, hooks);
        }

        std::optional<std::uint64_t> totalOf(const nlohmann::json& hits)
        {
            const auto total = hits.find("total");
            if (total == hits.end())
            {
                return std::nullopt;
            }
            const nlohmann::json* value = &*total;
            if (total->is_object())
            {
                const auto inner = total->find("value");
                if (inner == total->end())
                {
                    return std::nullopt;
                }
                value = &*inner;
            }
            if (value->is_number_unsigned())
            {
                return value->get<std::uint64_t>();
            }
            if (value->is_number_integer() && value->get<std::int64_t>() >= 0)
            {
                return static_cast<std::uint64_t>(value->get<std::int64_t>());
            }
            return std::nullopt;
        }
    } // namespace

    TimePoint addSaturated(TimePoint from, Duration span)
    {
        const auto room = std::chrono::duration_cast<Duration>(TimePoint::max() - from);
        return span >= room ? TimePoint::max() : from + span;
    }

    PitStats pitStats()
    {
        auto stats = registryStats();
        stats.expired += g_expired.load(std::memory_order_relaxed);
        stats.stale += g_stale.load(std::memory_order_relaxed);
        return stats;
    }

    Outcome<Pit> createPit(const std::shared_ptr<ClientState>& client,
                           std::vector<std::string> indices,
                           PitOptions pitOptions,
                           const QueryOptions& options,
                           Deadline deadline)
    {
        // Reentrancy, validation and the client/runtime checks are QueryImpl::pit's (query.cpp admit()).
        auto registry = runtimePitRegistry(client->runtime, client->epoch);
        if (!registry)
        {
            return Outcome<Pit>::failure(Cause::Shutdown, "the runtime is shut down");
        }

        // allow_partial_pit_creation defaults to true: without it a PIT missing a shard is created, and its pages miss
        // that shard's documents without any shard failure to show it.
        std::vector<std::string> params {"keep_alive=" + keepAliveText(pitOptions.keepAlive),
                                         "allow_partial_pit_creation=false"};
        if (pitOptions.expandWildcardsAll || options.expandWildcardsAll)
        {
            params.emplace_back("expand_wildcards=all");
        }
        RouteSpec route;
        route.method = HttpMethod::Post;
        route.target = target(joined(indices), "/_search/point_in_time", params);

        const auto slots = std::make_shared<CreateSlots>();
        const auto keepAlive = pitOptions.keepAlive;
        const auto wholeResponseCap = pitOptions.wholeResponseCap;
        EngineHooks hooks;
        // I89/I91: one slot per attempt; a slot no attempt settled (a "no node" wait) is kept for the next one.
        hooks.preAttempt = [slots, registry]() -> std::optional<PreAttemptAbort>
        {
            if (slots->held)
            {
                return std::nullopt;
            }
            std::uint64_t occupied = 0;
            if (!registry->acquire(occupied))
            {
                return PreAttemptAbort {Cause::QueueFull,
                                        std::string(PIT_FULL) + " (" + std::to_string(occupied) + ")"};
            }
            slots->held = true;
            return std::nullopt;
        };
        // Weak: a Late copy of the observer must not keep the registry (and its runtime) alive.
        hooks.observer = [slots, weak = std::weak_ptr<PitRegistry>(registry), keepAlive](const AttemptEvent& event)
        {
            if (event.kind == AttemptEvent::Kind::Late || !slots->held)
            {
                return; // A late result changes nothing: the reservation stays until it lapses.
            }
            slots->held = false;
            auto owner = weak.lock();
            if (!owner)
            {
                return;
            }
            switch (event.kind)
            {
                case AttemptEvent::Kind::Answered:
                    if (!slots->refusedId.empty())
                    {
                        // A PIT the creation refused (partial): it exists, so its slot stays taken until its DELETE.
                        owner->discard({std::exchange(slots->refusedId, {}), keepAlive, now()});
                    }
                    else if (std::exchange(slots->refused2xx, false))
                    {
                        // The indexer created a PIT the library cannot address: an orphan until its keep_alive.
                        owner->reserve(addSaturated(now(), keepAlive));
                    }
                    else if (!slots->accepted)
                    {
                        owner->releaseSlot();
                    }
                    return; // Accepted: the slot stays acquired until opened() makes it the PIT's.
                case AttemptEvent::Kind::Failed:
                    if (event.result && event.result->mayHaveSent)
                    {
                        owner->reserve(addSaturated(now(), keepAlive)); // The PIT may exist: an orphan (I91).
                    }
                    else
                    {
                        owner->releaseSlot();
                    }
                    return;
                case AttemptEvent::Kind::Abandoned: owner->reserve(addSaturated(now(), keepAlive)); return;
                default: return; // Late returned above.
            }
        };
        const auto cap = client->maxResponseBytes;
        const Classifier classify = [slots, cap](const HttpResult& result)
        {
            auto response = classifyPitCreate(result, cap);
            slots->accepted = response.verdict == QueryVerdict::Ok;
            slots->refusedId.clear();
            slots->refused2xx = false;
            if (!slots->accepted && response.body.is_object())
            {
                const auto id = response.body.find("pit_id");
                if (id != response.body.end() && id->is_string())
                {
                    slots->refusedId = id->get<std::string>();
                }
            }
            slots->refused2xx =
                !slots->accepted && slots->refusedId.empty() && result.status >= 200 && result.status < 300;
            return response;
        };

        auto out = execute(client, options, deadline, route, classify, hooks);
        if (!out.ok())
        {
            if (slots->held)
            {
                registry->releaseSlot(); // Never became a PIT (pit.hpp CREATE: a final failure frees what it holds).
            }
            return failFrom<Pit>(out);
        }

        auto state = std::make_shared<PitState>();
        state->id = out.value.body.at("pit_id").get<std::string>(); // classifyPitCreate checked it.
        state->lastUse = now();
        state->keepAlive = keepAlive;
        state->generation = g_generation.fetch_add(1, std::memory_order_relaxed) + 1;
        state->options = options;
        state->wholeResponseCap = wholeResponseCap;
        state->indices = std::move(indices);
        state->client = client;
        state->registry = registry;
        state->handoff = std::make_unique<RegistryHandoff>(*state);
        registry->opened(state);
        return Outcome<Pit>::success(Pit(std::move(state)));
    }

    std::shared_ptr<CursorState>
    openCursor(std::shared_ptr<PitState> pit, CursorQuery query, std::optional<Slice> slice)
    {
        auto cursor = std::make_shared<CursorState>();
        if (query.pageSize == 0)
        {
            cursor->invalid = "query.pageSize: must be > 0";
        }
        else if (slice && slice->max < 2)
        {
            cursor->invalid = "slice.max: must be >= 2";
        }
        else if (slice && slice->id >= slice->max)
        {
            cursor->invalid = "slice.id: must be < slice.max";
        }
        cursor->pit = std::move(pit);
        cursor->query = std::move(query);
        cursor->slice = slice;
        return cursor;
    }

    Outcome<PitPage> cursorNext(const std::shared_ptr<CursorState>& cursor, Deadline deadline)
    {
        if (!cursor->invalid.empty())
        {
            return Outcome<PitPage>::failure(Cause::InvalidArgument, cursor->invalid);
        }
        const auto& pit = cursor->pit;
        if (!pit || !pit->client)
        {
            return Outcome<PitPage>::failure(Cause::InvalidState, "cursor of an empty Pit");
        }

        std::lock_guard<std::mutex> lock(cursor->mutex); // One page at a time per cursor.
        PitPage page;
        page.generation = pit->generation;
        if (cursor->exhausted.load())
        {
            page.last = true;
            return Outcome<PitPage>::success(std::move(page));
        }
        if (auto refused = unusable(*pit))
        {
            return Outcome<PitPage>::failure(refused->cause, std::move(refused->reason));
        }

        // Built once per page: a retry repeats the same id and search_after.
        const auto& query = cursor->query;
        nlohmann::json body = nlohmann::json::object();
        body["size"] = query.pageSize;
        body["query"] = query.query;
        body["sort"] =
            query.sort.empty() ? nlohmann::json::array({nlohmann::json::object({{"_shard_doc", "asc"}})}) : query.sort;
        if (!query.source.is_null())
        {
            body["_source"] = query.source;
        }
        if (cursor->slice)
        {
            body["slice"] = {{"id", cursor->slice->id}, {"max", cursor->slice->max}};
        }
        body["pit"] = pitField(*pit);
        if (cursor->firstPage)
        {
            body["track_total_hits"] = true;
        }
        else
        {
            body["search_after"] = cursor->searchAfter;
        }

        auto out = runOnPit(pit, body.dump(), deadline);
        if (!out.ok())
        {
            return failFrom<PitPage>(out);
        }

        auto& response = out.value.body;
        nlohmann::json hits = nlohmann::json::array();
        const auto outer = response.is_object() ? response.find("hits") : response.end();
        if (outer != response.end() && outer->is_object())
        {
            if (cursor->firstPage)
            {
                page.total = totalOf(*outer);
            }
            const auto inner = outer->find("hits");
            if (inner != outer->end() && inner->is_array())
            {
                hits = std::move(*inner);
            }
        }
        page.last = hits.size() < query.pageSize;
        if (!page.last)
        {
            const auto& lastHit = hits.back();
            const auto sort = lastHit.is_object() ? lastHit.find("sort") : lastHit.end();
            if (sort != lastHit.end() && sort->is_array() && !sort->empty())
            {
                cursor->searchAfter = *sort;
            }
            else
            {
                page.last = true; // Nothing to continue from.
            }
        }
        page.hits = std::move(hits);
        cursor->firstPage = false;
        if (page.last)
        {
            cursor->exhausted.store(true);
        }
        return Outcome<PitPage>::success(std::move(page));
    }

    Outcome<nlohmann::json>
    pitSearch(const std::shared_ptr<PitState>& pit, const nlohmann::json& body, Deadline deadline)
    {
        if (!pit || !pit->client)
        {
            return Outcome<nlohmann::json>::failure(Cause::InvalidState, "empty Pit");
        }
        if (!body.is_object() && !body.is_null())
        {
            return Outcome<nlohmann::json>::failure(Cause::InvalidArgument, "body: must be a JSON object");
        }
        if (auto refused = unusable(*pit))
        {
            return Outcome<nlohmann::json>::failure(refused->cause, std::move(refused->reason));
        }
        nlohmann::json request = body.is_null() ? nlohmann::json::object() : body;
        request["pit"] = pitField(*pit); // Overwritten; nothing else touched (pit.hpp SEARCH).
        auto out = runOnPit(pit, request.dump(), deadline);
        if (!out.ok())
        {
            return failFrom<nlohmann::json>(out);
        }
        return Outcome<nlohmann::json>::success(std::move(out.value.body));
    }
} // namespace indexer_client::detail::query
