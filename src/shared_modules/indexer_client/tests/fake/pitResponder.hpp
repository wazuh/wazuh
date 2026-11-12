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

#ifndef _INDEXER_CLIENT_TESTS_FAKE_PIT_RESPONDER_HPP
#define _INDEXER_CLIENT_TESTS_FAKE_PIT_RESPONDER_HPP

// Point in time on the fake indexer (plan 18, E4b step 6). The responder keeps OpenSearch's PIT lifecycle over a
// synthetic index of documents 1..N: `POST /<indices>/_search/point_in_time?keep_alive=<n>ms` creates a PIT (pit_id
// "pit-<k>"), `POST /_search` with `pit {id, keep_alive}` serves a page (sorted by the document number, `sort: [k]`,
// `slice {id, max}` keeps the documents with (k - 1) % max == id, `search_after: [k]` continues after k, `size`
// hits) and renews the PIT's expiry by that keep_alive (a search without one does not renew it), and
// `DELETE /_search/point_in_time` with `{"pit_id": id}` (a string or an array) deletes it. A search on an expired,
// deleted or unknown PIT gets OpenSearch's 404 (`search_phase_execution_exception` with a
// `search_context_missing_exception` root cause). On demand it expires every PIT at once, answers the next search
// with a new pit_id (every id of a PIT keeps addressing it) and counts creations, deletions and requests.
// A per-request intercept scripts faults: it sees the kind, the ordinal and the parsed body, and either replaces the
// answer or only adds transport behaviour (hold, cutAfter, latency) to the normal one. rules() turns it into plain
// rules, so several fakes can share one PIT state (a failover lands on the same PITs).

#include "fakeIndexer.hpp"
#include "json.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace indexer_client::testing
{
    inline constexpr std::string_view PIT_CREATE_PATH_REGEX {"/[^/]+/_search/point_in_time"};
    inline constexpr std::string_view PIT_SEARCH_PATH_REGEX {"/_search"};
    inline constexpr std::string_view PIT_DELETE_PATH_REGEX {"/_search/point_in_time"};
    inline constexpr std::string_view SEARCH_CONTEXT_MISSING_TYPE {"search_context_missing_exception"};

    enum class PitCall
    {
        Create,
        Search,
        Delete
    };

    /// One PIT request as the intercept sees it.
    struct PitRequestView
    {
        PitCall call {PitCall::Search};
        /// 1-based, per call kind, in arrival order (every request counts, intercepted or not).
        std::size_t ordinal {0};
        /// The parsed body (null when empty or unreadable).
        nlohmann::json body;
        /// The raw target (path and query string).
        std::string target;
    };

    class PitResponder final : public std::enable_shared_from_this<PitResponder>
    {
    public:
        /// Called before the normal handling, outside the responder's lock. true: `reply` (status, body, headers,
        /// hold...) is served as the intercept left it and the PIT state is untouched. false: the normal handling runs
        /// and only rewrites `reply.status` and `reply.body`, keeping whatever else the intercept set (hold, cutAfter,
        /// latency).
        using Intercept = std::function<bool(const PitRequestView&, Rule&)>;

        explicit PitResponder(std::int64_t documents)
            : m_documents(documents)
        {
        }

        /// The create, delete and search rules (in that order: the delete path is also a prefix of nothing else).
        std::vector<Rule> rules()
        {
            std::weak_ptr<PitResponder> weak = shared_from_this();
            const auto make = [weak](std::string method, std::string_view regex, PitCall call)
            {
                Rule r;
                r.method = std::move(method);
                r.pathRegex = std::string(regex);
                r.dynamic = [weak, call](const httplib::Request& request, Rule& reply)
                {
                    if (auto self = weak.lock())
                    {
                        self->handle(call, request, reply);
                    }
                };
                return r;
            };
            return {make("POST", PIT_CREATE_PATH_REGEX, PitCall::Create),
                    make("DELETE", PIT_DELETE_PATH_REGEX, PitCall::Delete),
                    make("POST", PIT_SEARCH_PATH_REGEX, PitCall::Search)};
        }

        void intercept(Intercept hook)
        {
            std::lock_guard lock(m_mutex);
            m_intercept = std::move(hook);
        }

        /// Every live PIT expires now (OpenSearch dropped their contexts).
        void expireAll()
        {
            std::lock_guard lock(m_mutex);
            for (auto& pit : m_pits)
            {
                if (pit.alive)
                {
                    pit.alive = false;
                    ++m_expired;
                }
            }
        }

        /// The next `count` creations answer 200 with a PIT that misses a shard (`_shards.failed` 1 of 2), as
        /// OpenSearch does with allow_partial_pit_creation=true: the PIT is created and alive all the same.
        void partialCreates(std::size_t count)
        {
            std::lock_guard lock(m_mutex);
            m_partialCreates = count;
        }

        /// The next answered search carries a new pit_id for its PIT (the old ids keep working).
        void renewIdOnNextSearch()
        {
            std::lock_guard lock(m_mutex);
            m_renewNext = true;
        }

        std::size_t created() const
        {
            std::lock_guard lock(m_mutex);
            return m_pits.size();
        }

        /// PITs deleted by a DELETE (a DELETE of an unknown or expired id deletes nothing).
        std::size_t deleted() const
        {
            std::lock_guard lock(m_mutex);
            return m_deleted;
        }

        /// PITs that expired (by their keep_alive, seen at a request, or by expireAll()).
        std::size_t expired() const
        {
            std::lock_guard lock(m_mutex);
            return m_expired;
        }

        /// PITs alive now (their expiry is checked against the clock).
        std::size_t alive()
        {
            std::lock_guard lock(m_mutex);
            sweepLocked(std::chrono::steady_clock::now());
            std::size_t n = 0;
            for (const auto& pit : m_pits)
            {
                n += pit.alive ? 1 : 0;
            }
            return n;
        }

        /// Requests of one kind received so far (intercepted ones included).
        std::size_t requests(PitCall call) const
        {
            std::lock_guard lock(m_mutex);
            return m_counts[static_cast<std::size_t>(call)];
        }

        /// Every id handed out so far (creations and renewals), sorted.
        std::vector<std::string> ids() const
        {
            std::lock_guard lock(m_mutex);
            std::vector<std::string> out;
            for (const auto& [id, index] : m_byId)
            {
                (void)index;
                out.push_back(id);
            }
            return out;
        }

        /// The id the PIT created `k`-th (1-based) answers with now (its last renewal).
        std::string currentId(std::size_t k) const
        {
            std::lock_guard lock(m_mutex);
            return m_pits.at(k - 1).current;
        }

        /// OpenSearch's 404 for a search on a missing context.
        static std::string contextMissingBody(const std::string& id)
        {
            const std::string reason = "No search context found for id [" + id + "]";
            return nlohmann::json {{"error",
                                    {{"root_cause", {{{"type", SEARCH_CONTEXT_MISSING_TYPE}, {"reason", reason}}}},
                                     {"type", "search_phase_execution_exception"},
                                     {"reason", "all shards failed"},
                                     {"phase", "query"},
                                     {"grouped", true}}},
                                   {"status", 404}}
                .dump();
        }

        /// A 200 whose `_shards` reports one failed shard of type `type` (and still carries `hits`).
        static std::string partialFailureBody(const std::string& id, const nlohmann::json& hits, std::string_view type)
        {
            nlohmann::json failure {{"shard", 1},
                                    {"index", "idx"},
                                    {"node", "n1"},
                                    {"reason", {{"type", type}, {"reason", "No search context found for id [7]"}}}};
            return nlohmann::json {
                {"pit_id", id},
                {"took", 1},
                {"timed_out", false},
                {"_shards", {{"total", 2}, {"successful", 1}, {"skipped", 0}, {"failed", 1}, {"failures", {failure}}}},
                {"hits", {{"total", {{"value", hits.size()}, {"relation", "eq"}}}, {"hits", hits}}}}
                .dump();
        }

        /// The hit of document k: {"_index":"idx","_id":"d<k>","_source":{"n":k},"sort":[k]}.
        static nlohmann::json document(std::int64_t k)
        {
            return {{"_index", "idx"}, {"_id", "d" + std::to_string(k)}, {"_source", {{"n", k}}}, {"sort", {k}}};
        }

    private:
        struct PitEntry
        {
            std::string current;
            std::chrono::steady_clock::time_point expiresAt;
            bool alive {true};
            std::size_t renewals {0};
        };

        static std::chrono::milliseconds parseKeepAlive(const std::string& text)
        {
            // "<n>ms", "<n>s" or "<n>m"; anything else is 0 (expires at once).
            std::size_t used = 0;
            long long n = 0;
            try
            {
                n = std::stoll(text, &used);
            }
            catch (...)
            {
                return std::chrono::milliseconds {0};
            }
            const auto unit = text.substr(used);
            if (unit == "ms")
            {
                return std::chrono::milliseconds {n};
            }
            if (unit == "s")
            {
                return std::chrono::milliseconds {n * 1000};
            }
            if (unit == "m")
            {
                return std::chrono::milliseconds {n * 60000};
            }
            return std::chrono::milliseconds {0};
        }

        void sweepLocked(std::chrono::steady_clock::time_point now)
        {
            for (auto& pit : m_pits)
            {
                if (pit.alive && now >= pit.expiresAt)
                {
                    pit.alive = false;
                    ++m_expired;
                }
            }
        }

        void handle(PitCall call, const httplib::Request& request, Rule& reply)
        {
            PitRequestView view;
            view.call = call;
            view.target = request.target;
            view.body = request.body.empty() ? nlohmann::json() : nlohmann::json::parse(request.body, nullptr, false);
            if (view.body.is_discarded())
            {
                view.body = nlohmann::json();
            }
            Intercept hook;
            {
                std::lock_guard lock(m_mutex);
                view.ordinal = ++m_counts[static_cast<std::size_t>(call)];
                hook = m_intercept;
            }
            if (hook && hook(view, reply))
            {
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard lock(m_mutex);
            sweepLocked(now);
            switch (call)
            {
                case PitCall::Create: create(request, reply, now); return;
                case PitCall::Search: search(view.body, reply, now); return;
                case PitCall::Delete: remove(view.body, reply); return;
            }
        }

        void create(const httplib::Request& request, Rule& reply, std::chrono::steady_clock::time_point now)
        {
            const auto keepAlive = parseKeepAlive(request.get_param_value("keep_alive"));
            PitEntry entry;
            entry.current = "pit-" + std::to_string(m_pits.size() + 1);
            entry.expiresAt = now + keepAlive;
            m_byId[entry.current] = m_pits.size();
            m_pits.push_back(entry);
            const bool partial = m_partialCreates > 0;
            if (partial)
            {
                --m_partialCreates;
            }
            reply.status = 200;
            reply.body =
                nlohmann::json {
                    {"pit_id", entry.current},
                    {"_shards",
                     {{"total", partial ? 2 : 1}, {"successful", 1}, {"skipped", 0}, {"failed", partial ? 1 : 0}}},
                    {"creation_time", 1}}
                    .dump();
        }

        void search(const nlohmann::json& body, Rule& reply, std::chrono::steady_clock::time_point now)
        {
            const auto pit = body.is_object() ? body.find("pit") : body.end();
            std::string id;
            if (pit != body.end() && pit->is_object() && pit->contains("id") && pit->at("id").is_string())
            {
                id = pit->at("id").get<std::string>();
            }
            const auto known = m_byId.find(id);
            if (known == m_byId.end() || !m_pits[known->second].alive)
            {
                reply.status = 404;
                reply.body = contextMissingBody(id);
                return;
            }
            auto& entry = m_pits[known->second];
            if (pit->contains("keep_alive") && pit->at("keep_alive").is_string())
            {
                entry.expiresAt = now + parseKeepAlive(pit->at("keep_alive").get<std::string>());
            }
            if (m_renewNext)
            {
                m_renewNext = false;
                entry.current = "pit-" + std::to_string(known->second + 1) + "-r" + std::to_string(++entry.renewals);
                m_byId[entry.current] = known->second;
            }

            std::uint32_t sliceId = 0;
            std::uint32_t sliceMax = 1;
            if (const auto slice = body.find("slice"); slice != body.end() && slice->is_object())
            {
                sliceId = slice->value("id", 0u);
                sliceMax = std::max<std::uint32_t>(1, slice->value("max", 1u));
            }
            std::int64_t after = 0;
            if (const auto sa = body.find("search_after"); sa != body.end() && sa->is_array() && !sa->empty())
            {
                after = sa->at(0).get<std::int64_t>();
            }
            const auto size = body.value("size", static_cast<std::int64_t>(10));
            nlohmann::json hits = nlohmann::json::array();
            std::int64_t inSlice = 0;
            for (std::int64_t k = 1; k <= m_documents; ++k)
            {
                if (static_cast<std::uint32_t>((k - 1) % sliceMax) != sliceId)
                {
                    continue;
                }
                ++inSlice;
                if (k > after && static_cast<std::int64_t>(hits.size()) < size)
                {
                    hits.push_back(document(k));
                }
            }
            reply.status = 200;
            reply.body =
                nlohmann::json {{"pit_id", entry.current},
                                {"took", 1},
                                {"timed_out", false},
                                {"_shards", {{"total", 1}, {"successful", 1}, {"skipped", 0}, {"failed", 0}}},
                                {"hits", {{"total", {{"value", inSlice}, {"relation", "eq"}}}, {"hits", hits}}}}
                    .dump();
        }

        void remove(const nlohmann::json& body, Rule& reply)
        {
            std::vector<std::string> ids;
            if (body.is_object() && body.contains("pit_id"))
            {
                const auto& field = body.at("pit_id");
                if (field.is_string())
                {
                    ids.push_back(field.get<std::string>());
                }
                else if (field.is_array())
                {
                    for (const auto& one : field)
                    {
                        if (one.is_string())
                        {
                            ids.push_back(one.get<std::string>());
                        }
                    }
                }
            }
            nlohmann::json pits = nlohmann::json::array();
            bool any = false;
            for (const auto& id : ids)
            {
                const auto known = m_byId.find(id);
                const bool live = known != m_byId.end() && m_pits[known->second].alive;
                if (live)
                {
                    m_pits[known->second].alive = false;
                    ++m_deleted;
                    any = true;
                }
                pits.push_back({{"successful", live}, {"pit_id", id}});
            }
            reply.status = any ? 200 : 404;
            reply.body = nlohmann::json {{"pits", pits}}.dump();
        }

        const std::int64_t m_documents;
        mutable std::mutex m_mutex;
        std::size_t m_partialCreates {0}; ///< partialCreates(): creations still to answer partial.
        Intercept m_intercept;
        std::vector<PitEntry> m_pits;
        std::map<std::string, std::size_t> m_byId;
        std::size_t m_counts[3] {0, 0, 0};
        std::size_t m_deleted {0};
        std::size_t m_expired {0};
        bool m_renewNext {false};
    };
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_FAKE_PIT_RESPONDER_HPP
