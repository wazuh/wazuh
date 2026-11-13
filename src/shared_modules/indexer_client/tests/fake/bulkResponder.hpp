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

#ifndef _INDEXER_CLIENT_TESTS_FAKE_BULK_RESPONDER_HPP
#define _INDEXER_CLIENT_TESTS_FAKE_BULK_RESPONDER_HPP

// Dynamic `_bulk` answers of the fake indexer. The responder parses the NDJSON it receives
// and answers one item per operation with OpenSearch's real body
// (`{"took":…,"errors":…,"items":[{"index":{"_index":…,"_id":…,"status":…,"result":…}}]}`), scripted by position;
// on demand it serves an unreadable body, one item too many or too few, or a whole-request answer (413, 429 with
// Retry-After, 5xx, 401) instead of items. bulkRule() turns it into a plain Rule, so it lives with every other rule
// of the fake (insertion order, times, hold, latency).

#include "fakeIndexer.hpp"
#include "json.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace indexer_client::testing
{
    /// Rule::pathRegex of the bulk endpoint: `/_bulk` or `/<index>/_bulk` (the query string is never matched).
    inline constexpr std::string_view BULK_PATH_REGEX {"(/[^/]+)?/_bulk"};

    /// `_index` of an operation that names none and arrives on `/_bulk` (no index in the path).
    inline constexpr std::string_view BULK_DEFAULT_INDEX {"wazuh-default"};

    /// One operation of a received `_bulk` request.
    struct BulkOp
    {
        /// Action key: "index", "create", "update" or "delete".
        std::string action;
        /// `_index` of the action line, else the path's index, else BULK_DEFAULT_INDEX.
        std::string index;
        /// `_id` of the action line, if any.
        std::optional<std::string> id;
        /// The source (or update) line that followed the action line, verbatim; empty for `delete`.
        std::string source;
    };

    /**
     * @brief The scripted answer for one position of the items array.
     *
     * The default is a success: 201 `created` for index/create, 200 `updated` for update and 200 `deleted` for delete.
     */
    struct BulkItem
    {
        /// Item status; absent means the action's success status.
        std::optional<int> status;
        /// Item key; absent means the op's action. Any string is served (e.g. "bogus", a key no client knows).
        std::optional<std::string> key;
        /// `result`; absent means the default: created/updated/deleted on 2xx, `not_found` on a delete 404 without
        /// an error, and no `result` otherwise.
        std::optional<std::string> result;
        /// When set the item carries `error: {type, reason[, caused_by]}` (and no default `result`).
        std::optional<std::string> errorType;
        /// `error.reason`; absent means a generic reason.
        std::optional<std::string> errorReason;
        /// When set, `error.caused_by: {type, reason}`.
        std::optional<std::string> causedByType;
        /// `error.caused_by.reason`; absent means a generic reason.
        std::optional<std::string> causedByReason;
        /// Serve the item without its `status` member (a malformed item).
        bool omitStatus {false};

        /// The default success.
        static BulkItem ok()
        {
            return {};
        }

        /// A success with this @p status and @p result (e.g. 200 "noop").
        static BulkItem ok(int status, std::string result)
        {
            BulkItem item;
            item.status = status;
            item.result = std::move(result);
            return item;
        }

        /// A failed item: @p status with `error.type` = @p type and an optional @p reason.
        static BulkItem failed(int status, std::string type, std::optional<std::string> reason = std::nullopt)
        {
            BulkItem item;
            item.status = status;
            item.errorType = std::move(type);
            item.errorReason = std::move(reason);
            return item;
        }

        /// A delete of a missing document: 404 `not_found`, no error.
        static BulkItem notFound()
        {
            BulkItem item;
            item.status = 404;
            return item;
        }

        /// 409 `version_conflict_engine_exception`.
        static BulkItem conflict()
        {
            return failed(409,
                          "version_conflict_engine_exception",
                          "[1]: version conflict, document already exists (current version [1])");
        }

        /// 429 `es_rejected_execution_exception` (a full write queue).
        static BulkItem rejected()
        {
            return failed(429,
                          "es_rejected_execution_exception",
                          "rejected execution of coordinating operation [coordinating_and_primary_bytes=0, "
                          "replica_bytes=0, all_bytes=0, coordinating_operation_bytes=1024, max_coordinating_and_"
                          "primary_bytes=104857600]");
        }

        /// This item with `error.caused_by` = {@p type, @p reason}.
        BulkItem causedBy(std::string type, std::optional<std::string> reason = std::nullopt) &&
        {
            causedByType = std::move(type);
            causedByReason = std::move(reason);
            return std::move(*this);
        }
    };

    /// What a scripted `_bulk` answer is.
    enum class BulkMode
    {
        /// One item per received op (plus/minus BulkScript::itemDelta), scripted by position.
        Items,
        /// The items body cut in half: a 2xx whose body is not JSON.
        Unreadable,
        /// A whole-request answer (BulkScript::status, body, retryAfter) and no items.
        Request
    };

    /**
     * @brief The answer to one `_bulk` request.
     */
    struct BulkScript
    {
        BulkMode mode {BulkMode::Items};
        /// Items: the answer for position i (0-based); positions without an entry get #fallback.
        std::map<std::size_t, BulkItem> at;
        /// Items: the answer for every position that #at does not script.
        BulkItem fallback;
        /// Items: > 0 appends that many extra items (#fallback, on a synthetic `index` op), < 0 drops that many from
        /// the end (never below zero items).
        int itemDelta {0};
        /// Items: `errors` as served; absent means coherent (true iff some served item carries `error`).
        std::optional<bool> errors;
        /// Items/Unreadable: the HTTP status. Request: the status of the whole answer.
        int status {200};
        /// Request: the body served verbatim.
        std::string body;
        /// Request: the Retry-After header value, if any.
        std::optional<std::string> retryAfter;
        /// `took` of the items body (milliseconds).
        int took {3};
        /// Hold this answer until FakeIndexer::releaseHeld(), as Rule::hold does.
        bool hold {false};
        /// Delay before answering (after the hold), as Rule::latency does.
        std::chrono::milliseconds latency {0};
        /// Items: a request holding more ops than this gets 413 with an empty body instead (the Split413 case).
        std::optional<std::size_t> maxOps;

        /// Every op succeeds.
        static BulkScript items()
        {
            return {};
        }

        /// Every op succeeds except the scripted positions.
        static BulkScript items(std::map<std::size_t, BulkItem> positions)
        {
            BulkScript script;
            script.at = std::move(positions);
            return script;
        }

        /// Every op gets @p item.
        static BulkScript all(BulkItem item)
        {
            BulkScript script;
            script.fallback = std::move(item);
            return script;
        }

        /// 200 with a body that is not JSON.
        static BulkScript unreadable()
        {
            BulkScript script;
            script.mode = BulkMode::Unreadable;
            return script;
        }

        /// A whole-request answer.
        static BulkScript request(int status, std::string body, std::optional<std::string> retryAfter = std::nullopt)
        {
            BulkScript script;
            script.mode = BulkMode::Request;
            script.status = status;
            script.body = std::move(body);
            script.retryAfter = std::move(retryAfter);
            return script;
        }

        /// Items, except that a request with more than @p ops operations gets 413 (empty body): a split ends there.
        static BulkScript tooLargeAbove(std::size_t ops)
        {
            BulkScript script;
            script.maxOps = ops;
            return script;
        }

        /// 413 with an empty body, as OpenSearch answers a request over `http.max_content_length`.
        static BulkScript tooLarge()
        {
            return request(413, std::string {});
        }

        /// 429 `es_rejected_execution_exception` for the whole request, with @p retryAfter if given.
        static BulkScript throttled(std::optional<std::string> retryAfter = std::nullopt)
        {
            return request(
                429,
                R"({"error":{"root_cause":[{"type":"es_rejected_execution_exception","reason":)"
                R"("rejected execution of coordinating operation"}],"type":"es_rejected_execution_exception",)"
                R"("reason":"rejected execution of coordinating operation"},"status":429})",
                std::move(retryAfter));
        }

        /// A 5xx (503 by default) with OpenSearch's error shape.
        static BulkScript serverError(int status = 503)
        {
            return request(
                status,
                R"({"error":{"root_cause":[{"type":"cluster_manager_not_discovered_exception","reason":null}],)"
                R"("type":"cluster_manager_not_discovered_exception","reason":null},"status":)" +
                    std::to_string(status) + "}");
        }

        /// 401 with the security plugin's plain `Unauthorized`.
        static BulkScript unauthorized()
        {
            return request(401, "Unauthorized");
        }

        /// This script, held until FakeIndexer::releaseHeld().
        BulkScript held() &&
        {
            hold = true;
            return std::move(*this);
        }
    };

    /// A rendered answer.
    struct BulkReply
    {
        int status {200};
        std::string body;
        std::optional<std::string> retryAfter;
        bool hold {false};
        std::chrono::milliseconds latency {0};
    };

    /**
     * @brief Dynamic `_bulk` responder. Thread-safe; create it with std::make_shared and install it with bulkRule().
     *
     * Each request consumes the oldest pushed script, or uses the default script when none is queued. A request
     * whose NDJSON does not parse is answered 400 `illegal_argument_exception` (whatever the script) and recorded with
     * the ops parsed before the bad line.
     */
    class BulkResponder final
    {
    public:
        explicit BulkResponder(BulkScript defaultScript = {})
            : m_default(std::move(defaultScript))
        {
        }

        /// Replaces the script used when the queue is empty.
        void setDefault(BulkScript script)
        {
            std::lock_guard lock(m_mutex);
            m_default = std::move(script);
        }

        /// Queues a script for the next request that finds the queue at this point (FIFO).
        void push(BulkScript script)
        {
            std::lock_guard lock(m_mutex);
            m_queue.push_back(std::move(script));
        }

        /// Scripts still queued.
        std::size_t queued() const
        {
            std::lock_guard lock(m_mutex);
            return m_queue.size();
        }

        /// The ops of every request answered so far, in arrival order.
        std::vector<std::vector<BulkOp>> received() const
        {
            std::lock_guard lock(m_mutex);
            return m_received;
        }

        /// Requests answered so far.
        std::size_t answered() const
        {
            std::lock_guard lock(m_mutex);
            return m_received.size();
        }

        /// Total ops received so far.
        std::size_t opCount() const
        {
            std::lock_guard lock(m_mutex);
            std::size_t total {0};
            for (const auto& ops : m_received)
            {
                total += ops.size();
            }
            return total;
        }

        /**
         * @brief Answers one `_bulk` request (what bulkRule() calls; usable without HTTP).
         *
         * @param path Request path without the query string (`/_bulk` or `/<index>/_bulk`).
         * @param body The NDJSON body.
         */
        BulkReply answer(std::string_view path, std::string_view body)
        {
            const std::string pathIndex = indexFromPath(path);
            std::vector<BulkOp> ops;
            const auto parseError = parse(body, pathIndex, ops);

            BulkScript script;
            std::size_t seqNo {0};
            {
                std::lock_guard lock(m_mutex);
                if (!m_queue.empty())
                {
                    script = std::move(m_queue.front());
                    m_queue.pop_front();
                }
                else
                {
                    script = m_default;
                }
                m_received.push_back(ops);
                seqNo = m_seqNo;
                m_seqNo += ops.size() + static_cast<std::size_t>(std::max(0, script.itemDelta));
            }

            BulkReply reply;
            reply.hold = script.hold;
            reply.latency = script.latency;
            if (parseError.has_value())
            {
                reply.status = 400;
                reply.body = illegalArgument(*parseError);
                return reply;
            }
            reply.status = script.status;
            if (script.maxOps.has_value() && ops.size() > *script.maxOps)
            {
                reply.status = 413;
                reply.body.clear();
                return reply;
            }
            if (script.mode == BulkMode::Request)
            {
                reply.body = script.body;
                reply.retryAfter = script.retryAfter;
                return reply;
            }
            reply.body = renderItems(ops, script, seqNo);
            if (script.mode == BulkMode::Unreadable)
            {
                // Any proper prefix of a JSON object is unbalanced, hence not JSON.
                reply.body.resize(reply.body.size() / 2);
            }
            return reply;
        }

        /**
         * @brief OpenSearch's items body for @p ops under @p script (BulkMode::Items semantics).
         *
         * @param firstSeqNo `_seq_no` of the first item (successes count up from it).
         */
        static std::string renderItems(const std::vector<BulkOp>& ops, const BulkScript& script, std::size_t firstSeqNo)
        {
            std::vector<const BulkOp*> served;
            served.reserve(ops.size());
            for (const auto& op : ops)
            {
                served.push_back(&op);
            }
            BulkOp extra {"index", std::string(BULK_DEFAULT_INDEX), std::nullopt, "{}"};
            if (script.itemDelta > 0)
            {
                for (int i = 0; i < script.itemDelta; ++i)
                {
                    served.push_back(&extra);
                }
            }
            else if (script.itemDelta < 0)
            {
                const auto drop = std::min(served.size(), static_cast<std::size_t>(-script.itemDelta));
                served.resize(served.size() - drop);
            }

            auto items = nlohmann::ordered_json::array();
            bool anyError {false};
            for (std::size_t i = 0; i < served.size(); ++i)
            {
                const auto it = script.at.find(i);
                const BulkItem& item = it != script.at.end() ? it->second : script.fallback;
                const std::string id =
                    served[i]->id.value_or(served[i] == &extra ? "extra-" + std::to_string(i) : autoId(firstSeqNo + i));
                items.push_back(renderItem(*served[i], id, item, firstSeqNo + i, anyError));
            }

            nlohmann::ordered_json root;
            root["took"] = script.took;
            root["errors"] = script.errors.value_or(anyError);
            root["items"] = std::move(items);
            return root.dump();
        }

    private:
        static std::string indexFromPath(std::string_view path)
        {
            static constexpr std::string_view SUFFIX {"/_bulk"};
            if (path.size() > SUFFIX.size() + 1 && path.substr(path.size() - SUFFIX.size()) == SUFFIX &&
                path.front() == '/')
            {
                return std::string(path.substr(1, path.size() - SUFFIX.size() - 1));
            }
            return std::string(BULK_DEFAULT_INDEX);
        }

        /// OpenSearch's id of an op without `_id` (any unique string; real ones are 20-char base64).
        static std::string autoId(std::size_t seqNo)
        {
            return "auto-" + std::to_string(seqNo);
        }

        /// Parses the NDJSON into @p ops; on error returns OpenSearch-like reason (the ops before it stay in @p ops).
        static std::optional<std::string>
        parse(std::string_view body, const std::string& pathIndex, std::vector<BulkOp>& ops)
        {
            std::vector<std::string_view> lines;
            std::size_t start {0};
            while (start < body.size())
            {
                auto end = body.find('\n', start);
                if (end == std::string_view::npos)
                {
                    end = body.size();
                }
                const auto line = body.substr(start, end - start);
                if (!line.empty())
                {
                    lines.push_back(line);
                }
                start = end + 1;
            }

            for (std::size_t i = 0; i < lines.size(); ++i)
            {
                const std::string where = "line [" + std::to_string(i + 1) + "]";
                auto action = nlohmann::json::parse(lines[i], nullptr, false);
                if (action.is_discarded() || !action.is_object() || action.size() != 1)
                {
                    return "Malformed action/metadata " + where + ", expected START_OBJECT";
                }
                // A real iterator: binding to *action.items().begin() would reference a proxy that dies with the
                // statement (stack-use-after-scope under ASAN).
                const auto entry = action.begin();
                const std::string key = entry.key();
                const auto& meta = entry.value();
                if ((key != "index" && key != "create" && key != "update" && key != "delete") || !meta.is_object())
                {
                    return "Malformed action/metadata " + where + ", expected a simple action";
                }
                BulkOp op;
                op.action = key;
                op.index = pathIndex;
                if (const auto index = meta.find("_index"); index != meta.end() && index->is_string())
                {
                    op.index = index->get<std::string>();
                }
                if (const auto id = meta.find("_id"); id != meta.end() && id->is_string())
                {
                    op.id = id->get<std::string>();
                }
                if (key != "delete")
                {
                    if (i + 1 >= lines.size())
                    {
                        return "The bulk request must be terminated by a newline [\\n]";
                    }
                    ++i;
                    if (nlohmann::json::parse(lines[i], nullptr, false).is_discarded())
                    {
                        return "failed to parse source of " + where;
                    }
                    op.source = std::string(lines[i]);
                }
                ops.push_back(std::move(op));
            }
            return std::nullopt;
        }

        static std::string illegalArgument(const std::string& reason)
        {
            nlohmann::ordered_json cause;
            cause["type"] = "illegal_argument_exception";
            cause["reason"] = reason;
            nlohmann::ordered_json error;
            error["root_cause"] = nlohmann::ordered_json::array({cause});
            error["type"] = "illegal_argument_exception";
            error["reason"] = reason;
            nlohmann::ordered_json root;
            root["error"] = std::move(error);
            root["status"] = 400;
            return root.dump();
        }

        static int successStatus(const std::string& action)
        {
            return action == "index" || action == "create" ? 201 : 200;
        }

        static std::string successResult(const std::string& action, int status)
        {
            if (action == "delete")
            {
                return "deleted";
            }
            if (action == "update")
            {
                return "updated";
            }
            return status == 201 ? "created" : "updated";
        }

        static nlohmann::ordered_json
        renderItem(const BulkOp& op, const std::string& id, const BulkItem& item, std::size_t seqNo, bool& anyError)
        {
            const int status = item.status.value_or(successStatus(op.action));
            const bool success = status >= 200 && status < 300;
            const bool hasError = item.errorType.has_value();

            std::optional<std::string> result = item.result;
            if (!result.has_value() && !hasError)
            {
                if (success)
                {
                    result = successResult(op.action, status);
                }
                else if (status == 404 && op.action == "delete")
                {
                    result = "not_found";
                }
            }

            nlohmann::ordered_json body;
            body["_index"] = op.index;
            body["_id"] = id;
            if (!hasError)
            {
                body["_version"] = 1;
            }
            if (result.has_value())
            {
                body["result"] = *result;
            }
            if (!hasError)
            {
                body["_shards"] = {{"total", 2}, {"successful", 1}, {"failed", 0}};
                body["_seq_no"] = seqNo;
                body["_primary_term"] = 1;
            }
            if (!item.omitStatus)
            {
                body["status"] = status;
            }
            if (hasError)
            {
                anyError = true;
                nlohmann::ordered_json error;
                error["type"] = *item.errorType;
                error["reason"] = item.errorReason.value_or("failed to execute " + op.action);
                error["index"] = op.index;
                if (item.causedByType.has_value())
                {
                    nlohmann::ordered_json cause;
                    cause["type"] = *item.causedByType;
                    cause["reason"] = item.causedByReason.value_or("caused by " + *item.causedByType);
                    error["caused_by"] = std::move(cause);
                }
                body["error"] = std::move(error);
            }

            nlohmann::ordered_json wrapped;
            wrapped[item.key.value_or(op.action)] = std::move(body);
            return wrapped;
        }

        mutable std::mutex m_mutex;
        BulkScript m_default;
        std::deque<BulkScript> m_queue;
        std::vector<std::vector<BulkOp>> m_received;
        std::size_t m_seqNo {0};
    };

    /**
     * @brief A Rule that answers `POST /_bulk` and `POST /<index>/_bulk` through @p responder.
     *
     * The rule keeps the responder alive. Tune it like any rule (times, hold, latency) before FakeIndexer::addRule();
     * a script's own hold/latency add to the rule's (either one holding holds the answer). The responder owns the
     * status, the body and the Retry-After header of the answer (the rule's own values are ignored).
     */
    inline Rule bulkRule(std::shared_ptr<BulkResponder> responder)
    {
        Rule rule;
        rule.method = "POST";
        rule.pathRegex = std::string(BULK_PATH_REGEX);
        rule.dynamic = [responder = std::move(responder)](const httplib::Request& request, Rule& reply)
        {
            auto answer = responder->answer(request.path, request.body);
            reply.status = answer.status;
            reply.body = std::move(answer.body);
            reply.retryAfter = std::move(answer.retryAfter);
            reply.hold = reply.hold || answer.hold;
            reply.latency += answer.latency;
            // A whole-request answer is a plain body; never stream or cut it.
            reply.bodySize.reset();
        };
        return rule;
    }
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_FAKE_BULK_RESPONDER_HPP
