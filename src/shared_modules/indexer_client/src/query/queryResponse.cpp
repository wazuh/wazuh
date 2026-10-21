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

#include "query/queryResponse.hpp"

#include <string_view>
#include <utility>

#include "query/query.hpp"

// E4a I84-I86, 03 §4.16: pure classifiers of a query response. Every parse goes through
// nlohmann::json::parse(..., allow_exceptions = false); nothing here throws on a hostile body.

namespace indexer_client::detail::query
{
    namespace
    {
        constexpr std::string_view INDEX_NOT_FOUND = "index_not_found_exception";
        constexpr std::string_view VERSION_CONFLICT = "version_conflict_engine_exception";
        constexpr long HTTP_CONFLICT = 409;
        constexpr long HTTP_NOT_FOUND = 404;

        /// Appends at most `limit - out.size()` bytes of `text`, never splitting a UTF-8 sequence.
        void appendBounded(std::string& out, std::string_view text, std::size_t limit)
        {
            if (out.size() >= limit)
            {
                return;
            }
            const std::size_t room = limit - out.size();
            if (text.size() <= room)
            {
                out.append(text);
                return;
            }
            std::size_t cut = room;
            // Back off over continuation bytes (10xxxxxx) so the cut lands on a sequence start.
            while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0U) == 0x80U)
            {
                --cut;
            }
            out.append(text.substr(0, cut));
        }

        /// "<status> <type>: <at most REASON_BODY_BYTES of text>" within OpResult::MAX_REASON. An empty type drops
        /// its space and an empty text drops the colon.
        std::string boundedReason(long status, std::string_view type, std::string_view text)
        {
            std::string reason;
            appendBounded(reason, std::to_string(status), OpResult::MAX_REASON);
            if (!type.empty())
            {
                appendBounded(reason, " ", OpResult::MAX_REASON);
                appendBounded(reason, type, OpResult::MAX_REASON);
            }
            if (!text.empty())
            {
                std::string head;
                appendBounded(head, text, REASON_BODY_BYTES);
                appendBounded(reason, ": ", OpResult::MAX_REASON);
                appendBounded(reason, head, OpResult::MAX_REASON);
            }
            return reason;
        }

        bool is2xx(long status) noexcept
        {
            return status >= 200 && status < 300;
        }

        QueryResponse fail(const HttpResult& result, Cause cause, std::string reason)
        {
            QueryResponse response;
            response.verdict = QueryVerdict::Fail;
            response.cause = cause;
            response.httpStatus = static_cast<int>(result.status);
            response.reason = std::move(reason);
            return response;
        }

        /// A 404 (any query): index_not_found_exception ⇒ NotFound, any other ⇒ Client4xx; the type is in the reason.
        QueryResponse failNotFound(const HttpResult& result)
        {
            const auto type = errorType(result.body);
            return fail(result,
                        type == INDEX_NOT_FOUND ? Cause::NotFound : Cause::Client4xx,
                        errorReason(result.status, result.body));
        }

        /// Defensive: the engine settles every status other than 2xx/404 with classifyRequest before calling here.
        QueryResponse failUnexpected(const HttpResult& result)
        {
            Cause cause = Cause::Unavailable;
            if (result.status >= 400 && result.status < 500)
            {
                cause = Cause::Client4xx;
            }
            else if (result.status >= 500 && result.status < 600)
            {
                cause = Cause::Server5xx;
            }
            return fail(result, cause, errorReason(result.status, result.body));
        }

        /// I84: the size cap, checked before parsing. `size * QUERY_DOM_FACTOR > max` without the multiplication
        /// (no overflow): for integers it is `size > floor(max / QUERY_DOM_FACTOR)`.
        bool tooLarge(const std::string& body, std::uint64_t maxResponseBytes) noexcept
        {
            return static_cast<std::uint64_t>(body.size()) > maxResponseBytes / QUERY_DOM_FACTOR;
        }

        /// A 2xx body: capped, parsed and required to be a JSON object; a failure is Fail ItemPermanent.
        bool parse2xx(const HttpResult& result, std::uint64_t maxResponseBytes, QueryResponse& response)
        {
            if (tooLarge(result.body, maxResponseBytes))
            {
                response = fail(result, Cause::ItemPermanent, "response too large for a query");
                response.tooLarge = true;
                return false;
            }
            auto parsed = nlohmann::json::parse(result.body, nullptr, false);
            if (parsed.is_discarded() || !parsed.is_object())
            {
                response = fail(result, Cause::ItemPermanent, boundedReason(result.status, "unparsable response", {}));
                return false;
            }
            response.httpStatus = static_cast<int>(result.status);
            response.body = std::move(parsed);
            return true;
        }

        /// A `failures` entry that is a version conflict: status 409 or cause.type version_conflict_engine_exception.
        bool isVersionConflict(const nlohmann::json& failure)
        {
            if (!failure.is_object())
            {
                return false;
            }
            const auto status = failure.find("status");
            if (status != failure.end() && status->is_number_integer() && status->get<long>() == HTTP_CONFLICT)
            {
                return true;
            }
            const auto cause = failure.find("cause");
            if (cause != failure.end() && cause->is_object())
            {
                const auto type = cause->find("type");
                return type != cause->end() && type->is_string() &&
                       type->get_ref<const std::string&>() == VERSION_CONFLICT;
            }
            return false;
        }

        /// The type of a `failures` entry (cause.type or reason.type), for the reason; empty when absent.
        std::string failureType(const nlohmann::json& failure)
        {
            if (!failure.is_object())
            {
                return {};
            }
            for (const char* field : {"cause", "reason"})
            {
                const auto node = failure.find(field);
                if (node != failure.end() && node->is_object())
                {
                    const auto type = node->find("type");
                    if (type != node->end() && type->is_string())
                    {
                        return type->get<std::string>();
                    }
                }
            }
            return {};
        }

        std::uint64_t versionConflictsOf(const nlohmann::json& body)
        {
            const auto field = body.find("version_conflicts");
            if (field != body.end() && field->is_number_unsigned())
            {
                return field->get<std::uint64_t>();
            }
            return 0;
        }
    } // namespace

    std::string errorType(const std::string& body)
    {
        // Keeps only `error` (root) and `error.type`: whatever else the body carries is parsed but never stored, so
        // an error body of any size costs no DOM.
        nlohmann::json::parser_callback_t keep =
            [](int depth, nlohmann::json::parse_event_t event, nlohmann::json& parsed)
        {
            switch (event)
            {
                case nlohmann::json::parse_event_t::array_start: return false;
                case nlohmann::json::parse_event_t::object_start: return depth <= 1;
                case nlohmann::json::parse_event_t::key:
                    return (depth == 1 && parsed == "error") || (depth == 2 && parsed == "type");
                default: return true;
            }
        };
        const auto parsed = nlohmann::json::parse(body, keep, false);
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return {};
        }
        const auto error = parsed.find("error");
        if (error == parsed.end())
        {
            return {};
        }
        if (error->is_string())
        {
            return error->get<std::string>();
        }
        if (error->is_object())
        {
            const auto type = error->find("type");
            if (type != error->end() && type->is_string())
            {
                return type->get<std::string>();
            }
        }
        return {};
    }

    std::string errorReason(long status, const std::string& body)
    {
        return boundedReason(status, errorType(body), body);
    }

    QueryResponse classifySearch(const HttpResult& result, std::uint64_t maxResponseBytes)
    {
        if (result.status == HTTP_NOT_FOUND)
        {
            return failNotFound(result);
        }
        if (!is2xx(result.status))
        {
            return failUnexpected(result);
        }
        QueryResponse response;
        parse2xx(result, maxResponseBytes, response);
        return response;
    }

    QueryResponse classifyByQuery(const HttpResult& result, bool isDelete, std::uint64_t maxResponseBytes)
    {
        if (result.status == HTTP_NOT_FOUND)
        {
            if (isDelete && errorType(result.body) == INDEX_NOT_FOUND)
            {
                // I85 / obj. 4: nothing to delete. Only the missing index; any other 404 stays a Client4xx.
                QueryResponse response;
                response.httpStatus = static_cast<int>(result.status);
                response.body = nlohmann::json::object();
                return response;
            }
            return failNotFound(result);
        }
        if (!is2xx(result.status))
        {
            return failUnexpected(result);
        }

        QueryResponse response;
        if (!parse2xx(result, maxResponseBytes, response))
        {
            return response;
        }
        const auto& body = response.body;

        const auto failures = body.find("failures");
        if (failures != body.end() && !failures->is_null())
        {
            if (!failures->is_array())
            {
                return fail(result, Cause::ItemPermanent, boundedReason(result.status, "malformed failures", {}));
            }
            if (!failures->empty())
            {
                bool allConflicts = true;
                for (const auto& failure : *failures)
                {
                    allConflicts = allConflicts && isVersionConflict(failure);
                }
                if (!allConflicts)
                {
                    // The first failure in the reason (obj. 13(f): also an update with conflicts=proceed).
                    const auto& first = failures->front();
                    return fail(result,
                                Cause::ItemPermanent,
                                boundedReason(result.status,
                                              failureType(first),
                                              first.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)));
                }
                // obj. 5: conflicts=abort answers 200 with 409 failures; they feed the I86 budget.
                const auto counted = versionConflictsOf(body);
                response.verdict = QueryVerdict::Conflict;
                response.versionConflicts = counted > 0 ? counted : static_cast<std::uint64_t>(failures->size());
                response.reason = std::to_string(response.versionConflicts) + " version conflicts";
                return response;
            }
        }

        const auto timedOut = body.find("timed_out");
        if (timedOut != body.end() && timedOut->is_boolean() && timedOut->get<bool>())
        {
            response.verdict = QueryVerdict::Retry;
            response.reason = boundedReason(result.status, "by-query timed out", {});
            return response;
        }

        const auto conflicts = versionConflictsOf(body);
        if (conflicts > 0)
        {
            response.verdict = QueryVerdict::Conflict;
            response.versionConflicts = conflicts;
            response.reason = std::to_string(conflicts) + " version conflicts";
        }
        return response;
    }

    QueryResponse classifyExists(const HttpResult& result)
    {
        if (is2xx(result.status) || result.status == HTTP_NOT_FOUND)
        {
            QueryResponse response;
            response.httpStatus = static_cast<int>(result.status);
            response.exists = is2xx(result.status);
            return response;
        }
        return failUnexpected(result);
    }
} // namespace indexer_client::detail::query
