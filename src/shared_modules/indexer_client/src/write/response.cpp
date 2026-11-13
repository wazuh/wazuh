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

#include "write/response.hpp"

#include <cstdint>
#include <exception>
#include <string_view>
#include <utility>

#include <simdjson.h>

#ifdef INDEXER_CLIENT_TESTING
#include "testing/hooks.hpp"
#endif

// The request table over the HttpResult and the item table over a 2xx `_bulk` body, streamed with simdjson
// ondemand (no DOM, no simdjson exception: every call goes through its error codes). `errors` is never used to skip
// anything: every item is classified, also under `"errors":false`.

namespace indexer_client::detail::write
{
    static_assert(simdjson::SIMDJSON_PADDING <= RESPONSE_PADDING,
                  "the transport must reserve at least simdjson's padding");

    namespace
    {
        /// Above this the thread's parser is rebuilt after the parse, so a single large response does not pin its
        /// buffers on a pool thread for the runtime's lifetime.
        constexpr std::size_t PARSER_CAPACITY_CAP = 4 * 1024 * 1024;

        simdjson::ondemand::parser& threadParser()
        {
            thread_local simdjson::ondemand::parser parser;
            return parser;
        }

        void trimParser()
        {
            auto& parser = threadParser();
            if (parser.capacity() > PARSER_CAPACITY_CAP)
            {
                parser = simdjson::ondemand::parser {};
            }
        }

        /// Appends at most `room` bytes of `text`, never splitting a UTF-8 sequence.
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

        std::string bounded(std::string_view text, std::size_t limit)
        {
            std::string out;
            appendBounded(out, text, limit);
            return out;
        }

        /// "HTTP <status>" plus, when there is one, the start of the response body (bounded).
        std::string httpReason(const HttpResult& result, std::string_view what = {})
        {
            std::string reason;
            if (!what.empty())
            {
                appendBounded(reason, what, OpResult::MAX_REASON);
                appendBounded(reason, " ", OpResult::MAX_REASON);
            }
            appendBounded(reason, "HTTP " + std::to_string(result.status), OpResult::MAX_REASON);
            if (!result.body.empty())
            {
                appendBounded(reason, ": ", OpResult::MAX_REASON);
                appendBounded(reason, result.body, OpResult::MAX_REASON);
            }
            return reason;
        }

        /// The op's lastCause for a transport failure (none of them reaches the per-op table).
        Cause transportCause(TransportCause cause) noexcept
        {
            switch (cause)
            {
                case TransportCause::Timeout: return Cause::TransportTimeout;
                case TransportCause::Tls:
                case TransportCause::TlsConfig: return Cause::TransportTls;
                case TransportCause::Cancelled: return Cause::Cancelled;
                // The runtime, not the node, is at fault (transport.hpp): never reported as a connection failure.
                case TransportCause::LocalError: return Cause::InvalidState;
                case TransportCause::Shutdown: return Cause::Shutdown;
                case TransportCause::ResponseTooLarge: return Cause::ItemPermanent;
                case TransportCause::Connect:
                case TransportCause::SendError:
                case TransportCause::RecvError:
                case TransportCause::PartialResponse:
                case TransportCause::None:
                default: return Cause::TransportConnect;
            }
        }

        std::string transportReason(const HttpResult& result)
        {
            return bounded(std::string(toString(result.cause)) + " (curl " + std::to_string(result.curlCode) + ")",
                           OpResult::MAX_REASON);
        }

        RequestOutcome classifyTransport(const HttpResult& result, std::size_t batchSize)
        {
            RequestOutcome out;
            out.cause = transportCause(result.cause);
            out.reason = transportReason(result);
            switch (result.cause)
            {
                case TransportCause::Cancelled:
                case TransportCause::Shutdown: out.verdict = RequestVerdict::Ignore; break;
                case TransportCause::ResponseTooLarge:
                    if (batchSize > 1)
                    {
                        out.verdict = RequestVerdict::Split;
                    }
                    else
                    {
                        out.verdict = RequestVerdict::FailBatch;
                        out.reason = "response over maxResponseBytes";
                    }
                    break;
                case TransportCause::TlsConfig:
                case TransportCause::LocalError: out.verdict = RequestVerdict::Retry; break;
                default:
                    // Timeout, Connect, SendError, RecvError, PartialResponse, Tls; anything the transport adds later
                    // falls here only when it is node-attributable, else it is a local retry.
                    out.verdict = result.nodeAttributable || nodeAttributable(result.cause) ? RequestVerdict::Failover
                                                                                            : RequestVerdict::Retry;
                    break;
            }
            return out;
        }

        RequestOutcome classifyStatus(const HttpResult& result, std::size_t batchSize)
        {
            RequestOutcome out;
            const long status = result.status;
            if (status >= 200 && status < 300)
            {
                out.verdict = RequestVerdict::Items;
                return out;
            }
            if (status == 429)
            {
                out.verdict = RequestVerdict::Throttled;
                out.cause = Cause::Throttled;
            }
            else if (status == 413)
            {
                out.cause = Cause::PayloadTooLarge;
                out.verdict = batchSize > 1 ? RequestVerdict::Split : RequestVerdict::FailBatch;
            }
            else if (status == 408)
            {
                out.verdict = RequestVerdict::Retry;
                out.cause = Cause::TransportTimeout;
            }
            else if (status >= 500 && status < 600)
            {
                out.verdict = RequestVerdict::Retry;
                out.cause = Cause::Server5xx;
            }
            else if (status == 401 || status == 403)
            {
                // Deviation from "4xx is permanent": the probe marks the node; dropping data over credentials
                // would be silent.
                out.verdict = RequestVerdict::Retry;
                out.cause = Cause::Client4xx;
            }
            else if (status >= 300 && status < 400)
            {
                out.verdict = RequestVerdict::FailBatch;
                out.cause = Cause::Client4xx;
                out.reason = httpReason(result, "unexpected 3xx:");
                return out;
            }
            else if (status >= 400 && status < 500)
            {
                out.verdict = RequestVerdict::FailBatch; // Includes a request-level 409.
                out.cause = Cause::Client4xx;
            }
            else
            {
                // 1xx as a final status, >= 600 or 0 without a transport cause: not in the table; retried with an
                // attempt (bounded by maxAttempts) rather than dropped.
                out.verdict = RequestVerdict::Retry;
                out.cause = Cause::Server5xx;
                out.reason = httpReason(result, "unexpected status:");
                return out;
            }
            out.reason = httpReason(result);
            return out;
        }

        ItemOutcome outcomeOf(std::string_view result) noexcept
        {
            if (result == "created")
            {
                return ItemOutcome::Created;
            }
            if (result == "updated")
            {
                return ItemOutcome::Updated;
            }
            if (result == "noop")
            {
                return ItemOutcome::Noop;
            }
            if (result == "deleted")
            {
                return ItemOutcome::Deleted;
            }
            return ItemOutcome::None;
        }

        enum class OpKey
        {
            Unknown,
            Index,
            Create,
            Delete,
            Update
        };

        OpKey opKeyOf(std::string_view key) noexcept
        {
            if (key == "index")
            {
                return OpKey::Index;
            }
            if (key == "create")
            {
                return OpKey::Create;
            }
            if (key == "delete")
            {
                return OpKey::Delete;
            }
            if (key == "update")
            {
                return OpKey::Update;
            }
            return OpKey::Unknown;
        }

        /// What one item's operation object holds (copied out of the parser's string buffer).
        struct RawItem final
        {
            std::optional<std::int64_t> status;
            std::string result;
            bool hasError {false};
            std::string errorType;
            std::string errorReason;
            std::string causedByType;
            std::string causedByReason;
        };

        /// Outcome of reading a value: Ok, a type mismatch confined to the item (malformed), or a fatal parse error.
        enum class Read
        {
            Ok,
            Malformed,
            Fatal
        };

        /// Only a type or number mismatch is confined to the value (ondemand leaves it unconsumed and the iterator
        /// skips it); every other error is structural and makes the whole body unreadable.
        Read fromError(simdjson::error_code error) noexcept
        {
            switch (error)
            {
                case simdjson::SUCCESS: return Read::Ok;
                case simdjson::INCORRECT_TYPE:
                case simdjson::NUMBER_OUT_OF_RANGE:
                case simdjson::BIGINT_ERROR:
                case simdjson::NUMBER_ERROR: return Read::Malformed;
                default: return Read::Fatal;
            }
        }

        /// Reads a string value if it is one; another type leaves `out` empty and is not an error of the item.
        Read readString(simdjson::ondemand::value value, std::string& out, std::size_t limit)
        {
            simdjson::ondemand::json_type type {};
            if (const auto error = value.type().get(type); error)
            {
                return fromError(error);
            }
            if (type != simdjson::ondemand::json_type::string)
            {
                return Read::Ok;
            }
            std::string_view text;
            if (const auto error = value.get_string().get(text); error)
            {
                return fromError(error);
            }
            out = bounded(text, limit);
            return Read::Ok;
        }

        /// `{type, reason}` of an error or of its caused_by; other fields are skipped.
        Read readTypeReason(simdjson::ondemand::object object,
                            std::string& type,
                            std::string& reason,
                            std::string* causedByType,
                            std::string* causedByReason)
        {
            for (auto entry : object)
            {
                simdjson::ondemand::field field;
                std::string_view key;
                if (const auto error = std::move(entry).get(field); error)
                {
                    return Read::Fatal;
                }
                if (const auto error = field.unescaped_key().get(key); error)
                {
                    return Read::Fatal;
                }
                Read read = Read::Ok;
                if (key == "type")
                {
                    read = readString(field.value(), type, OpResult::MAX_ITEM_ERROR_TYPE);
                }
                else if (key == "reason")
                {
                    read = readString(field.value(), reason, OpResult::MAX_REASON);
                }
                else if (key == "caused_by" && causedByType != nullptr)
                {
                    simdjson::ondemand::object inner;
                    if (const auto error = field.value().get_object().get(inner); error)
                    {
                        read = fromError(error) == Read::Fatal ? Read::Fatal : Read::Ok;
                    }
                    else
                    {
                        read = readTypeReason(inner, *causedByType, *causedByReason, nullptr, nullptr);
                    }
                }
                if (read == Read::Fatal)
                {
                    return read;
                }
            }
            return Read::Ok;
        }

        Read readOperation(simdjson::ondemand::object object, RawItem& item)
        {
            for (auto entry : object)
            {
                simdjson::ondemand::field field;
                std::string_view key;
                if (const auto error = std::move(entry).get(field); error)
                {
                    return Read::Fatal;
                }
                if (const auto error = field.unescaped_key().get(key); error)
                {
                    return Read::Fatal;
                }
                if (key == "status")
                {
                    std::int64_t status {0};
                    if (const auto error = field.value().get_int64().get(status); error)
                    {
                        if (fromError(error) == Read::Fatal)
                        {
                            return Read::Fatal;
                        }
                    }
                    else if (status >= 0 && status <= 999)
                    {
                        item.status = status; // Out of range: as if absent (malformed item).
                    }
                }
                else if (key == "result")
                {
                    if (readString(field.value(), item.result, 32) == Read::Fatal)
                    {
                        return Read::Fatal;
                    }
                }
                else if (key == "error")
                {
                    item.hasError = true;
                    simdjson::ondemand::value value = field.value();
                    simdjson::ondemand::json_type type {};
                    if (const auto error = value.type().get(type); error)
                    {
                        return fromError(error);
                    }
                    Read read = Read::Ok;
                    if (type == simdjson::ondemand::json_type::object)
                    {
                        simdjson::ondemand::object error;
                        if (const auto code = value.get_object().get(error); code)
                        {
                            return fromError(code);
                        }
                        read = readTypeReason(
                            error, item.errorType, item.errorReason, &item.causedByType, &item.causedByReason);
                    }
                    else if (type == simdjson::ondemand::json_type::string)
                    {
                        // Older servers answer a bare string.
                        read = readString(value, item.errorReason, OpResult::MAX_REASON);
                    }
                    if (read == Read::Fatal)
                    {
                        return read;
                    }
                }
            }
            return Read::Ok;
        }

        ItemResult malformed()
        {
            ItemResult out;
            out.verdict = ItemVerdict::Permanent;
            out.reason = "malformed item";
            return out;
        }

        ItemResult verdictOf(OpKey key, RawItem&& raw)
        {
            ItemResult out;
            out.httpStatus = static_cast<int>(*raw.status);
            out.itemErrorType = std::move(raw.errorType);
            const long status = static_cast<long>(*raw.status);

            if (status >= 200 && status < 300)
            {
                out.verdict = ItemVerdict::Ok;
                out.outcome = outcomeOf(raw.result);
                return out;
            }

            out.reason = std::move(raw.errorReason);
            if (!raw.causedByType.empty() || !raw.causedByReason.empty())
            {
                appendBounded(out.reason, out.reason.empty() ? "" : "; caused by ", OpResult::MAX_REASON);
                appendBounded(out.reason, raw.causedByType, OpResult::MAX_REASON);
                appendBounded(out.reason, ": ", OpResult::MAX_REASON);
                appendBounded(out.reason, raw.causedByReason, OpResult::MAX_REASON);
            }

            const std::string_view type = out.itemErrorType;
            if (key == OpKey::Delete && status == 404 && !raw.hasError && raw.result == "not_found")
            {
                out.verdict = ItemVerdict::NotFound;
                out.outcome = ItemOutcome::NotFound;
            }
            else if (status == 429 || (status >= 500 && status < 600) || type == "cluster_block_exception" ||
                     type == "es_rejected_execution_exception")
            {
                out.verdict = ItemVerdict::Retry;
            }
            else if (status == 409 && type == "version_conflict_engine_exception")
            {
                out.verdict = ItemVerdict::Conflict;
            }
            else
            {
                // index_not_found_exception, a 409 of another type, any other 4xx and anything outside the table.
                out.verdict = ItemVerdict::Permanent;
            }
            return out;
        }

        /// One element of `items`. Fatal only on a structural error of the body; anything else is a malformed item.
        Read classifyItem(simdjson::ondemand::value element, ItemResult& out)
        {
            simdjson::ondemand::object object;
            if (const auto error = element.get_object().get(object); error)
            {
                const Read read = fromError(error);
                out = malformed();
                return read == Read::Fatal ? read : Read::Ok;
            }

            std::size_t keys {0};
            OpKey opKey {OpKey::Unknown};
            RawItem raw;
            bool opIsObject {false};
            for (auto entry : object)
            {
                simdjson::ondemand::field field;
                std::string_view key;
                if (const auto error = std::move(entry).get(field); error)
                {
                    return Read::Fatal;
                }
                if (const auto error = field.unescaped_key().get(key); error)
                {
                    return Read::Fatal;
                }
                if (++keys > 1)
                {
                    continue; // The value is skipped by the iterator; the item is malformed below.
                }
                opKey = opKeyOf(key);
                if (opKey == OpKey::Unknown)
                {
                    continue;
                }
                simdjson::ondemand::object operation;
                if (const auto error = field.value().get_object().get(operation); error)
                {
                    if (fromError(error) == Read::Fatal)
                    {
                        return Read::Fatal;
                    }
                    continue;
                }
                opIsObject = true;
                if (readOperation(operation, raw) == Read::Fatal)
                {
                    return Read::Fatal;
                }
            }

            if (keys != 1 || opKey == OpKey::Unknown || !opIsObject || !raw.status)
            {
                out = malformed();
                return Read::Ok;
            }
            out = verdictOf(opKey, std::move(raw));
            return Read::Ok;
        }

        std::optional<std::vector<ItemResult>> parseItems(std::string& body, std::size_t expected, std::string& why)
        {
            const auto fail = [&why](std::string text)
            {
                why = std::move(text);
                return std::nullopt;
            };
            auto& parser = threadParser();
            simdjson::ondemand::document document;
            if (const auto code = parser.iterate(body).get(document); code != simdjson::SUCCESS)
            {
                return fail(std::string("unreadable body: ") + simdjson::error_message(code));
            }
            simdjson::ondemand::object root;
            if (document.get_object().get(root) != simdjson::SUCCESS)
            {
                return fail("unreadable body: the root is not an object");
            }

            std::vector<ItemResult> results;
            bool sawItems {false};
            for (auto entry : root)
            {
                simdjson::ondemand::field field;
                std::string_view key;
                if (std::move(entry).get(field) != simdjson::SUCCESS ||
                    field.unescaped_key().get(key) != simdjson::SUCCESS)
                {
                    return fail("unreadable body: bad key");
                }
                if (key != "items" || sawItems)
                {
                    continue; // `took`, `errors`, ...: skipped, never used to skip items.
                }
                sawItems = true;
                simdjson::ondemand::array items;
                if (field.value().get_array().get(items) != simdjson::SUCCESS)
                {
                    return fail("unreadable body: items is not an array");
                }
                results.reserve(expected);
                for (auto element : items)
                {
                    simdjson::ondemand::value value;
                    if (element.get(value) != simdjson::SUCCESS)
                    {
                        return fail("unreadable body: bad item");
                    }
                    if (results.size() == expected)
                    {
                        return fail("items: more than the " + std::to_string(expected) + " expected");
                    }
                    ItemResult item;
                    if (classifyItem(value, item) == Read::Fatal)
                    {
                        return fail("unreadable body: bad item " + std::to_string(results.size()));
                    }
                    results.push_back(std::move(item));
                }
            }
            if (!sawItems)
            {
                return fail("unreadable body: no items");
            }
            if (results.size() != expected)
            {
                return fail("items: got " + std::to_string(results.size()) + ", expected " + std::to_string(expected));
            }
            if (!document.at_end())
            {
                return fail("unreadable body: content after the document");
            }
            return results;
        }
    } // namespace

    RequestOutcome classifyRequest(const HttpResult& result, std::size_t batchSize)
    {
        RequestOutcome out = result.cause == TransportCause::None ? classifyStatus(result, batchSize)
                                                                  : classifyTransport(result, batchSize);
        out.httpStatus = static_cast<int>(result.status);
        out.retryAfter = result.retryAfter;
        out.mayHaveSent = result.mayHaveSent;
        return out;
    }

    std::optional<std::vector<ItemResult>> classifyItems(std::string& body, std::size_t expected, std::string* reason)
    {
        std::optional<std::vector<ItemResult>> results;
        std::string why;
        try
        {
            results = parseItems(body, expected, why);
        }
        catch (const std::exception&)
        {
            // Only an allocation can throw here (simdjson is used through its error codes): unreadable.
            results.reset();
            why = "allocation failed";
        }
        if (!results && reason)
        {
            *reason = why.substr(0, OpResult::MAX_REASON);
        }
        trimParser();
        return results;
    }
} // namespace indexer_client::detail::write

#ifdef INDEXER_CLIENT_TESTING
namespace indexer_client::testing_hooks
{
    std::size_t parserCapacity()
    {
        return indexer_client::detail::write::threadParser().capacity();
    }
} // namespace indexer_client::testing_hooks
#endif
