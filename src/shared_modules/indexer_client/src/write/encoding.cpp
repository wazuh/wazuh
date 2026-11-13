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

#include "write/encoding.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"

namespace indexer_client::detail::write
{
    namespace
    {
        /// INT64_MAX: Painless compares `doc_version` as a long; a JSON number above it would not round-trip.
        constexpr std::string_view MAX_VERSION = "9223372036854775807";

        constexpr std::string_view INDEX_PREFIX = R"({"index":{"_index":")";
        constexpr std::string_view CREATE_PREFIX = R"({"create":{"_index":")";
        constexpr std::string_view DELETE_PREFIX = R"({"delete":{"_index":")";
        constexpr std::string_view UPDATE_PREFIX = R"({"update":{"_index":")";
        constexpr std::string_view ID_INFIX = R"(","_id":")";
        constexpr std::string_view ACTION_SUFFIX = "\"}}\n";
        constexpr std::string_view ID_CLOSE = "\"";
        constexpr std::string_view RETRY_INFIX = R"(,"retry_on_conflict":)";
        constexpr std::string_view RETRY_ACTION_SUFFIX = "}}\n";
        // The v1's appendScriptedUpdate (indexerConnectorSyncImpl.hpp:121-145; the v1 was removed in 5.x),
        // byte for byte.
        constexpr std::string_view V1_GUARD_SOURCE =
            "if (ctx._source?.state?.document_version == null || ctx._source.state.document_version <= "
            "params.doc_version) { ctx._source = params.doc } else { ctx.op = 'none' }";
        constexpr std::string_view SCRIPT_OPEN = R"({"script":{"source":")";
        constexpr std::string_view SCRIPT_PARAMS = R"(","lang":"painless","params":{)";
        constexpr std::string_view SCRIPT_VERSION = R"("doc_version":)";
        constexpr std::string_view SCRIPT_PATHS = R"("paths":)";
        constexpr std::string_view SCRIPT_DOC = R"(,"doc":)";
        constexpr std::string_view SCRIPT_UPSERT = R"(}},"upsert":)";
        constexpr std::string_view SCRIPT_TAIL = ",\"scripted_upsert\":true}\n";

        /// The sources go into a JSON string verbatim: none of them may need escaping.
        constexpr bool isJsonVerbatim(std::string_view source) noexcept
        {
            for (const char c : source)
            {
                if (c == '"' || c == '\\' || static_cast<unsigned char>(c) < 0x20)
                {
                    return false;
                }
            }
            return true;
        }
        static_assert(isJsonVerbatim(V1_GUARD_SOURCE) && isJsonVerbatim(PRESERVE_SOURCE) &&
                          isJsonVerbatim(PRESERVE_VERSIONED_SOURCE),
                      "a script source would need JSON escaping");

        constexpr std::size_t MAX_PRESERVED_PATHS = 16;
        constexpr std::size_t MAX_PATH_SEGMENTS = 8;
        constexpr std::size_t MAX_SEGMENT_SIZE = 64;

        /// The v1's escape table (shared_modules/utils/reflectiveJson.hpp ESCAPE_TABLE, used by appendEscapedId):
        /// '"', '\\', the five short escapes and every other control character below 0x20 as \u00XX. Nothing else.
        const std::array<std::string, 256>& escapeTable()
        {
            static const std::array<std::string, 256> table = []
            {
                std::array<std::string, 256> t {};
                t[static_cast<unsigned char>('"')] = "\\\"";
                t[static_cast<unsigned char>('\\')] = "\\\\";
                t[static_cast<unsigned char>('\b')] = "\\b";
                t[static_cast<unsigned char>('\f')] = "\\f";
                t[static_cast<unsigned char>('\n')] = "\\n";
                t[static_cast<unsigned char>('\r')] = "\\r";
                t[static_cast<unsigned char>('\t')] = "\\t";
                for (int c = 0; c < 0x20; ++c)
                {
                    if (t[c].empty())
                    {
                        std::array<char, 7> buffer {};
                        std::snprintf(buffer.data(), buffer.size(), "\\u%04x", c);
                        t[c] = buffer.data();
                    }
                }
                return t;
            }();
            return table;
        }

        std::size_t escapedSize(std::string_view id)
        {
            const auto& table = escapeTable();
            std::size_t size = 0;
            for (const unsigned char c : id)
            {
                size += table[c].empty() ? 1 : table[c].size();
            }
            return size;
        }

        void appendEscaped(std::string& out, std::string_view id)
        {
            const auto& table = escapeTable();
            for (const unsigned char c : id)
            {
                if (table[c].empty())
                {
                    out.push_back(static_cast<char>(c));
                }
                else
                {
                    out.append(table[c]);
                }
            }
        }

        bool isVersion(std::string_view version) noexcept
        {
            // A canonical JSON integer in [0, INT64_MAX]: digits only, no leading zero (a leading zero is not valid
            // JSON).
            if (version.empty() || version.size() > MAX_VERSION.size() || (version.size() > 1 && version[0] == '0'))
            {
                return false;
            }
            for (const char c : version)
            {
                if (c < '0' || c > '9')
                {
                    return false;
                }
            }
            return version.size() < MAX_VERSION.size() || version <= MAX_VERSION;
        }

        const char* kindName(Op::Kind kind) noexcept
        {
            switch (kind)
            {
                case Op::Kind::Index: return "Index";
                case Op::Kind::IndexAutoId: return "IndexAutoId";
                case Op::Kind::IndexDataStream: return "IndexDataStream";
                case Op::Kind::Delete: return "Delete";
                case Op::Kind::IndexVersionedScript: return "IndexVersionedScript";
            }
            return "unknown";
        }

        Outcome<Encoded> invalid(std::string why)
        {
            return Outcome<Encoded>::failure(Cause::InvalidArgument, std::move(why));
        }

        /// Validation of an op; empty string when the op is valid, otherwise the reason (field first).
        /// `indexKnownSafe`: the index equals the cached one of a shared head, already validated: its checks
        /// are skipped (they would pass). `trustedBody`: BucketSpec::trustedBodies, the '\n' search is skipped.
        std::string validate(const Op& op, bool indexKnownSafe, bool trustedBody)
        {
            const char* const kind = kindName(op.kind); // A literal: nothing is allocated unless a reason is built.
            if (!indexKnownSafe)
            {
                if (op.index.empty())
                {
                    return "index: empty";
                }
                if (!isSafeIndexName(op.index))
                {
                    return "index: contains characters outside [a-zA-Z0-9._*-]";
                }
            }

            const bool needsId =
                op.kind == Op::Kind::Index || op.kind == Op::Kind::Delete || op.kind == Op::Kind::IndexVersionedScript;
            if (needsId && op.id.empty())
            {
                return std::string("id: required for ") + kind;
            }
            if (!needsId && !op.id.empty())
            {
                return std::string("id: must be empty for ") + kind;
            }

            if (op.kind == Op::Kind::IndexVersionedScript)
            {
                if (!isVersion(op.version))
                {
                    return "version: must be an integer in [0, 9223372036854775807] without leading zeros for "
                           "IndexVersionedScript";
                }
            }
            else if (!op.version.empty())
            {
                return std::string("version: only IndexVersionedScript takes a version, not ") + kind;
            }

            if (op.kind == Op::Kind::Delete)
            {
                if (!op.body.empty())
                {
                    return "body: must be empty for Delete";
                }
            }
            else
            {
                if (op.body.empty())
                {
                    return std::string("body: empty for ") + kind;
                }
                if (!trustedBody && op.body.find('\n') != std::string::npos)
                {
                    return "body: contains '\\n' (compact JSON expected)";
                }
            }

            // The tag is a cancellation key, never wire bytes; the reason never echoes it.
            if (op.tag.size() > MAX_TAG_SIZE)
            {
                return "tag: longer than " + std::to_string(MAX_TAG_SIZE) + " bytes";
            }
            for (const char c : op.tag)
            {
                const auto byte = static_cast<unsigned char>(c);
                if (byte < 0x20 || byte == 0x7f)
                {
                    return "tag: contains a control character";
                }
            }
            return {};
        }

        /// The effective policy; empty when valid.
        std::string validatePolicy(const ConflictPolicy& effective)
        {
            if (effective.kind == ConflictPolicy::Kind::Retry &&
                (effective.retryOnConflict == 0 || effective.retryOnConflict > MAX_RETRY_ON_CONFLICT))
            {
                return "onConflict.retryOnConflict: must be in [1, " + std::to_string(MAX_RETRY_ON_CONFLICT) +
                       "] with ConflictPolicy::Retry, got " + std::to_string(effective.retryOnConflict);
            }
            return {};
        }

        bool isSegmentChar(char c) noexcept
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '@' ||
                   c == '-';
        }

        /// One preserved path: 1-8 segments of [A-Za-z0-9_@-]{1,64} separated by '.'; empty when valid.
        std::string validatePath(std::string_view path, std::size_t i)
        {
            const auto where = [i]
            {
                return "mode: preservedPaths[" + std::to_string(i) + "] ";
            };
            if (path.empty())
            {
                return where() + "is empty";
            }
            std::size_t segments = 0;
            std::size_t start = 0;
            while (true)
            {
                const auto dot = path.find('.', start);
                const auto segment =
                    path.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
                if (++segments > MAX_PATH_SEGMENTS)
                {
                    return where() + "has more than " + std::to_string(MAX_PATH_SEGMENTS) + " segments";
                }
                if (segment.empty())
                {
                    return where() + "has an empty segment";
                }
                if (segment.size() > MAX_SEGMENT_SIZE)
                {
                    return where() + "has a segment longer than " + std::to_string(MAX_SEGMENT_SIZE);
                }
                for (const char c : segment)
                {
                    if (!isSegmentChar(c))
                    {
                        return where() + "has a segment character outside [A-Za-z0-9_@-]";
                    }
                }
                if (dot == std::string_view::npos)
                {
                    return {};
                }
                start = dot + 1;
            }
        }

        /// `a` equals `b` or is a segment prefix of it ("a" of "a.b", not of "ab").
        bool coversBySegments(std::string_view a, std::string_view b) noexcept
        {
            return b.size() >= a.size() && b.compare(0, a.size(), a) == 0 &&
                   (b.size() == a.size() || b[a.size()] == '.');
        }

        /// WriteMode against the kind; empty when valid.
        std::string validateMode(const Op& op)
        {
            const auto& paths = op.mode.preservedPaths;
            if (op.mode.kind != WriteMode::Kind::ReplacePreserving)
            {
                return paths.empty() ? std::string {} : std::string("mode: preservedPaths requires ReplacePreserving");
            }
            if (op.kind != Op::Kind::Index && op.kind != Op::Kind::IndexVersionedScript)
            {
                return std::string("mode: ReplacePreserving applies to Index or IndexVersionedScript, not ") +
                       kindName(op.kind);
            }
            if (paths.empty() || paths.size() > MAX_PRESERVED_PATHS)
            {
                return "mode: ReplacePreserving takes 1 to " + std::to_string(MAX_PRESERVED_PATHS) +
                       " preservedPaths, got " + std::to_string(paths.size());
            }
            for (std::size_t i = 0; i < paths.size(); ++i)
            {
                if (auto why = validatePath(paths[i], i); !why.empty())
                {
                    return why;
                }
                // Any path on the way to or under the guarded field would replace the version the guard compares.
                if (op.kind == Op::Kind::IndexVersionedScript &&
                    (coversBySegments(paths[i], "state.document_version") ||
                     coversBySegments("state.document_version", paths[i])))
                {
                    // The index alone: a reason is never built from consumer bytes.
                    return "mode: preservedPaths[" + std::to_string(i) +
                           "] would defeat the version guard of IndexVersionedScript";
                }
                for (std::size_t j = 0; j < i; ++j)
                {
                    if (coversBySegments(paths[j], paths[i]) || coversBySegments(paths[i], paths[j]))
                    {
                        return "mode: preservedPaths[" + std::to_string(j) + "] and [" + std::to_string(i) +
                               "] are equal or one is a segment prefix of the other";
                    }
                }
            }
            return {};
        }

        /// The per-thread cache over the HeadTables: THREAD_CACHE entries keyed by (generation, kind,
        /// index), the last one used checked first, replaced in turn. Only a fully valid op ever fills an entry, and
        /// `line` points into the table of `generation` (generations start at 1: 0 is an empty entry).
        struct HeadCacheEntry final
        {
            std::uint64_t generation {0};
            Op::Kind kind {Op::Kind::IndexAutoId};
            std::string index;
            const std::string* line {nullptr};
        };

        struct HeadCache final
        {
            std::array<HeadCacheEntry, THREAD_CACHE> entries;
            std::size_t last {0}; ///< The entry of the last hit or fill.
            std::size_t next {0}; ///< The next entry a fill replaces.
        };

        HeadCache& headCache() noexcept
        {
            thread_local HeadCache cache;
            return cache;
        }

        /// The process-wide generation counter of HeadTable (monotonic, never reused).
        std::atomic<std::uint64_t> g_headTableGenerations {0};

        /// Size of <P>: [["a","b"],["c"]] (validated paths: no segment needs escaping).
        std::size_t pathsSize(const std::vector<std::string>& paths) noexcept
        {
            std::size_t size = 2 + (paths.size() - 1); // [] and the commas between paths.
            for (const auto& path : paths)
            {
                std::size_t dots = 0;
                for (const char c : path)
                {
                    dots += c == '.' ? 1 : 0;
                }
                // [] + the segment bytes + two quotes per segment; each '.' becomes "," (3 bytes for 1).
                size += 2 + path.size() + 2 + dots * 2;
            }
            return size;
        }

        void appendPaths(std::string& out, const std::vector<std::string>& paths)
        {
            out.push_back('[');
            for (std::size_t i = 0; i < paths.size(); ++i)
            {
                if (i > 0)
                {
                    out.push_back(',');
                }
                out.append("[\"");
                for (const char c : paths[i])
                {
                    if (c == '.')
                    {
                        out.append("\",\"");
                    }
                    else
                    {
                        out.push_back(c);
                    }
                }
                out.append("\"]");
            }
            out.push_back(']');
        }
    } // namespace

    bool isSafeIndexName(std::string_view index) noexcept
    {
        if (index.empty())
        {
            return false;
        }
        for (const char c : index)
        {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                            c == '_' || c == '.' || c == '*';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    std::uint64_t wireSize(std::string_view head, const std::string& body) noexcept
    {
        return head.size() + (body.empty() ? 0 : body.size() + 1);
    }

    std::uint64_t chargeSize(std::string_view head, const std::string& body) noexcept
    {
        // An SSO body owns no heap: its inline capacity is not charged.
        static const std::size_t inlineCapacity = std::string().capacity();
        const std::uint64_t slack = body.capacity() > inlineCapacity ? body.capacity() - body.size() : 0;
        return wireSize(head, body) + slack;
    }

    void appendWire(std::string& out, std::string_view head, const std::string& body)
    {
        out.append(head);
        if (!body.empty())
        {
            out.append(body);
            out.push_back('\n');
        }
    }

    void appendWire(std::string& out, const Encoded& encoded)
    {
        appendWire(out, encoded.headView(), encoded.body);
    }

    HeadTable::HeadTable()
        : m_generation(g_headTableGenerations.fetch_add(1) + 1)
        , m_slots(std::make_unique<Slot[]>(CAPACITY))
    {
    }

    const std::string* HeadTable::find(Op::Kind kind, std::string_view index) const noexcept
    {
        // Published slots are immutable: the acquire load makes their contents visible without the append mutex.
        const std::size_t count = m_count.load(std::memory_order_acquire);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto& slot = m_slots[i];
            if (slot.kind == kind && slot.index == index)
            {
                return &slot.line;
            }
        }
        return nullptr;
    }

    const std::string* HeadTable::intern(Op::Kind kind, std::string_view index, std::string&& line)
    {
        if (full())
        {
            // The table only grows: once full, no op takes the mutex again.
            return find(kind, index);
        }
        std::lock_guard<std::mutex> lock(m_appendMutex);
        m_appendLocks.fetch_add(1, std::memory_order_relaxed);
        if (const auto* existing = find(kind, index))
        {
            return existing; // Another thread stored it first: `line` is left as it was.
        }
        const std::size_t count = m_count.load(std::memory_order_relaxed);
        if (count == CAPACITY)
        {
            return nullptr; // Full: the op keeps its own line (`line` untouched).
        }
        auto& slot = m_slots[count];
        slot.kind = kind;
        slot.index.assign(index);
        slot.line = std::move(line);
        m_count.store(count + 1, std::memory_order_release);
        return &slot.line;
    }

    std::uint64_t Encoded::wire() const noexcept
    {
        return wireSize(headView(), body);
    }

    std::uint64_t Encoded::charge() const noexcept
    {
        return chargeSize(headView(), body);
    }

    Outcome<Encoded> encode(Op&& op, const ConflictPolicy& effective, bool trustedBody, HeadTable* heads)
    {
        // The kinds without `_id` share their action line through the write path's HeadTable, reached by
        // the per-thread cache. A hit (same table, same kind, the same index byte for byte) skips the index checks:
        // the cached index passed them.
        const bool sharedKind =
            heads != nullptr && (op.kind == Op::Kind::IndexAutoId || op.kind == Op::Kind::IndexDataStream);
        HeadCache* cache = nullptr;
        const std::string* cached = nullptr;
        if (sharedKind)
        {
            cache = &headCache();
            const auto generation = heads->generation();
            const auto matches = [&](const HeadCacheEntry& entry)
            {
                return entry.generation == generation && entry.kind == op.kind && entry.index == op.index;
            };
            if (matches(cache->entries[cache->last]))
            {
                cached = cache->entries[cache->last].line;
            }
            else
            {
                for (std::size_t i = 0; i < cache->entries.size(); ++i)
                {
                    if (matches(cache->entries[i]))
                    {
                        cached = cache->entries[i].line;
                        cache->last = i;
                        break;
                    }
                }
            }
        }
        const bool hit = cached != nullptr;

        // The first failure wins: the op's fields, then the effective policy, then the write mode.
        if (auto why = validate(op, hit, trustedBody); !why.empty())
        {
            return invalid(std::move(why));
        }
        if (auto why = validatePolicy(effective); !why.empty())
        {
            return invalid(std::move(why));
        }
        if (auto why = validateMode(op); !why.empty())
        {
            return invalid(std::move(why));
        }

        if (hit)
        {
            // Neither validated nor built again: the cached line is this op's, byte for byte.
            Encoded encoded;
            encoded.cachedHead = cached;
            encoded.body = std::move(op.body);
            return Outcome<Encoded>::success(std::move(encoded));
        }

        const bool preserving = op.mode.kind == WriteMode::Kind::ReplacePreserving;
        const bool versioned = op.kind == Op::Kind::IndexVersionedScript;
        const bool scripted = versioned || preserving; // The update actions.

        std::string_view prefix;
        bool withId = true;
        switch (op.kind)
        {
            case Op::Kind::Index: prefix = preserving ? UPDATE_PREFIX : INDEX_PREFIX; break;
            case Op::Kind::IndexAutoId:
                prefix = INDEX_PREFIX;
                withId = false;
                break;
            case Op::Kind::IndexDataStream:
                prefix = CREATE_PREFIX;
                withId = false;
                break;
            case Op::Kind::Delete: prefix = DELETE_PREFIX; break;
            case Op::Kind::IndexVersionedScript: prefix = UPDATE_PREFIX; break;
        }

        // <R>: only an update action carries retry_on_conflict, and only with an effective Retry (Success: v1 parity).
        std::array<char, 16> retryDigits {};
        std::size_t retrySize = 0;
        if (scripted && effective.kind == ConflictPolicy::Kind::Retry)
        {
            const auto end =
                std::to_chars(retryDigits.data(), retryDigits.data() + retryDigits.size(), effective.retryOnConflict)
                    .ptr;
            retrySize = static_cast<std::size_t>(end - retryDigits.data());
        }

        std::string_view source;
        if (scripted)
        {
            source = !preserving ? V1_GUARD_SOURCE : versioned ? PRESERVE_VERSIONED_SOURCE : PRESERVE_SOURCE;
        }

        // Exact size first: one allocation for `head`. The kinds without a script keep only their action line in it
        // and take the document by move (no copy, no reserve); the update actions copy it twice into `head`,
        // which is their wire format (params.doc and the upsert).
        std::size_t size = prefix.size() + op.index.size();
        if (withId)
        {
            size += ID_INFIX.size() + escapedSize(op.id);
        }
        size += retrySize == 0 ? ACTION_SUFFIX.size()
                               : ID_CLOSE.size() + RETRY_INFIX.size() + retrySize + RETRY_ACTION_SUFFIX.size();
        if (scripted)
        {
            size += SCRIPT_OPEN.size() + source.size() + SCRIPT_PARAMS.size() + SCRIPT_DOC.size() + op.body.size() +
                    SCRIPT_UPSERT.size() + op.body.size() + SCRIPT_TAIL.size();
            if (versioned)
            {
                size += SCRIPT_VERSION.size() + op.version.size();
            }
            if (preserving)
            {
                size += (versioned ? 1 : 0) + SCRIPT_PATHS.size() + pathsSize(op.mode.preservedPaths);
            }
        }

        size += seams::encodeSizeSkew(); // 0 outside the size-invariant cases.

        std::string lines;
        lines.reserve(size);
        lines.append(prefix);
        lines.append(op.index);
        if (withId)
        {
            lines.append(ID_INFIX);
            appendEscaped(lines, op.id);
        }
        if (retrySize == 0)
        {
            lines.append(ACTION_SUFFIX);
        }
        else
        {
            lines.append(ID_CLOSE);
            lines.append(RETRY_INFIX);
            lines.append(retryDigits.data(), retrySize);
            lines.append(RETRY_ACTION_SUFFIX);
        }

        if (scripted)
        {
            lines.append(SCRIPT_OPEN);
            lines.append(source);
            lines.append(SCRIPT_PARAMS);
            if (versioned)
            {
                lines.append(SCRIPT_VERSION);
                lines.append(op.version);
            }
            if (preserving)
            {
                if (versioned)
                {
                    lines.push_back(',');
                }
                lines.append(SCRIPT_PATHS);
                appendPaths(lines, op.mode.preservedPaths);
            }
            lines.append(SCRIPT_DOC);
            lines.append(op.body);
            lines.append(SCRIPT_UPSERT);
            lines.append(op.body);
            lines.append(SCRIPT_TAIL);
        }
        if (lines.size() != size)
        {
            // A bug in the size computation above, never an abort (the manager's Release builds keep
            // assert live). The lines may be right or not: the op is refused before it is charged or queued.
            internalError("encode: the precomputed size of an operation and its encoded lines disagree; operation "
                          "refused");
            return Outcome<Encoded>::failure(Cause::InvalidState,
                                             "internal error: the encoded size of the operation disagrees with its "
                                             "precomputed size");
        }

        Encoded encoded;
        if (sharedKind)
        {
            // Valid op (no retry digits, no script: a ReplacePreserving or Retry line is not reachable here). The
            // table's line (found lock-free, else interned), or the op's own when the table is full (seen lock-free:
            // a full table is never locked again).
            const std::string* line = heads->find(op.kind, op.index);
            if (line == nullptr && !heads->full())
            {
                line = heads->intern(op.kind, op.index, std::move(lines));
            }
            if (line != nullptr)
            {
                auto& entry = cache->entries[cache->next];
                entry.generation = 0; // Empty while it is rewritten (an allocation below may throw).
                entry.line = nullptr;
                entry.kind = op.kind;
                entry.index.assign(op.index);
                entry.line = line;
                entry.generation = heads->generation();
                cache->last = cache->next;
                cache->next = (cache->next + 1) % cache->entries.size();
                encoded.cachedHead = line;
            }
            else
            {
                encoded.head = std::move(lines);
            }
        }
        else
        {
            encoded.head = std::move(lines);
        }
        if (scripted)
        {
            // The op's own copy dies here: the encoded lines are the only copy that stays charged.
            std::string().swap(op.body);
        }
        else if (op.kind != Op::Kind::Delete)
        {
            // The document itself, by move: its buffer (and its heap slack, charged with the payload) goes on the wire.
            encoded.body = std::move(op.body);
        }
        return Outcome<Encoded>::success(std::move(encoded));
    }
} // namespace indexer_client::detail::write
