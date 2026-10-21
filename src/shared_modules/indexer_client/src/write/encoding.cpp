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
#include <cassert>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

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
        // indexer_connector/src/indexerConnectorSyncImpl.hpp:121-145 (appendScriptedUpdate), byte for byte.
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

        Outcome<std::string> invalid(std::string why)
        {
            return Outcome<std::string>::failure(Cause::InvalidArgument, std::move(why));
        }

        /// Validation of I61 / RF-4; empty string when the op is valid, otherwise the reason (field first).
        std::string validate(const Op& op)
        {
            const char* const kind = kindName(op.kind); // A literal: nothing is allocated unless a reason is built.
            if (op.index.empty())
            {
                return "index: empty";
            }
            if (!isSafeIndexName(op.index))
            {
                return "index: contains characters outside [a-zA-Z0-9._*-]";
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
                if (op.body.find('\n') != std::string::npos)
                {
                    return "body: contains '\\n' (compact JSON expected)";
                }
            }

            // E3c-2 I80: the tag is a cancellation key, never wire bytes; the reason never echoes it (D42).
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

        /// I73: the effective policy; empty when valid.
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

        /// I72/I73: WriteMode against the kind; empty when valid.
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
                    // The index alone: a reason is never built from consumer bytes (D42).
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

    Outcome<std::string> encode(Op&& op, const ConflictPolicy& effective)
    {
        // The first failure wins: the op's fields, then the effective policy, then the write mode.
        if (auto why = validate(op); !why.empty())
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

        const bool preserving = op.mode.kind == WriteMode::Kind::ReplacePreserving;
        const bool versioned = op.kind == Op::Kind::IndexVersionedScript;
        const bool scripted = versioned || preserving; // The update actions (I71).

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

        // Exact size first: one allocation, and the document copied once (twice for the update actions, whose wire
        // format carries it as params.doc and as the upsert).
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
        else if (op.kind != Op::Kind::Delete)
        {
            size += op.body.size() + 1;
        }

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
        else if (op.kind != Op::Kind::Delete)
        {
            lines.append(op.body);
            lines.push_back('\n');
        }
        assert(lines.size() == size && "the exact size and the encoded lines disagree");

        // The op's own copy dies here: the encoded lines are the only copy that stays charged.
        std::string().swap(op.body);
        return Outcome<std::string>::success(std::move(lines));
    }
} // namespace indexer_client::detail::write
