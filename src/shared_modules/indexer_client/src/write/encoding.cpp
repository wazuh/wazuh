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
#include <cstddef>
#include <cstdio>
#include <utility>

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
        // indexer_connector/src/indexerConnectorSyncImpl.hpp:121-145 (appendScriptedUpdate), byte for byte.
        constexpr std::string_view SCRIPT_HEAD =
            R"({"script":{"source":"if (ctx._source?.state?.document_version == null || ctx._source.state.document_version <= params.doc_version) { ctx._source = params.doc } else { ctx.op = 'none' }","lang":"painless","params":{"doc_version":)";
        constexpr std::string_view SCRIPT_DOC = R"(,"doc":)";
        constexpr std::string_view SCRIPT_UPSERT = R"(}},"upsert":)";
        constexpr std::string_view SCRIPT_TAIL = ",\"scripted_upsert\":true}\n";

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
            if (op.mode.kind == WriteMode::Kind::ReplacePreserving)
            {
                return "mode: ReplacePreserving is not supported yet (E3c)";
            }
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
            return {};
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

    Outcome<std::string> encode(Op&& op)
    {
        if (auto why = validate(op); !why.empty())
        {
            return invalid(std::move(why));
        }

        std::string_view prefix;
        bool withId = true;
        switch (op.kind)
        {
            case Op::Kind::Index: prefix = INDEX_PREFIX; break;
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

        // Exact size first: one allocation, and the document copied once (twice for the versioned update, whose wire
        // format carries it as params.doc and as the upsert).
        std::size_t size = prefix.size() + op.index.size() + ACTION_SUFFIX.size();
        if (withId)
        {
            size += ID_INFIX.size() + escapedSize(op.id);
        }
        if (op.kind == Op::Kind::IndexVersionedScript)
        {
            size += SCRIPT_HEAD.size() + op.version.size() + SCRIPT_DOC.size() + op.body.size() + SCRIPT_UPSERT.size() +
                    op.body.size() + SCRIPT_TAIL.size();
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
        lines.append(ACTION_SUFFIX);

        if (op.kind == Op::Kind::IndexVersionedScript)
        {
            lines.append(SCRIPT_HEAD);
            lines.append(op.version);
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

        // The op's own copy dies here: the encoded lines are the only copy that stays charged.
        std::string().swap(op.body);
        return Outcome<std::string>::success(std::move(lines));
    }
} // namespace indexer_client::detail::write
