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

#ifndef _INDEXER_CLIENT_LOG_POLICY_HPP
#define _INDEXER_CLIENT_LOG_POLICY_HPP

#include <cstddef>
#include <string>
#include <string_view>

/// What a log line of the indexer client, or of a consumer writing through it, may say about a document.
namespace indexer_client
{
    /// Whether a log line may quote the content of a document on its way to the indexer. A document is event or
    /// inventory content: by default a line names it (index, id, size) and never quotes it. A build-time switch on
    /// purpose: it is the single place to wire an internal option to, or to flip, if a later version wants the
    /// content in the logs.
    inline constexpr bool LOG_DOCUMENT_CONTENT = false;

    /// Most bytes of a document a log line quotes when LOG_DOCUMENT_CONTENT is on.
    inline constexpr std::size_t MAX_LOGGED_DOCUMENT_BYTES = 512;

    /// @p text with every control byte escaped (`\n`, `\r`, `\t`, else `\xNN`): text the indexer or an agent supplies
    /// (an item's `error.reason` may quote the rejected value, newlines included) can neither break the log line nor
    /// start a forged one. Each byte becomes at most 4. Escaping twice changes nothing.
    inline std::string escapedForLog(std::string_view text)
    {
        static constexpr char HEX[] = "0123456789abcdef";
        std::string out;
        out.reserve(text.size());
        for (const char c : text)
        {
            const auto byte = static_cast<unsigned char>(c);
            switch (byte)
            {
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (byte < 0x20U || byte == 0x7FU)
                    {
                        out += "\\x";
                        out += HEX[byte >> 4U];
                        out += HEX[byte & 0x0FU];
                    }
                    else
                    {
                        out += c;
                    }
            }
        }
        return out;
    }

    /// How a log line names one document: `index: '<index>', id: '<id>', document size: <n> bytes` (`id: 'none'`
    /// for a document without one). The content follows, escaped and cut at MAX_LOGGED_DOCUMENT_BYTES, only when
    /// @p withContent is set; every caller leaves it at LOG_DOCUMENT_CONTENT.
    inline std::string documentForLog(std::string_view index,
                                      std::string_view id,
                                      std::string_view document,
                                      bool withContent = LOG_DOCUMENT_CONTENT)
    {
        std::string out = "index: '" + escapedForLog(index) + "', id: '" + (id.empty() ? "none" : escapedForLog(id)) +
                          "', document size: " + std::to_string(document.size()) + " bytes";
        if (withContent)
        {
            out += ", document: " + escapedForLog(document.substr(0, MAX_LOGGED_DOCUMENT_BYTES));
            if (document.size() > MAX_LOGGED_DOCUMENT_BYTES)
            {
                out += "...";
            }
        }
        return out;
    }
} // namespace indexer_client

#endif // _INDEXER_CLIENT_LOG_POLICY_HPP
