/*
 * Wazuh - Indexer connector index-name allowlist.
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_SAFE_INDEX_NAME_HPP
#define _INDEXER_SAFE_INDEX_NAME_HPP

#include <string_view>

/**
 * @brief Validates that an index name is safe to embed in a URL path component or
 *        in a JSON string sent to wazuh-indexer.
 *
 * Rejects empty strings and any character outside the conservative allowlist
 * `[a-zA-Z0-9._*-]`. Blocks `/`, `?`, `#`, `,`, whitespace and quote characters,
 * which would otherwise enable path traversal, query-string injection in URLs,
 * or JSON-body escape attacks. `*` is allowed because wazuh-indexer interprets it
 * as a wildcard and the connector has legitimate callers that use patterns such
 * as `wazuh-states-*`.
 *
 * ONE definition shared by both connector variants, so the sync and async paths that build a URL
 * from an index name apply the same rule.
 *
 * @param idx Candidate index name.
 * @return true if the name is non-empty and contains only safe characters.
 */
inline bool isSafeIndexName(std::string_view idx) noexcept
{
    if (idx.empty())
    {
        return false;
    }
    for (const char c : idx)
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

#endif // _INDEXER_SAFE_INDEX_NAME_HPP
