/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * October 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_JSON_NESTING_DEPTH_HPP
#define _INVSYNC_COMMON_JSON_NESTING_DEPTH_HPP

/**
 * @file jsonNestingDepth.hpp
 * @brief The nesting cap on agent JSON bodies (`/stats`, `/config`), checked on the raw text.
 *
 * nlohmann's parser is iterative, but `dump()`, the copy constructor and `operator==` recurse once per
 * level. A few tens of thousands of nested `[` overflow an 8 MiB stack, and zstd shrinks such a body
 * to a few dozen bytes, so neither remoted's body cap nor the in-flight byte budget bounds the depth.
 * The check therefore runs on the bytes, before a DOM exists: whatever nlohmann does later only ever
 * sees a shallow tree, independently of its version.
 */

#include <cstddef>
#include <string_view>

namespace invsync::common
{
    /**
     * @brief Deepest container nesting an agent body may carry.
     *
     * Depth 1 is the root container: a text with MAX_JSON_NESTING_DEPTH nested containers is accepted,
     * one with MAX_JSON_NESTING_DEPTH + 1 is not. Same value and convention as the engine's
     * `Json::MAX_DEPTH`, which closed the same class of crash there. Far above any real report: the
     * indexer's own mapping depth limit (20 by default) rejects a fraction of this.
     */
    constexpr std::size_t MAX_JSON_NESTING_DEPTH {256};

    /**
     * @brief Whether @p text opens more than @p maxDepth nested objects/arrays at any point.
     *
     * A linear scan that tracks string state (quotes and backslash escapes) so brackets inside strings
     * are not counted, and stops at the first level over the cap. It does not validate: malformed text
     * that stays under the cap is left for the parser to reject, and stray closers never drive the
     * count below zero.
     *
     * @param text The raw request body.
     * @param maxDepth Deepest nesting allowed.
     * @return true when the body must be rejected without parsing it.
     */
    inline bool exceedsNestingDepth(std::string_view text, std::size_t maxDepth = MAX_JSON_NESTING_DEPTH) noexcept
    {
        std::size_t depth {0};
        bool inString {false};
        bool escaped {false};

        for (const char c : text)
        {
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (c == '\\')
                {
                    escaped = true;
                }
                else if (c == '"')
                {
                    inString = false;
                }
                continue;
            }

            switch (c)
            {
                case '"': inString = true; break;
                case '[':
                case '{':
                    if (++depth > maxDepth)
                    {
                        return true;
                    }
                    break;
                case ']':
                case '}':
                    if (depth > 0)
                    {
                        --depth;
                    }
                    break;
                default: break;
            }
        }

        return false;
    }
} // namespace invsync::common

#endif // _INVSYNC_COMMON_JSON_NESTING_DEPTH_HPP
