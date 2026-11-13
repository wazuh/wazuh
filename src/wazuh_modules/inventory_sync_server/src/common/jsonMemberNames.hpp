/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_JSON_MEMBER_NAMES_HPP
#define _INVSYNC_COMMON_JSON_MEMBER_NAMES_HPP

/**
 * @file jsonMemberNames.hpp
 * @brief Detects member names that the indexer would expand into field paths.
 *
 * The manager treats a JSON member name as an opaque string, but the indexer splits a name that
 * contains a '.' into a field path: `{"wazuh.agent.id":"002"}` and `{"wazuh":{"agent":{"id":"002"}}}`
 * land on the same field. The overlay that binds a document to its agent only rewrites the nested
 * spelling, so a dotted sibling would survive it and be indexed as a second value of the identity.
 *
 * A dotted name expands only below the object that holds it, so exactly two places can reach the
 * manager-owned `wazuh.*` fields: a root member whose first segment is `wazuh`, and any member inside
 * the root `wazuh` object. Dotted names anywhere else stay inside their own subtree.
 */

#include <json.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace invsync::common
{
    /**
     * @brief Whether any member name inside @p subtree, at any depth, contains a '.'.
     *
     * Iterative (explicit stack): it never recurses, whatever the depth. Callers still bound the depth
     * first with exceedsNestingDepth(), because other nlohmann operations on the same document do recurse.
     *
     * @param subtree A parsed value.
     * @return true when a member name of @p subtree contains a '.'.
     */
    inline bool hasDottedMemberName(const nlohmann::json& subtree)
    {
        std::vector<const nlohmann::json*> pending {&subtree};
        while (!pending.empty())
        {
            const auto* value = pending.back();
            pending.pop_back();

            if (value->is_object())
            {
                for (auto it = value->begin(); it != value->end(); ++it)
                {
                    if (it.key().find('.') != std::string::npos)
                    {
                        return true;
                    }
                    pending.push_back(&it.value());
                }
            }
            else if (value->is_array())
            {
                for (const auto& element : *value)
                {
                    pending.push_back(&element);
                }
            }
        }
        return false;
    }

    /**
     * @brief Whether a dotted member name of @p document would expand into the `wazuh.*` fields.
     *
     * True for a root member whose first segment is `wazuh` (`"wazuh.agent.id"`, `"wazuh."`) and for a
     * dotted name at any depth inside the root `wazuh` object (`"agent.id"`).
     *
     * @param document A parsed document; a non-object root has no member names to check.
     * @return true when the document must not reach the indexer.
     */
    inline bool dottedNameReachesWazuh(const nlohmann::json& document)
    {
        if (!document.is_object())
        {
            return false;
        }

        constexpr std::string_view WAZUH {"wazuh"};
        for (auto it = document.begin(); it != document.end(); ++it)
        {
            const std::string_view name {it.key()};
            const auto dot = name.find('.');
            if (dot != std::string_view::npos)
            {
                if (name.substr(0, dot) == WAZUH)
                {
                    return true;
                }
                continue;
            }
            if (name == WAZUH && hasDottedMemberName(it.value()))
            {
                return true;
            }
        }
        return false;
    }
} // namespace invsync::common

#endif // _INVSYNC_COMMON_JSON_MEMBER_NAMES_HPP
