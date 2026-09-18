/*
 * Wazuh remoted module - Group selector helpers
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_GROUP_SELECTOR_HPP
#define _REMOTED_CONTROL_GROUP_SELECTOR_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace remoted::control
{
    /// Rebuild the raw group CSV wdb returned (no URL-encoding, matches wdb).
    ///
    /// Order is wdb's and is preserved verbatim: it is part of the identity of a multigroup, both
    /// for the directory name (sha256 of this CSV) and for the config_hash computed over the file
    /// that name resolves to. Sorting or de-duplicating here would silently rename multigroups.
    inline std::string toGroupsCsv(const std::vector<std::string>& groups)
    {
        std::string out;
        for (size_t i = 0; i < groups.size(); ++i)
        {
            if (i > 0)
                out.push_back(',');
            out.append(groups[i]);
        }
        return out;
    }

    /// The /download resource_id the agent must use for its shared configuration.
    ///
    /// Opaque to the agent by contract: it passes this through verbatim and never parses it,
    /// which is exactly what lets this value change without shipping a new agent. Today it IS
    /// the group selector -- the same CSV config_hash was computed over, so the two provably
    /// name the same merged.mg.
    ///
    /// Never empty: /download needs some resource to name, and an agent with no groups is
    /// implicitly in "default". The substitution is defensive only, since every site that
    /// writes AgentEntry::groups already falls back to {"default"}.
    inline std::string makeConfigToken(const std::string& groupsCsv)
    {
        return groupsCsv.empty() ? std::string {"default"} : groupsCsv;
    }
} // namespace remoted::control

#endif // _REMOTED_CONTROL_GROUP_SELECTOR_HPP
