/*
 * Wazuh remoted module - Group selector helpers
 * Copyright (C) Wazuh Inc.
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

    /// Inverse of toGroupsCsv(): "" is no groups; anything else splits on every comma and keeps
    /// every empty entry (leading, trailing or doubled) so group-name validation can reject it.
    inline std::vector<std::string> fromGroupsCsv(const std::string& csv)
    {
        std::vector<std::string> groups;
        if (csv.empty())
        {
            return groups;
        }

        size_t start = 0;
        for (size_t comma = csv.find(','); comma != std::string::npos; comma = csv.find(',', start))
        {
            groups.push_back(csv.substr(start, comma - start));
            start = comma + 1;
        }
        groups.push_back(csv.substr(start));
        return groups;
    }

    /// The config_token /control publishes: the group selector, the same CSV config_hash was
    /// computed over, so the two provably name the same merged.mg.
    ///
    /// Informational: the agent does not read it. Its /download request names no resource and
    /// the manager derives the selector from the agent's groups, so a resource_id an older agent
    /// still sends is only compared with that selector.
    ///
    /// Never empty: an agent with no groups is implicitly in "default". The substitution is
    /// defensive only, since every site that writes AgentEntry::groups goes through
    /// membershipGroups() below.
    inline std::string makeConfigToken(const std::string& groupsCsv)
    {
        return groupsCsv.empty() ? std::string {"default"} : groupsCsv;
    }

    /// The membership to store for an agent row wazuh-db answered with: its groups in wazuh-db
    /// order, or {"default"} for a row with no groups -- the one mapping every writer of
    /// AgentEntry::groups shares, so /control's groups, config_hash and config_token and the
    /// /download selector are all computed over the same list. A missing row is not a membership
    /// at all and never reaches this function.
    inline std::vector<std::string> membershipGroups(std::vector<std::string> groups)
    {
        if (groups.empty())
        {
            return {"default"};
        }
        return groups;
    }
} // namespace remoted::control

#endif // _REMOTED_CONTROL_GROUP_SELECTOR_HPP
