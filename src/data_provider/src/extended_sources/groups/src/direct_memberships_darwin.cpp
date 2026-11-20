/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <cctype>
#include <iterator>
#include <set>

#include "direct_memberships_darwin.hpp"

static std::string mapChars(std::string value, int (*convert)(int))
{
    std::transform(value.begin(), value.end(), value.begin(), [convert](unsigned char c)
    {
        return convert(c);
    });
    return value;
}

// OpenDirectory writes GUIDs in upper case, but nothing guarantees it for every record.
static std::string toUpper(std::string value)
{
    return mapChars(std::move(value), ::toupper);
}

// Account names are not case sensitive on macOS, so a group listing "Bob" lists the user "bob".
static std::string toLower(std::string value)
{
    return mapChars(std::move(value), ::tolower);
}

DirectMemberships::DirectMemberships(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                     std::shared_ptr<IODUtilsWrapper> odWrapper,
                                     std::shared_ptr<IUUIDWrapper> uuidWrapper)
    : m_groupWrapper(std::move(groupWrapper))
    , m_odWrapper(std::move(odWrapper))
    , m_uuidWrapper(std::move(uuidWrapper))
{
}

void DirectMemberships::load()
{
    if (m_loaded)
    {
        return;
    }

    m_loaded = true;

    std::map<std::string, ODGroupMembers> membersByGroup;
    m_readable = m_odWrapper->genGroupMembers(membersByGroup);

    if (!m_readable)
    {
        return;
    }

    for (auto& [name, members] : membersByGroup)
    {
        // A group the system cannot resolve to a gid cannot be reported as a membership.
        if (const struct group* grp = m_groupWrapper->getgrnam(name.c_str()); grp != nullptr)
        {
            std::set<std::string> uuids;
            std::transform(members.uuids.begin(), members.uuids.end(), std::inserter(uuids, uuids.end()), toUpper);
            members.uuids = std::move(uuids);

            std::set<std::string> names;
            std::transform(members.names.begin(), members.names.end(), std::inserter(names, names.end()), toLower);
            members.names = std::move(names);
            m_groups.push_back({grp->gr_gid, std::move(members)});
        }
    }
}

std::optional<std::string> DirectMemberships::uuidOf(uid_t uid) const
{
    uuid_t uuid = {0};
    uuid_string_t uuidString = {0};

    m_uuidWrapper->uidToUUID(uid, uuid);

    // mbr_uid_to_uuid() reports a failure only through its return value, which the wrapper does not
    // pass on. A successful call always writes a UUID, so a null one means there is no answer.
    if (uuid_is_null(uuid))
    {
        return std::nullopt;
    }

    m_uuidWrapper->uuidToString(uuid, uuidString);
    return toUpper(uuidString);
}

std::vector<gid_t> DirectMemberships::groupsOf(const std::string& userName, uid_t uid, gid_t primaryGid)
{
    load();

    if (!m_readable)
    {
        return {};
    }

    const auto uuid = uuidOf(uid);

    // Without the account's UUID the memberships listed by GUID cannot be told apart, and
    // reporting only the others would hide groups, so the account's groups are unknown.
    if (!uuid)
    {
        return {};
    }

    const auto lowerName = toLower(userName);
    std::vector<gid_t> others;

    for (const auto& group : m_groups)
    {
        const bool listed = group.members.names.count(lowerName) != 0 || group.members.uuids.count(*uuid) != 0;

        if (listed && group.gid != primaryGid)
        {
            others.push_back(group.gid);
        }
    }

    std::sort(others.begin(), others.end());
    others.erase(std::unique(others.begin(), others.end()), others.end());

    std::vector<gid_t> groups {primaryGid};
    groups.insert(groups.end(), others.begin(), others.end());
    return groups;
}
