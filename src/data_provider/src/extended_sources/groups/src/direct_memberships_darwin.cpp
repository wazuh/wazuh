/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <charconv>
#include <cstdint>

#include "direct_memberships_darwin.hpp"
#include "directory_keys_darwin.hpp"

// OpenDirectory stores a PrimaryGroupID as a signed 32-bit integer in decimal (nobody is -2), and
// the system reports it as the gid_t with the same bits (4294967294). Anything else is no gid.
static std::optional<gid_t> parseGid(const std::string& text)
{
    int32_t value {};
    const char* end = text.data() + text.size();
    const auto [last, error] = std::from_chars(text.data(), end, value);

    if (text.empty() || error != std::errc {} || last != end)
    {
        return std::nullopt;
    }

    return static_cast<gid_t>(value);
}

// An account whose record has no GUID cannot be listed by GUID, only by name.
static bool lists(const ODGroupMembers& members, const std::string& lowerName, const std::string& uuid)
{
    return members.names.count(lowerName) != 0 || (!uuid.empty() && members.uuids.count(uuid) != 0);
}

DirectMemberships::DirectMemberships(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                     std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_groupWrapper(std::move(groupWrapper))
    , m_odWrapper(std::move(odWrapper))
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
    m_readable = m_odWrapper->genGroupMembers(membersByGroup) && m_odWrapper->genUserGuids(m_guidByName);

    if (m_readable)
    {
        m_guidByName = DirectoryKeys::byName(m_guidByName);
        resolveGroups(membersByGroup);
    }
}

void DirectMemberships::resolveGroups(const std::map<std::string, ODGroupMembers>& membersByGroup)
{
    for (const auto& [name, members] : membersByGroup)
    {
        // A group without a gid cannot be reported as a membership.
        if (const auto gid = gidOf(name, members.gid); gid.has_value())
        {
            m_groups.push_back({*gid, {DirectoryKeys::names(members.names), DirectoryKeys::guids(members.uuids), {}}});
        }
    }
}

// The system's answer first. When getgrnam() cannot resolve a group the directory just listed,
// for example a lookup that fails for a moment, the record's own PrimaryGroupID is used, so its
// members do not lose the group for one scan.
std::optional<gid_t> DirectMemberships::gidOf(const std::string& groupName, const std::string& recordGid) const
{
    if (const struct group* grp = m_groupWrapper->getgrnam(groupName.c_str()); grp != nullptr)
    {
        return grp->gr_gid;
    }

    return parseGid(recordGid);
}

std::string DirectMemberships::guidOf(const std::string& lowerName) const
{
    const auto guid = m_guidByName.find(lowerName);
    return guid != m_guidByName.end() ? DirectoryKeys::guid(guid->second) : std::string {};
}

std::set<gid_t> DirectMemberships::otherGroupsOf(const std::string& lowerName, const std::string& uuid,
                                                 gid_t primaryGid) const
{
    std::set<gid_t> others;

    for (const auto& group : m_groups)
    {
        if (group.gid != primaryGid && lists(group.members, lowerName, uuid))
        {
            others.insert(group.gid);
        }
    }

    return others;
}

std::vector<gid_t> DirectMemberships::groupsOf(const std::string& userName, gid_t primaryGid)
{
    load();

    if (!m_readable)
    {
        return {};
    }

    const auto lowerName = DirectoryKeys::name(userName);
    const auto others = otherGroupsOf(lowerName, guidOf(lowerName), primaryGid);
    std::vector<gid_t> groups {primaryGid};
    groups.insert(groups.end(), others.begin(), others.end());
    return groups;
}

bool DirectMemberships::readFailed() const
{
    return m_loaded && !m_readable;
}
