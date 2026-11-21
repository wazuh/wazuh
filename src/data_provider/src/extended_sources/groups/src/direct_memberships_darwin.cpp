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

static std::set<std::string> mapAll(const std::set<std::string>& values, std::string (*convert)(std::string))
{
    std::set<std::string> mapped;
    std::transform(values.begin(), values.end(), std::inserter(mapped, mapped.end()), convert);
    return mapped;
}

// Names are not case sensitive on macOS, so the keys are folded as the member names are.
static std::map<std::string, std::string> foldNames(const std::map<std::string, std::string>& guidByName)
{
    std::map<std::string, std::string> folded;

    for (const auto& [name, guid] : guidByName)
    {
        folded[toLower(name)] = guid;
    }

    return folded;
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
        m_guidByName = foldNames(m_guidByName);
        resolveGroups(membersByGroup);
    }
}

void DirectMemberships::resolveGroups(const std::map<std::string, ODGroupMembers>& membersByGroup)
{
    for (const auto& [name, members] : membersByGroup)
    {
        // A group the system cannot resolve to a gid cannot be reported as a membership.
        if (const struct group* grp = m_groupWrapper->getgrnam(name.c_str()); grp != nullptr)
        {
            m_groups.push_back({grp->gr_gid, {mapAll(members.names, toLower), mapAll(members.uuids, toUpper)}});
        }
    }
}

std::string DirectMemberships::guidOf(const std::string& lowerName) const
{
    const auto guid = m_guidByName.find(lowerName);
    return guid != m_guidByName.end() ? toUpper(guid->second) : std::string {};
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

    const auto lowerName = toLower(userName);
    const auto others = otherGroupsOf(lowerName, guidOf(lowerName), primaryGid);
    std::vector<gid_t> groups {primaryGid};
    groups.insert(groups.end(), others.begin(), others.end());
    return groups;
}
