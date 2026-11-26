/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <iterator>

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

// The gids of the directory groups that feed each local group. A GUID the membership service
// cannot resolve feeds nothing, so the local group is not reported through it.
static std::map<gid_t, std::set<gid_t>> resolveFeeds(const IGroupWrapperDarwin& groupWrapper,
                                                     const std::map<gid_t, std::set<std::string>>& feedGuids)
{
    std::map<std::string, std::optional<gid_t>> gidByGuid;
    std::map<gid_t, std::set<gid_t>> feeds;

    for (const auto& [localGid, guids] : feedGuids)
    {
        for (const auto& guid : guids)
        {
            auto known = gidByGuid.find(guid);

            if (known == gidByGuid.end())
            {
                known = gidByGuid.emplace(guid, groupWrapper.gidOfGroupGuid(guid)).first;
            }

            if (known->second.has_value())
            {
                feeds[localGid].insert(*known->second);
            }
        }
    }

    return feeds;
}

// Whether the account is in one of the directory groups that feed this local group.
static bool reachedThroughDirectory(const std::map<gid_t, std::set<gid_t>>& feeds, gid_t localGid,
                                    const std::set<gid_t>& effective)
{
    const auto fed = feeds.find(localGid);
    return fed != feeds.end() && std::any_of(fed->second.begin(), fed->second.end(), [&](gid_t feed)
    {
        return effective.count(feed) != 0;
    });
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
    std::set<std::string> localGuids;
    std::vector<DirectoryNesting::LocalGroup> nesting;

    for (const auto& [name, members] : membersByGroup)
    {
        localGuids.insert(DirectoryKeys::guid(members.guid));

        // A group without a gid cannot be reported as a membership.
        if (const auto gid = gidOf(name, members.gid); gid.has_value())
        {
            addGroup(*gid, members, nesting);
        }
    }

    m_fedByDirectory = resolveFeeds(*m_groupWrapper, DirectoryNesting::directoryFeeds(nesting, localGuids));
}

void DirectMemberships::addGroup(gid_t gid, const ODGroupMembers& members,
                                 std::vector<DirectoryNesting::LocalGroup>& nesting)
{
    m_localGids.insert(gid);

    // An unreadable record still makes its gid a local one, but it has no members to report.
    if (members.readable)
    {
        m_groups.push_back({gid, {DirectoryKeys::names(members.names), DirectoryKeys::guids(members.uuids), {}}});
        nesting.push_back({gid, DirectoryKeys::guid(members.guid), DirectoryKeys::guids(members.nestedGuids)});
    }
}

std::vector<gid_t> DirectMemberships::groupsFromDirectoryServices(const std::vector<gid_t>& effectiveGids) const
{
    const std::set<gid_t> effective(effectiveGids.begin(), effectiveGids.end());
    std::vector<gid_t> groups;
    std::copy_if(effectiveGids.begin(), effectiveGids.end(), std::back_inserter(groups), [&](gid_t gid)
    {
        return m_localGids.count(gid) == 0 || reachedThroughDirectory(m_fedByDirectory, gid, effective);
    });
    return groups;
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
