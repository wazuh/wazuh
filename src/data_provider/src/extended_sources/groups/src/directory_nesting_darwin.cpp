/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "directory_nesting_darwin.hpp"

namespace
{
    using DirectoryNesting::LocalGroup;
    using Feeds = std::map<std::string, std::set<std::string>>;

    // The outside GUIDs a group nests, plus the ones its nested local groups are known to bring.
    std::set<std::string> feedsOf(const LocalGroup& group, const std::set<std::string>& localGuids,
                                  const Feeds& feedsByGuid)
    {
        std::set<std::string> feeds;

        for (const auto& nested : group.nestedGuids)
        {
            const auto known = feedsByGuid.find(nested);

            if (localGuids.count(nested) == 0)
            {
                feeds.insert(nested);
            }
            else if (known != feedsByGuid.end())
            {
                feeds.insert(known->second.begin(), known->second.end());
            }
        }

        return feeds;
    }

    // One pass over the groups. @return Whether a group got feeds it did not have yet.
    bool spreadFeeds(const std::vector<LocalGroup>& groups, const std::set<std::string>& localGuids,
                     Feeds& feedsByGuid)
    {
        bool grew {false};

        // A group without a GUID cannot be nested, so nothing reads its feeds from the map.
        for (const auto& group : groups)
        {
            if (group.guid.empty())
            {
                continue;
            }

            auto feeds = feedsOf(group, localGuids, feedsByGuid);
            auto& known = feedsByGuid[group.guid];
            const auto before = known.size();
            known.insert(feeds.begin(), feeds.end());
            grew = grew || known.size() != before;
        }

        return grew;
    }
} // namespace

std::map<gid_t, std::set<std::string>> DirectoryNesting::directoryFeeds(const std::vector<LocalGroup>& groups,
                                                                        const std::set<std::string>& localGuids)
{
    Feeds feedsByGuid;

    // Each pass reaches one more level of local nesting; it stops when a pass adds nothing.
    while (spreadFeeds(groups, localGuids, feedsByGuid))
    {
    }

    std::map<gid_t, std::set<std::string>> feedsByGid;

    for (const auto& group : groups)
    {
        if (const auto feeds = feedsOf(group, localGuids, feedsByGuid); !feeds.empty())
        {
            feedsByGid[group.gid].insert(feeds.begin(), feeds.end());
        }
    }

    return feedsByGid;
}
