/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "od_wrapper.hpp"
#include "od_local_node.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace od
{
    /// @brief The values of one attribute of a record, as strings.
    /// @return nullopt when the record could not be read. An absent attribute is an empty list.
    static std::optional<std::vector<std::string>> readStrings(ODRecord* record, ODAttributeType attribute)
    {
        NSError* err = nullptr;
        NSArray* values = [record valuesForAttribute:attribute error:&err];

        if (err != nullptr)
        {
            return std::nullopt;
        }

        std::vector<std::string> strings;

        for (id value in values)
        {
            strings.push_back(toStdString([value description]));
        }

        return strings;
    }

    // A group record that cannot be read is left out of this read: its members lose that group
    // for one scan, where failing the whole read would leave every account without groups, and a
    // record that never reads would stop the inventory for good.
    static void addGroupMembers(ODRecord* record, std::map<std::string, ODGroupMembers>& collected)
    {
        const auto names = readStrings(record, kODAttributeTypeGroupMembership);
        const auto uuids = readStrings(record, kODAttributeTypeGroupMembers);
        const auto gids = readStrings(record, kODAttributeTypePrimaryGroupID);

        if (names && uuids && gids)
        {
            auto& members = collected[toStdString([record recordName])];
            members.names.insert(names->begin(), names->end());
            members.uuids.insert(uuids->begin(), uuids->end());
            members.gid = gids->empty() ? std::string {} : gids->front();
        }
    }

    // A user record that cannot be read, or that has no GUID, gives no GUID: the account is then
    // matched by name only. The accounts are joined by name, as the system does for a group
    // membership: the record names are unique in the node, unlike a uid text, which can be
    // written in several ways.
    static void addUserGuid(ODRecord* record, std::map<std::string, std::string>& collected)
    {
        const auto names = readStrings(record, kODAttributeTypeRecordName);
        const auto guids = readStrings(record, kODAttributeTypeGUID);

        if (names && guids && !guids->empty())
        {
            for (const auto& name : *names)
            {
                collected[name] = guids->front();
            }
        }
    }

    bool genGroupMembers(std::map<std::string, ODGroupMembers>& membersByGroup)
    {
        @autoreleasepool
        {
            // Every group has a gid, so a null value matches all of them, as in genEntries().
            NSArray* results = queryLocalNode(kODRecordTypeGroups, kODAttributeTypePrimaryGroupID, nil,
                                              @[kODAttributeTypeGroupMembership, kODAttributeTypeGroupMembers,
                                                kODAttributeTypePrimaryGroupID]);

            if (results == nil)
            {
                return false;
            }

            std::map<std::string, ODGroupMembers> collected;

            for (ODRecord * re in results)
            {
                addGroupMembers(re, collected);
            }

            membersByGroup = std::move(collected);
            return true;
        }
    }

    bool genUserGuids(std::map<std::string, std::string>& guidByName)
    {
        @autoreleasepool
        {
            // Every user has a uid, so a null value matches all of them, as in genEntries().
            NSArray* results = queryLocalNode(kODRecordTypeUsers, kODAttributeTypeUniqueID, nil,
                                              @[kODAttributeTypeRecordName, kODAttributeTypeGUID]);

            if (results == nil)
            {
                return false;
            }

            std::map<std::string, std::string> collected;

            for (ODRecord * re in results)
            {
                addUserGuid(re, collected);
            }

            guidByName = std::move(collected);
            return true;
        }
    }

} // namespace od
