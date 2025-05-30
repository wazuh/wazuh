/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>

#include "groups_utils_wrapper.hpp"
#include "users_utils_wrapper.hpp"
#include "windows_api_wrapper.hpp"
#include "encodingWindowsHelper.h"

GroupsHelper::GroupsHelper(std::shared_ptr<IWindowsApiWrapper> winapiWrapper, std::shared_ptr<IUsersHelper> usersHelper)
    : m_winapiWrapper(std::move(winapiWrapper))
    , m_usersHelper(std::move(usersHelper))
{
}

GroupsHelper::GroupsHelper()
    : m_winapiWrapper(std::make_shared<WindowsApiWrapper>())
    , m_usersHelper(std::make_shared<UsersHelper>())
{
}

std::vector<Group> GroupsHelper::processLocalGroups()
{
    std::vector<Group> groups;
    DWORD groupInfoLevel = 1;
    DWORD numGroupsRead = 0;
    DWORD totalGroups = 0;
    DWORD ret = 0;
    localgroup_info_1_ptr groupsInfoBuffer;

    do
    {
        ret = m_winapiWrapper->NetLocalGroupEnumWrapper(nullptr,
                                                        groupInfoLevel,
                                                        reinterpret_cast<LPBYTE*>(groupsInfoBuffer.get_new_ptr()),
                                                        MAX_PREFERRED_LENGTH,
                                                        &numGroupsRead,
                                                        &totalGroups,
                                                        nullptr);

        if (ret != NERR_Success && ret != ERROR_MORE_DATA)
        {
            // std::cout << "NetLocalGroupEnum failed with return value: " << ret << std::endl;
            break;
        }

        if (groupsInfoBuffer == nullptr)
        {
            // std::cout << "NetLocalGroupEnum groups buffer is null" << std::endl;
            break;
        }

        for (std::size_t i = 0; i < numGroupsRead; i++)
        {
            PWSTR groupname = groupsInfoBuffer.get()[i].lgrpi1_name;
            auto pSid = m_usersHelper->getSidFromAccountName(groupname);

            if (!pSid)
            {
                // If we failed to find a SID, don't add a row to the table.
                // std::cout << "Failed to find a SID from LookupAccountNameW for group: "
                //           << Utils::EncodingWindowsHelper::wstringToStringUTF8(groupname) << std::endl;
                continue;
            }

            const auto& groupSid = pSid.get();

            Group newGroup;
            newGroup.sid = m_usersHelper->psidToString(groupSid);
            newGroup.comment = Utils::EncodingWindowsHelper::wstringToStringUTF8(groupsInfoBuffer.get()[i].lgrpi1_comment);
            newGroup.gid = m_usersHelper->getRidFromSid(groupSid);
            newGroup.groupname = Utils::EncodingWindowsHelper::wstringToStringUTF8(groupsInfoBuffer.get()[i].lgrpi1_name);

            groups.push_back(std::move(newGroup));
        }

    }
    while (ret == ERROR_MORE_DATA);

    return groups;
}
