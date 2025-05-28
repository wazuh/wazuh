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
    DWORD group_info_level = 1;
    DWORD num_groups_read = 0;
    DWORD total_groups = 0;
    DWORD ret = 0;
    localgroup_info_1_ptr groups_info_buffer;

    do
    {
        ret = m_winapiWrapper->NetLocalGroupEnumWrapper(nullptr,
                                                        group_info_level,
                                                        reinterpret_cast<LPBYTE*>(groups_info_buffer.get_new_ptr()),
                                                        MAX_PREFERRED_LENGTH,
                                                        &num_groups_read,
                                                        &total_groups,
                                                        nullptr);

        if (ret != NERR_Success && ret != ERROR_MORE_DATA)
        {
            std::cout << "NetLocalGroupEnum failed with return value: " << ret << std::endl;
            break;
        }

        if (groups_info_buffer == nullptr)
        {
            std::cout << "NetLocalGroupEnum groups buffer is null" << std::endl;
            break;
        }

        for (std::size_t i = 0; i < num_groups_read; i++)
        {
            PWSTR groupname = groups_info_buffer.get()[i].lgrpi1_name;
            auto sid_ptr = m_usersHelper->getSidFromAccountName(groupname);

            if (!sid_ptr)
            {
                // If we failed to find a SID, don't add a row to the table.
                std::cout << "Failed to find a SID from LookupAccountNameW for group: "
                          << Utils::EncodingWindowsHelper::wstringToStringUTF8(groupname) << std::endl;
                continue;
            }

            const auto& group_sid = sid_ptr.get();

            Group new_group;
            new_group.sid = m_usersHelper->psidToString(group_sid);
            new_group.comment = Utils::EncodingWindowsHelper::wstringToStringUTF8(groups_info_buffer.get()[i].lgrpi1_comment);
            new_group.gid = m_usersHelper->getRidFromSid(group_sid);
            new_group.groupname = Utils::EncodingWindowsHelper::wstringToStringUTF8(groups_info_buffer.get()[i].lgrpi1_name);

            groups.push_back(std::move(new_group));
        }

    }
    while (ret == ERROR_MORE_DATA);

    return groups;
}
