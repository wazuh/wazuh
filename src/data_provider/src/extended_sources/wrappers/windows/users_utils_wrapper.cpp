/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "users_utils_wrapper.hpp"
#include "windows_api_wrapper.hpp"
#include "encodingWindowsHelper.h"

#include <iostream>

UsersHelper::UsersHelper(
    std::shared_ptr<IWindowsApiWrapper> winapiWrapper)
    : m_winapiWrapper(std::move(winapiWrapper)) {}

UsersHelper::UsersHelper()
    : m_winapiWrapper(std::make_shared<WindowsApiWrapper>()) {}

std::string UsersHelper::wstringToString(const wchar_t* src)
{
    if (src == nullptr)
    {
        return std::string("");
    }

    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::string utf8_str = converter.to_bytes(src);
    return utf8_str;
}

std::wstring UsersHelper::stringToWstring(const std::string& src)
{
    std::wstring utf16le_str;

    try
    {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        utf16le_str = converter.from_bytes(src);
    }
    catch (const std::exception& /* e */)
    {
        // std::cout << "Failed to convert string to wstring " << src;
    }

    return utf16le_str;
}

std::string UsersHelper::getUserHomeDir(const std::string& sid)
{
    std::wstring profile_key_path = kRegProfileKey;
    profile_key_path += kRegSep;
    profile_key_path += stringToWstring(sid);

    HKEY hkey;
    auto ret = m_winapiWrapper->RegOpenKeyExWWrapper(
                   HKEY_LOCAL_MACHINE, profile_key_path.c_str(), 0, KEY_READ, &hkey);

    if (ret != ERROR_SUCCESS)
    {
        if (ret != ERROR_FILE_NOT_FOUND)
        {
            // std::cout << "Failed to open " << wstringToString(profile_key_path.c_str())
            //   << " with error " << ret;
        }

        return {};
    }

    reg_handle_t registry_handle(hkey, makeRegHandleDeleter());
    DWORD values_count;
    DWORD max_value_data_length;

    ret = m_winapiWrapper->RegQueryInfoKeyWWrapper(registry_handle.get(),
                                                   nullptr,
                                                   nullptr,
                                                   nullptr,
                                                   nullptr,
                                                   nullptr,
                                                   nullptr,
                                                   &values_count,
                                                   nullptr,
                                                   &max_value_data_length,
                                                   nullptr,
                                                   nullptr);

    if (ret != ERROR_SUCCESS)
    {
        // std::cout << "Failed to query key info " << wstringToString(profile_key_path.c_str())
        //     << " with error " << ret;
        return {};
    }

    if (values_count == 0)
    {
        return {};
    }

    DWORD value_type;
    DWORD value_data_length;
    std::wstring value_data;
    value_data.resize(max_value_data_length);

    value_data_length = max_value_data_length;

    ret = m_winapiWrapper->RegQueryValueExWWrapper(registry_handle.get(),
                                                   kProfileValueName.c_str(),
                                                   nullptr,
                                                   &value_type,
                                                   reinterpret_cast<LPBYTE>(value_data.data()),
                                                   &value_data_length);

    if (ret != ERROR_SUCCESS)
    {
        // std::cout << "Failed to query value " << wstringToString(kProfileValueName.c_str())
        //     << " for key " << wstringToString(profile_key_path.c_str())
        //     << " with error " << ret;
        return {};
    }

    if (kRegistryStringTypes.find(value_type) == kRegistryStringTypes.end())
    {
        // std::cout << "Value " << wstringToString(kProfileValueName.c_str()) << " in key "
        //     << wstringToString(profile_key_path.c_str()) << " is not a string";
        return {};
    }

    return wstringToString(value_data.c_str());
}

std::optional<std::uint32_t> UsersHelper::getGidFromUsername(LPCWSTR username)
{
    // Use NetUserGetLocalGroups to get a Local Group GID for this user
    WORD level = 0;
    DWORD flags = 0;
    DWORD pref_max_len = MAX_PREFERRED_LENGTH;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    std::unique_ptr<BYTE[]> sid_smart_ptr = nullptr;
    localgroup_users_info_0_ptr user_groups_buff;

    auto ret = m_winapiWrapper->NetUserGetLocalGroupsWrapper(
                   nullptr,
                   username,
                   level,
                   flags,
                   reinterpret_cast<LPBYTE*>(user_groups_buff.get_new_ptr()),
                   pref_max_len,
                   &entries_read,
                   &total_entries);

    std::optional<std::uint32_t> gid;

    if (ret == NERR_Success)
    {
        // A user often has more than one local group. We only return the first!
        if (user_groups_buff != nullptr)
        {
            auto group_sid_ptr = getSidFromAccountName(user_groups_buff->lgrui0_name);

            if (group_sid_ptr)
            {
                gid = getRidFromSid(group_sid_ptr.get());
            }

            return gid;
        }
    }

    user_info_3_ptr user_buff;

    /* If none of the above worked, the user may not have a Local Group.
       Fallback to using the primary group id from its USER_INFO_3 struct */
    DWORD user_info_level = 3;
    ret = m_winapiWrapper->NetUserGetInfoWrapper(nullptr,
                                                 username,
                                                 user_info_level,
                                                 reinterpret_cast<LPBYTE*>(user_buff.get_new_ptr()));

    if (ret == NERR_Success)
    {
        gid = user_buff->usri3_primary_group_id;
    }

    return gid;
}

std::optional<std::vector<std::string>> UsersHelper::getRoamingProfileSids()
{
    HKEY hkey;
    auto ret = m_winapiWrapper->RegOpenKeyExWWrapper(
                   HKEY_LOCAL_MACHINE, kRegProfileKey.c_str(), 0, KEY_READ, &hkey);

    if (ret != ERROR_SUCCESS)
    {
        return std::nullopt;
    }

    reg_handle_t registry_handle(hkey, makeRegHandleDeleter());

    const auto max_key_length = 255;
    DWORD subkeys_count;
    DWORD max_name_length;
    DWORD ret_code;

    ret_code = m_winapiWrapper->RegQueryInfoKeyWWrapper(registry_handle.get(),
                                                        nullptr,
                                                        nullptr,
                                                        nullptr,
                                                        &subkeys_count,
                                                        nullptr,
                                                        nullptr,
                                                        nullptr,
                                                        &max_name_length,
                                                        nullptr,
                                                        nullptr,
                                                        nullptr);

    if (ret_code != ERROR_SUCCESS)
    {
        return std::nullopt;
    }

    if (subkeys_count == 0)
    {
        return {};
    }

    std::wstring key_name;
    key_name.resize(max_key_length);

    std::vector<std::string> subkeys_names;

    // Process registry subkeys
    for (DWORD i = 0; i < subkeys_count; i++)
    {
        ret_code =
            m_winapiWrapper->RegEnumKeyWWrapper(registry_handle.get(), i, key_name.data(), max_key_length);

        if (ret_code != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        subkeys_names.emplace_back(wstringToString(key_name.c_str()));
    }

    return subkeys_names;
}

DWORD UsersHelper::getRidFromSid(PSID sid)
{
    BYTE* count_ptr = m_winapiWrapper->GetSidSubAuthorityCountWrapper(sid);
    DWORD index_of_rid = static_cast<DWORD>(*count_ptr - 1);
    DWORD* rid_ptr = m_winapiWrapper->GetSidSubAuthorityWrapper(sid, index_of_rid);
    return *rid_ptr;
}

std::string UsersHelper::getUserShell(const std::string& sid)
{
    // TODO: This column exists for cross-platform consistency, but
    // the answer on Windows is arbitrary. %COMSPEC% env variable may
    // be the best answer. Currently, hard-coded.
    (void)sid;
    return "C:\\Windows\\system32\\cmd.exe";
}

// Enumerate all local users, constraining results to the list of UIDs if
// any, and recording all enumerated users' SIDs to exclude later from the
// walk of the Roaming Profiles key in the registry.
std::vector<User> UsersHelper::processLocalAccounts(std::set<std::string>& processed_sids)
{
    // Enumerate the users by only the usernames (level 0 struct) and then
    // get the desired level of info for each (level 4 struct includes SIDs).

    std::vector<User> users;
    DWORD user_info_level = 0;
    DWORD detailed_user_info_level = 4;
    DWORD num_users_read = 0;
    DWORD total_users = 0;
    DWORD resume_handle = 0;
    DWORD ret = 0;
    user_info_0_ptr users_info_buffer;

    do
    {
        ret =
            m_winapiWrapper->NetUserEnumWrapper(nullptr,
                                                user_info_level,
                                                FILTER_NORMAL_ACCOUNT,
                                                reinterpret_cast<LPBYTE*>(users_info_buffer.get_new_ptr()),
                                                MAX_PREFERRED_LENGTH,
                                                &num_users_read,
                                                &total_users,
                                                &resume_handle);

        if (ret != NERR_Success && ret != ERROR_MORE_DATA)
        {
            // std::cout << "NetUserEnum failed with return value " << ret;
            break;
        }

        if (users_info_buffer == nullptr)
        {
            // std::cout << "NetUserEnum user buffer is null";
            break;
        }

        for (DWORD i = 0; i < num_users_read; ++i)
        {
            const auto& user_info_lvl0 = users_info_buffer.get()[i];

            user_info_4_ptr user_info_lvl4;
            ret = m_winapiWrapper->NetUserGetInfoWrapper(
                      nullptr,
                      user_info_lvl0.usri0_name,
                      detailed_user_info_level,
                      reinterpret_cast<LPBYTE*>(user_info_lvl4.get_new_ptr()));

            if (ret != NERR_Success || user_info_lvl4 == nullptr)
            {
                // std::cout << "Failed to get additional information for the user "
                //          << wstringToString(user_info_lvl0.usri0_name)
                //          << " with error code " << ret;
                continue;
            }

            User new_user;

            PSID sid = user_info_lvl4->usri4_user_sid;
            std::string sid_string = psidToString(sid);
            processed_sids.insert(sid_string);

            new_user.username = wstringToString(user_info_lvl4->usri4_name);
            new_user.uid = getRidFromSid(sid);

            /* NOTE: This still keeps the old behavior where if getting the gid
               from the first local group or the primary group id fails,
               then we use the uid of the user. */
            new_user.gid = getGidFromUsername(user_info_lvl4->usri4_name).value_or(new_user.uid);
            new_user.description = wstringToString(user_info_lvl4->usri4_comment);
            new_user.directory = getUserHomeDir(sid_string);
            new_user.type = "local";
            new_user.sid = std::move(sid_string);

            users.push_back(new_user);
        }

    }
    while (ret == ERROR_MORE_DATA);

    return users;
}

// Enumerate the users from the profiles key in the Registry, matching only
// the UIDs/RIDs (if any) and skipping any SIDs of local-only users that
// were already processed in the earlier API-based enumeration.
std::vector<User> UsersHelper::processRoamingProfiles(std::set<std::string>& processed_sids)
{

    std::vector<User> users;

    auto opt_roaming_profile_sids = getRoamingProfileSids();

    if (!opt_roaming_profile_sids.has_value())
    {
        return users;
    }

    for (const auto& profile_sid : *opt_roaming_profile_sids)
    {
        // Skip this user if already processed
        if (processed_sids.find(profile_sid) != processed_sids.end())
        {
            continue;
        }

        User new_user;

        new_user.sid = profile_sid;
        new_user.type = kWellKnownSids.find(profile_sid) == kWellKnownSids.end()
                        ? "roaming"
                        : "special";

        PSID sid;
        auto ret = m_winapiWrapper->ConvertStringSidToSidAWrapper(profile_sid.c_str(), &sid);

        if (ret == FALSE)
        {
            // std::cout << "Converting SIDstring to SID failed with " << GetLastError();
            continue;
        }
        else
        {
            new_user.uid = getRidFromSid(sid);
            new_user.directory = getUserHomeDir(profile_sid);

            wchar_t account_name[UNLEN] = {0};
            wchar_t domain_name[DNLEN] = {0};
            DWORD account_name_length = UNLEN;
            DWORD domain_name_length = DNLEN;
            SID_NAME_USE e_use;
            ret = m_winapiWrapper->LookupAccountSidWWrapper(nullptr,
                                                            sid,
                                                            account_name,
                                                            &account_name_length,
                                                            domain_name,
                                                            &domain_name_length,
                                                            &e_use);

            m_winapiWrapper->FreeSidWrapper(sid);

            if (ret != FALSE)
            {
                new_user.username = wstringToString(account_name);
                /* NOTE: This still keeps the old behavior where if getting the gid
                from the first local group or the primary group id fails,
                then we use the uid of the user. */
                new_user.gid = getGidFromUsername(account_name).value_or(new_user.uid);
            }
            else
            {
                new_user.gid = -1;
            }

            // Also attempt to get the user account description comment. Move on if
            // NetUserGetInfo returns an error, as it will for some system accounts.
            DWORD basic_user_info_level = 2;
            user_info_2_ptr user_info_lvl2;
            ret = m_winapiWrapper->NetUserGetInfoWrapper(
                      nullptr,
                      account_name,
                      basic_user_info_level,
                      reinterpret_cast<LPBYTE*>(user_info_lvl2.get_new_ptr()));

            if (ret == NERR_Success && user_info_lvl2 != nullptr)
            {
                new_user.description = wstringToString(user_info_lvl2->usri2_comment);
            }

            users.push_back(new_user);
        }
    }

    return users;
}

std::unique_ptr<BYTE[]> UsersHelper::getSidFromAccountName(const std::wstring& accountNameInput)
{
    auto accountName = accountNameInput.data();

    if (accountName == nullptr || accountName[0] == 0)
    {
        std::cerr << "No account name provided" << std::endl;
        return nullptr;
    }

    // Call LookupAccountNameW() once to retrieve the necessary buffer sizes for
    // the SID (in bytes) and the domain name (in TCHARS):
    DWORD sidBufferSize = 0;
    DWORD domainNameSize = 0;
    auto eSidType = SidTypeUnknown;
    auto ret = m_winapiWrapper->LookupAccountNameWWrapper(nullptr,
                                                          accountName,
                                                          nullptr,
                                                          &sidBufferSize,
                                                          nullptr,
                                                          &domainNameSize,
                                                          &eSidType);

    if (ret == 0 && m_winapiWrapper->GetLastErrorWrapper() != ERROR_INSUFFICIENT_BUFFER)
    {
        std::cerr << "Failed to lookup account name " << Utils::EncodingWindowsHelper::wstringToStringUTF8(accountName)
                  << " with " << m_winapiWrapper->GetLastErrorWrapper() << std::endl;
        return nullptr;
    }

    // Allocate buffers for the (binary data) SID and (wide string) domain name:
    auto sidBuffer = std::make_unique<BYTE[]>(sidBufferSize);
    std::vector<wchar_t> domainName(domainNameSize);

    // Call LookupAccountNameW() a second time to actually obtain the SID for
    // the given account name:
    ret = m_winapiWrapper->LookupAccountNameWWrapper(nullptr,
                                                     accountName,
                                                     sidBuffer.get(),
                                                     &sidBufferSize,
                                                     domainName.data(),
                                                     &domainNameSize,
                                                     &eSidType);

    if (ret == 0)
    {
        std::cerr << "Failed to lookup account name " << Utils::EncodingWindowsHelper::wstringToStringUTF8(accountName)
                  << " with " << m_winapiWrapper->GetLastErrorWrapper() << std::endl;
        return nullptr;
    }
    else if (m_winapiWrapper->IsValidSidWrapper(sidBuffer.get()) == FALSE)
    {
        std::cerr << "The SID for " << Utils::EncodingWindowsHelper::wstringToStringUTF8(accountName)
                  << " is invalid." << std::endl;
    }

    // Implicit move operation. Caller "owns" returned pointer:
    return sidBuffer;
}

std::string UsersHelper::psidToString(PSID sid)
{
    LPWSTR sidOut = nullptr;
    // Custom deleter to free the allocated memory for sidOut.
    auto deleter = [](LPWSTR * p)
    {
        if (p && *p) LocalFree(*p);
    };
    std::unique_ptr<LPWSTR, decltype(deleter)> sidGuard(&sidOut, deleter);

    if (!m_winapiWrapper->ConvertSidToStringSidWWrapper(sid, &sidOut))
    {
        std::cerr << "ConvertSidToStringW failed with " << m_winapiWrapper->GetLastErrorWrapper() << std::endl;
        return {};
    }

    return Utils::EncodingWindowsHelper::wstringToStringUTF8(sidOut);
}
