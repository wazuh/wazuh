/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <aclapi.h>

#include <locale>
#include <codecvt>

#include <map>
#include <string>
#include <vector>
#include <memory>
#include <set>
#include <optional>

#include "json.hpp"
#include "iusers_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"

/// @brief Smart pointer wrapper managing Windows NetAPI allocated buffers.
///
/// This class automatically frees the memory allocated by Windows NetAPI functions
/// using `NetApiBufferFree` when the object is destroyed or reset.
/// It supports move semantics but disables copy semantics to avoid double-free errors.
///
/// @tparam T Type of the NetAPI object pointed to.
template <typename T>
class NetApiObjectPtr final
{
    public:
        /// @brief Default constructor. Initializes with nullptr.
        NetApiObjectPtr() noexcept = default;

        /// @brief Move constructor. Transfers ownership from another instance.
        /// @param other The source object to move from.
        NetApiObjectPtr(NetApiObjectPtr<T>&& other) noexcept
            : pointer(std::exchange(other.pointer, nullptr)) {}

        /// @brief Destructor. Frees the allocated NetAPI buffer if owned.
        ~NetApiObjectPtr()
        {
            if (pointer != nullptr)
            {
                NetApiBufferFree(pointer);
            }
        }

        /// @brief Move assignment operator. Transfers ownership from another instance.
        /// @param other The source object to move from.
        /// @return Reference to this instance.
        NetApiObjectPtr& operator=(NetApiObjectPtr<T>&& other) noexcept
        {
            if (this != &other)
            {
                pointer = std::exchange(other.pointer, nullptr);
            }

            return *this;
        }

        /// @brief Deleted copy constructor to prevent copying.
        NetApiObjectPtr(const NetApiObjectPtr<T>&) = delete;

        /// @brief Deleted copy assignment operator to prevent copying.
        NetApiObjectPtr& operator=(const NetApiObjectPtr<T>&) = delete;

        /// @brief Dereference operator to access the managed object.
        /// @return Pointer to the managed object.
        T* operator->()
        {
            return pointer;
        }

        /// @brief Equality comparison with raw pointer.
        /// @param other Raw pointer to compare.
        /// @return True if the internal pointer equals `other`.
        bool operator==(const T* other) const
        {
            return pointer == other;
        }

        /// @brief Inequality comparison with raw pointer.
        /// @param other Raw pointer to compare.
        /// @return True if the internal pointer differs from `other`.
        bool operator!=(const T* other) const
        {
            return pointer != other;
        }

        /// @brief Returns a pointer to the internal pointer for use with NetAPI allocation.
        ///
        /// If currently owning a pointer, it frees it first to avoid leaks.
        ///
        /// @return Address of the internal pointer.
        T** get_new_ptr()
        {
            // We ensure that the pointer cannot be leaked
            if (pointer != nullptr)
            {
                NetApiBufferFree(pointer);
                pointer = nullptr;
            }

            return &pointer;
        }

        /// @brief Gets the internal raw pointer without transferring ownership.
        /// @return Const pointer to the managed object.
        const T* get() const
        {
            return pointer;
        }

    private:
        T* pointer{nullptr};
};

/// @brief Alias for NetApiObjectPtr managing USER_INFO_0 pointers.
using user_info_0_ptr = NetApiObjectPtr<USER_INFO_0>;

/// @brief Alias for NetApiObjectPtr managing USER_INFO_2 pointers.
using user_info_2_ptr = NetApiObjectPtr<USER_INFO_2>;

/// @brief Alias for NetApiObjectPtr managing USER_INFO_3 pointers.
using user_info_3_ptr = NetApiObjectPtr<USER_INFO_3>;

/// @brief Alias for NetApiObjectPtr managing USER_INFO_4 pointers.
using user_info_4_ptr = NetApiObjectPtr<USER_INFO_4>;

/// @brief Alias for NetApiObjectPtr managing LOCALGROUP_USERS_INFO_0 pointers.
using localgroup_users_info_0_ptr = NetApiObjectPtr<LOCALGROUP_USERS_INFO_0>;

const std::wstring kRegProfileKey =
    L"SOFTWARE\\Microsoft\\Windows "
    "NT\\CurrentVersion\\ProfileList";
const std::set<std::string> kWellKnownSids =
{
    "S-1-5-1",
    "S-1-5-2",
    "S-1-5-3",
    "S-1-5-4",
    "S-1-5-6",
    "S-1-5-7",
    "S-1-5-8",
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-12",
    "S-1-5-13",
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-21",
    "S-1-5-32",
};
const std::wstring kProfileValueName = L"ProfileImagePath";
const wchar_t kRegSep = '\\';

const std::set<int> kRegistryStringTypes =
{
    REG_SZ, REG_MULTI_SZ, REG_EXPAND_SZ
};

/// @brief Helper class for managing and retrieving Windows user information.
///
/// Implements `IUsersHelper` to provide user account processing, SID conversions,
/// and roaming profile handling using Windows API wrappers.
class UsersHelper : public IUsersHelper
{
    private:
        /// @brief Converts a SID to its string representation.
        /// @param sid Pointer to the SID.
        /// @return String representation of the SID.
        std::string psidToString(PSID sid);

        /// @brief Converts a wide string (wstring) to a UTF-8 std::string.
        /// @param src Pointer to the wide character string.
        /// @return Converted UTF-8 string.
        std::string wstringToString(const wchar_t* src);

        /// @brief Converts a UTF-8 std::string to a wide string (wstring).
        /// @param src Input UTF-8 string.
        /// @return Converted wide string.
        std::wstring stringToWstring(const std::string& src);

        /// @brief Retrieves the home directory path for a given SID string.
        /// @param sid String representation of the user SID.
        /// @return Path to the user's home directory.
        std::string getUserHomeDir(const std::string& sid);

        /// @brief Gets the group ID (GID) for a given Windows username.
        /// @param username Wide string username.
        /// @return Optional GID if available.
        std::optional<std::uint32_t> getGidFromUsername(LPCWSTR username);

        /// @brief Retrieves the SID for a given account name.
        /// @param account_name Wide string account name.
        /// @return Unique pointer managing the SID bytes.
        std::unique_ptr<BYTE[]> getSidFromAccountName(LPCWSTR account_name);

        /// @brief Retrieves SIDs of roaming profiles available on the system.
        /// @return Optional vector of SID strings for roaming profiles.
        std::optional<std::vector<std::string>> getRoamingProfileSids();

        /// @brief Extracts the Relative Identifier (RID) from a SID.
        /// @param sid Pointer to the SID.
        /// @return RID as a DWORD.
        DWORD getRidFromSid(PSID sid);

        /// @brief Windows API wrapper instance used for system calls.
        std::shared_ptr<IWindowsApiWrapper> m_winapiWrapper;

        /// @brief Creates a custom deleter for Windows registry handles.
        /// @return Lambda function to safely close registry handles.
        auto makeRegHandleDeleter()
        {
            return [this](HKEY handle)
            {
                m_winapiWrapper->RegCloseKeyWrapper(handle);
            };
        }

        /// @brief Unique pointer type for managing Windows registry handles.
        using reg_handle_t = std::unique_ptr<HKEY__, std::function<void(HKEY)>>;

    public:
        /// @brief Constructs a UsersHelper with a Windows API wrapper.
        /// @param winapiWrapper Shared pointer to an `IWindowsApiWrapper`.
        explicit UsersHelper(
            std::shared_ptr<IWindowsApiWrapper> winapiWrapper);

        /// @brief Default constructor.
        UsersHelper();

        /// @brief Retrieves the shell path for the user identified by the SID.
        /// @param sid String representation of the user's SID.
        /// @return The shell executable path.
        std::string getUserShell(const std::string& sid) override;

        /// @brief Processes local Windows user accounts and collects user data.
        /// @param processed_sids Set to track processed SIDs and avoid duplicates.
        /// @return Vector of User objects representing local accounts.
        std::vector<User> processLocalAccounts(std::set<std::string>& processed_sids) override;

        /// @brief Processes roaming profiles and collects user data.
        /// @param processed_sids Set to track processed SIDs and avoid duplicates.
        /// @return Vector of User objects representing roaming profiles.
        std::vector<User> processRoamingProfiles(std::set<std::string>& processed_sids) override;
};
