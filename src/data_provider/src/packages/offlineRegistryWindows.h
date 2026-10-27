/* * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OFFLINE_REGISTRY_WINDOWS_H
#define _OFFLINE_REGISTRY_WINDOWS_H

#include <winsock2.h>
#include <windows.h>
#include <algorithm>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <vector>
#include "encodingWindowsHelper.h"
#include "stringHelper.h"
#include "windowsHelper.h"

using ORHKEY = PVOID;

/*
 * Offline Registry Library (offreg.dll), which ships with Windows and reads a hive file into memory
 * without loading it into the registry: nothing is mounted, no privilege is needed and the file is
 * never written. It is loaded by its System32 path, so it cannot be planted next to the agent.
 */
class OffregApi final
{
    public:
        static const OffregApi& instance()
        {
            static const OffregApi s_instance;
            return s_instance;
        }

        DWORD openHive(const std::wstring& file, ORHKEY* hive) const
        {
            return m_openHive ? m_openHive(file.c_str(), hive) : ERROR_PROC_NOT_FOUND;
        }

        DWORD openHive(const HANDLE file, ORHKEY* hive) const
        {
            return m_openHiveByHandle ? m_openHiveByHandle(file, hive) : ERROR_PROC_NOT_FOUND;
        }

        DWORD closeHive(const ORHKEY hive) const
        {
            return m_closeHive ? m_closeHive(hive) : ERROR_PROC_NOT_FOUND;
        }

        DWORD openKey(const ORHKEY key, const std::wstring& subKey, ORHKEY* result) const
        {
            return m_openKey ? m_openKey(key, subKey.c_str(), result) : ERROR_PROC_NOT_FOUND;
        }

        DWORD closeKey(const ORHKEY key) const
        {
            return m_closeKey ? m_closeKey(key) : ERROR_PROC_NOT_FOUND;
        }

        DWORD enumKey(const ORHKEY key, const DWORD index, PWSTR name, PDWORD nameSize) const
        {
            return m_enumKey ? m_enumKey(key, index, name, nameSize, nullptr, nullptr, nullptr) : ERROR_PROC_NOT_FOUND;
        }

        DWORD enumValue(const ORHKEY key, const DWORD index, PWSTR name, PDWORD nameSize) const
        {
            return m_enumValue ? m_enumValue(key, index, name, nameSize, nullptr, nullptr, nullptr) : ERROR_PROC_NOT_FOUND;
        }

        DWORD getValue(const ORHKEY key, const std::wstring& valueName, PDWORD type, PVOID data, PDWORD dataSize) const
        {
            return m_getValue ? m_getValue(key, nullptr, valueName.c_str(), type, data, dataSize) : ERROR_PROC_NOT_FOUND;
        }

        DWORD lastWriteTime(const ORHKEY key, PFILETIME time) const
        {
            return m_queryInfoKey ? m_queryInfoKey(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, time)
                   : ERROR_PROC_NOT_FOUND;
        }

        OffregApi(const OffregApi&) = delete;
        OffregApi& operator=(const OffregApi&) = delete;

    private:
        using OpenHiveFn = DWORD (WINAPI*)(PCWSTR, ORHKEY*);
        using OpenHiveByHandleFn = DWORD (WINAPI*)(HANDLE, ORHKEY*);
        using CloseFn = DWORD (WINAPI*)(ORHKEY);
        using OpenKeyFn = DWORD (WINAPI*)(ORHKEY, PCWSTR, ORHKEY*);
        using EnumFn = DWORD (WINAPI*)(ORHKEY, DWORD, PWSTR, PDWORD, PVOID, PDWORD, PVOID);
        using GetValueFn = DWORD (WINAPI*)(ORHKEY, PCWSTR, PCWSTR, PDWORD, PVOID, PDWORD);
        using QueryInfoKeyFn = DWORD (WINAPI*)(ORHKEY, PWSTR, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PFILETIME);

        OffregApi()
        {
            wchar_t systemDirectory[MAX_PATH] {};
            const auto size {GetSystemDirectoryW(systemDirectory, MAX_PATH)};

            if (size == 0 || size >= MAX_PATH)
            {
                return;
            }

            // The library stays loaded for the lifetime of the process.
            const auto module = LoadLibraryW((std::wstring(systemDirectory) + L"\\offreg.dll").c_str());

            if (module)
            {
                m_openHive = reinterpret_cast<OpenHiveFn>(reinterpret_cast<void*>(GetProcAddress(module, "OROpenHive")));
                m_openHiveByHandle = reinterpret_cast<OpenHiveByHandleFn>(reinterpret_cast<void*>(GetProcAddress(module, "OROpenHiveByHandle")));
                m_closeHive = reinterpret_cast<CloseFn>(reinterpret_cast<void*>(GetProcAddress(module, "ORCloseHive")));
                m_openKey = reinterpret_cast<OpenKeyFn>(reinterpret_cast<void*>(GetProcAddress(module, "OROpenKey")));
                m_closeKey = reinterpret_cast<CloseFn>(reinterpret_cast<void*>(GetProcAddress(module, "ORCloseKey")));
                m_enumKey = reinterpret_cast<EnumFn>(reinterpret_cast<void*>(GetProcAddress(module, "OREnumKey")));
                m_enumValue = reinterpret_cast<EnumFn>(reinterpret_cast<void*>(GetProcAddress(module, "OREnumValue")));
                m_getValue = reinterpret_cast<GetValueFn>(reinterpret_cast<void*>(GetProcAddress(module, "ORGetValue")));
                m_queryInfoKey = reinterpret_cast<QueryInfoKeyFn>(reinterpret_cast<void*>(GetProcAddress(module, "ORQueryInfoKey")));
            }
        }

        OpenHiveFn m_openHive {nullptr};
        OpenHiveByHandleFn m_openHiveByHandle {nullptr};
        CloseFn m_closeHive {nullptr};
        OpenKeyFn m_openKey {nullptr};
        CloseFn m_closeKey {nullptr};
        EnumFn m_enumKey {nullptr};
        EnumFn m_enumValue {nullptr};
        GetValueFn m_getValue {nullptr};
        QueryInfoKeyFn m_queryInfoKey {nullptr};
};

/*
 * Hive file opened with the Offline Registry Library, by path or through an open handle. The file is read
 * into memory when it is opened, so it is not held while the keys are read.
 */
template <typename TApi = OffregApi>
class TOfflineHive final
{
    public:
        explicit TOfflineHive(const std::wstring& file)
            : m_result {TApi::instance().openHive(file, &m_hive)}
        {
            if (m_result != ERROR_SUCCESS)
            {
                m_hive = nullptr;
            }
        }

        explicit TOfflineHive(const HANDLE file)
            : m_result {TApi::instance().openHive(file, &m_hive)}
        {
            if (m_result != ERROR_SUCCESS)
            {
                m_hive = nullptr;
            }
        }

        ~TOfflineHive()
        {
            if (m_hive)
            {
                TApi::instance().closeHive(m_hive);
            }
        }

        TOfflineHive(const TOfflineHive&) = delete;
        TOfflineHive& operator=(const TOfflineHive&) = delete;

        // The hive root, as the HKEY a registry reader is built on.
        HKEY key() const
        {
            return reinterpret_cast<HKEY>(m_hive);
        }

        DWORD result() const
        {
            return m_result;
        }

    private:
        ORHKEY m_hive {nullptr};
        const DWORD m_result;
};

using OfflineHive = TOfflineHive<>;

/*
 * Key of a hive opened with TOfflineHive, read through the same interface as Utils::Registry. Names and
 * strings are returned in the ANSI code page, as Utils::Registry reads them, so a hive returns the same
 * values offline as once loaded.
 */
template <typename TApi = OffregApi>
class TOfflineRegistry final
{
    public:
        // key is a TOfflineHive::key() or another key of the same hive.
        TOfflineRegistry(const HKEY key, const std::string& subKey = "", const REGSAM = KEY_READ)
        {
            const auto result {TApi::instance().openKey(reinterpret_cast<ORHKEY>(key),
                                                        Utils::EncodingWindowsHelper::stringToWStringAnsi(subKey),
                                                        &m_key)};

            if (result != ERROR_SUCCESS)
            {
                m_key = nullptr;
                throw std::system_error {static_cast<int>(result), std::system_category(), "Error opening registry: " + subKey};
            }
        }

        ~TOfflineRegistry()
        {
            if (m_key)
            {
                TApi::instance().closeKey(m_key);
            }
        }

        TOfflineRegistry(const TOfflineRegistry&) = delete;
        TOfflineRegistry& operator=(const TOfflineRegistry&) = delete;

        DWORD dword(const std::string& valueName) const
        {
            DWORD ret {};

            if (!dword(valueName, ret))
            {
                throw std::runtime_error {"Error reading DWORD value of: " + valueName};
            }

            return ret;
        }

        bool dword(const std::string& valueName, DWORD& value) const
        {
            DWORD size {sizeof(DWORD)};
            return TApi::instance().getValue(m_key, Utils::EncodingWindowsHelper::stringToWStringAnsi(valueName), nullptr, &value, &size) == ERROR_SUCCESS;
        }

        bool qword(const std::string& valueName, ULONGLONG& value) const
        {
            ULONGLONG valueRegistry {};
            DWORD size {sizeof(ULONGLONG)};
            DWORD type {};
            const auto result {TApi::instance().getValue(m_key, Utils::EncodingWindowsHelper::stringToWStringAnsi(valueName), &type, &valueRegistry, &size)};

            if (result != ERROR_SUCCESS)
            {
                throw std::system_error {static_cast<int>(result), std::system_category(), "Error reading the value of: " + valueName};
            }

            if (type != REG_QWORD)
            {
                return false;
            }

            value = valueRegistry;
            return true;
        }

        std::vector<std::string> enumerate() const
        {
            return enumerateNames(true);
        }

        void enumerate(const std::function<void(const std::string&)>& callback) const
        {
            for (const auto& name : enumerate())
            {
                callback(name);
            }
        }

        bool enumerate(std::vector<std::string>& values) const
        {
            try
            {
                values = enumerate();
            }
            catch (...)
            {
                return false;
            }

            return true;
        }

        std::vector<std::string> enumerateValueKey() const
        {
            return enumerateNames(false);
        }

        bool enumerateValueKey(std::vector<std::string>& values) const
        {
            try
            {
                values = enumerateValueKey();
            }
            catch (...)
            {
                return false;
            }

            return true;
        }

        std::string keyModificationDate() const
        {
            FILETIME lastWriteTime {};

            if (TApi::instance().lastWriteTime(m_key, &lastWriteTime) != ERROR_SUCCESS)
            {
                return {};
            }

            ULARGE_INTEGER time {};
            time.LowPart = lastWriteTime.dwLowDateTime;
            time.HighPart = lastWriteTime.dwHighDateTime;
            return Utils::buildTimestamp(time.QuadPart);
        }

        std::string string(const std::string& valueName) const
        {
            const auto wideName {Utils::EncodingWindowsHelper::stringToWStringAnsi(valueName)};
            DWORD type {};
            DWORD size {0};
            auto result {TApi::instance().getValue(m_key, wideName, &type, nullptr, &size)};

            if (result != ERROR_SUCCESS)
            {
                throw std::system_error {static_cast<int>(result), std::system_category(), "Error reading the size of: " + valueName};
            }

            // Room for a terminator the stored data may lack.
            std::vector<BYTE> data(size + sizeof(wchar_t), 0);
            result = TApi::instance().getValue(m_key, wideName, &type, data.data(), &size);

            if (result != ERROR_SUCCESS)
            {
                throw std::system_error {static_cast<int>(result), std::system_category(), "Error reading String value of: " + valueName};
            }

            // As the ANSI registry functions, the string types are converted and the rest is returned as is.
            if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)
            {
                const auto text {reinterpret_cast<const wchar_t*>(data.data())};
                return Utils::EncodingWindowsHelper::wstringToStringAnsi(std::wstring(text, wcsnlen(text, size / sizeof(wchar_t))));
            }

            return std::string {reinterpret_cast<const char*>(data.data())};
        }

        bool string(const std::string& valueName, std::string& value) const
        {
            try
            {
                value = Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(string(valueName));
            }
            catch (...)
            {
                return false;
            }

            return true;
        }

    private:
        std::vector<std::string> enumerateNames(const bool keys) const
        {
            // Same limits as Utils::Registry, so a name it cannot read is not read here either.
            constexpr DWORD MAX_KEY_NAME_SIZE {255};
            constexpr DWORD MAX_VALUE_NAME_SIZE {32767};
            const auto maxSize {keys ? MAX_KEY_NAME_SIZE : MAX_VALUE_NAME_SIZE};
            std::vector<wchar_t> buffer(maxSize, L'\0');
            std::vector<std::string> ret;
            DWORD index {0};
            DWORD result {ERROR_SUCCESS};

            while (true)
            {
                DWORD size {maxSize};
                result = keys ? TApi::instance().enumKey(m_key, index, buffer.data(), &size)
                         : TApi::instance().enumValue(m_key, index, buffer.data(), &size);

                if (result != ERROR_SUCCESS)
                {
                    break;
                }

                ret.push_back(Utils::EncodingWindowsHelper::wstringToStringAnsi(std::wstring(buffer.data(), size)));
                ++index;
            }

            if (result != ERROR_NO_MORE_ITEMS)
            {
                throw std::system_error {static_cast<int>(result), std::system_category(), "Error enumerating registry."};
            }

            return ret;
        }

        ORHKEY m_key {nullptr};
};

using OfflineRegistry = TOfflineRegistry<>;

namespace OfflineUserProfiles
{
    // Local and domain accounts, and Microsoft Entra ID accounts.
    const std::vector<std::string> USER_SID_PREFIXES {"S-1-5-21-", "S-1-12-1-"};

    /*
     * Whether a ProfileList entry is a user profile whose hives have to be read from disk: a user
     * account, not loaded under HKEY_USERS. Profiles of service accounts are loaded by Windows without
     * a logon, and a ".bak" suffix marks the backup entry of a profile that failed to load.
     */
    inline bool isOfflineUserProfile(const std::string& sid, const std::set<std::string>& loadedUsers)
    {
        const auto isUserSid {std::any_of(USER_SID_PREFIXES.begin(), USER_SID_PREFIXES.end(), [&sid](const std::string & prefix)
        {
            return Utils::startsWith(sid, prefix);
        })};

        return isUserSid && sid.find('.') == std::string::npos && loadedUsers.find(sid) == loadedUsers.end();
    }
}

#endif // _OFFLINE_REGISTRY_WINDOWS_H
