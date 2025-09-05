/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ie_explorer.hpp"
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>

std::string IEExtensionsProvider::getValueFromHKey(HKEY hKey)
{
    // If no subKeys, then get the value name
    const DWORD MAX_VALUE_NAME = 16384;  // MAX_VALUE_NAME + 1
    const DWORD MAX_VALUE_DATA = 1048576; // 1MB for registry data

    std::vector<char> valueName(MAX_VALUE_NAME);
    DWORD valueNameSize;
    DWORD valueType;
    std::vector<BYTE> data(MAX_VALUE_DATA);
    DWORD dataSize;

    // Enumerate all values in the key
    valueNameSize = static_cast<DWORD>(valueName.size());
    dataSize = static_cast<DWORD>(data.size());

    LONG valResult = m_ieExtensionsWrapper->RegEnumValueAWrapper(
                         hKey,
                         0,
                         valueName.data(),
                         &valueNameSize,
                         nullptr,
                         &valueType,
                         data.data(),
                         &dataSize
                     );

    if (valResult == ERROR_SUCCESS)
    {
        // Ensure null termination and validate size
        if (valueNameSize < valueName.size())
        {
            valueName[valueNameSize] = '\0';
        }

        return std::string(valueName.data());
    }
    else if (valResult == ERROR_NO_MORE_ITEMS)
    {
        return "";
    }
    else
    {
        std::cerr << "Failed to enumerate values. Error: " << valResult << std::endl;
        return "";
    }
}

std::string IEExtensionsProvider::getDefaultValueFromHKey(HKEY hKey)
{
    const DWORD MAX_VALUE_DATA = 1048576; // 1MB for registry data
    std::vector<BYTE> data(MAX_VALUE_DATA);
    DWORD dataSize = static_cast<DWORD>(data.size());
    DWORD valueType;

    // Query the default value by passing empty string as value name
    LONG result = m_ieExtensionsWrapper->RegQueryValueExAWrapper(
                      hKey,
                      "",          // Empty string for default value
                      nullptr,     // Reserved
                      &valueType,  // Type of data
                      data.data(), // Data buffer
                      &dataSize    // Size of data
                  );

    if (result == ERROR_SUCCESS && valueType == REG_SZ)
    {
        // Ensure data size is within bounds and null-terminated
        if (dataSize > 0 && dataSize <= data.size())
        {
            // Ensure null termination
            if (dataSize < data.size())
            {
                data[dataSize] = '\0';
            }

            return std::string(reinterpret_cast<char*>(data.data()));
        }
    }

    return "";
}

HKEY IEExtensionsProvider::getHKeyFromKeyString(HKEY hive, const std::string& key)
{
    HKEY hKey;

    if (m_ieExtensionsWrapper->RegOpenKeyExAWrapper(hive, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        return hKey;
    }
    else
    {
        return nullptr;
    }
}

std::string IEExtensionsProvider::getSubKeyNameFromHKey(HKEY hKey)
{
    const DWORD MAX_KEY_NAME = 256; // Windows registry limit
    std::vector<char> keyName(MAX_KEY_NAME);
    DWORD keyNameSize = static_cast<DWORD>(keyName.size());
    FILETIME lastWriteTime;

    keyNameSize = static_cast<DWORD>(keyName.size()); // Reset for each call
    LONG result = m_ieExtensionsWrapper->RegEnumKeyExAWrapper(
                      hKey,
                      0,
                      keyName.data(),
                      &keyNameSize,
                      nullptr,
                      nullptr,
                      nullptr,
                      &lastWriteTime);

    if (result == ERROR_SUCCESS)
    {
        // Ensure null termination and validate size
        if (keyNameSize < keyName.size())
        {
            keyName[keyNameSize] = '\0';
        }

        return std::string(keyName.data());
    }

    if (result == ERROR_NO_MORE_ITEMS)
    {
        return "";
    }
    else
    {
        std::cerr << "Failed to enumerate subkeys. Error: " << result << std::endl;
        return "";
    }
}

std::string IEExtensionsProvider::HKeyToString(HKEY hKey)
{
    if (HKEY_TO_STRING_MAP.find(hKey) != HKEY_TO_STRING_MAP.end())
    {
        return HKEY_TO_STRING_MAP.at(hKey);
    }

    return "UNKNOWN_HKEY";
}


void IEExtensionsProvider::getRegistryPathsFromKeys(HKEY hive, const std::vector<std::string> clsidKeys, std::vector<std::string>& regPaths)
{
    for (auto& subKey : clsidKeys)
    {
        HKEY hKey = getHKeyFromKeyString(hive, subKey);

        // Open the registry key
        if (hKey != nullptr)
        {
            std::string clsid;
            std::string subKeyName = getSubKeyNameFromHKey(hKey);

            if (subKeyName == "")
            {
                clsid = getValueFromHKey(hKey);
            }
            else
            {
                clsid = subKeyName;
            }

            std::string registryPath = HKeyToString(hive) + SEPARATOR + subKey + SEPARATOR + clsid;

            if (std::find(regPaths.begin(), regPaths.end(), registryPath) == regPaths.end())
            {
                regPaths.push_back(registryPath);  // Insert only if not already present
            }

            // Close the key
            m_ieExtensionsWrapper->RegCloseKeyWrapper(hKey);
        }
    }
}

std::vector<std::string> IEExtensionsProvider::listSubKeys(HKEY hive)
{
    std::vector<std::string> subKeys;

    DWORD index = 0;
    const DWORD MAX_KEY_NAME = 256; // Windows registry limit
    std::vector<char> subKey(MAX_KEY_NAME);
    DWORD subKeySize = static_cast<DWORD>(subKey.size());
    FILETIME ft;

    // Enumerate all SIDs under hive
    while (m_ieExtensionsWrapper->RegEnumKeyExAWrapper(hive, index, subKey.data(), &subKeySize, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS)
    {
        // Ensure null termination and validate size
        if (subKeySize < subKey.size())
        {
            subKey[subKeySize] = '\0';
        }

        subKeys.emplace_back(std::string(subKey.data()));
        index++;
        subKeySize = static_cast<DWORD>(subKey.size()); // Reset buffer size for next item
    }

    return subKeys;
}

std::vector<std::string> IEExtensionsProvider::expandUserKey(const std::string key)
{
    std::vector<std::string> expandedKeys;

    for (const auto& prefix : listSubKeys(HKEY_USERS))
    {
        expandedKeys.emplace_back(prefix + SEPARATOR + key);
    }

    return expandedKeys;
}

std::vector<std::string> IEExtensionsProvider::expandUserKeys(const std::vector<std::string>& keys)
{
    std::vector<std::string> expandedKeys;

    for (const auto& key : keys)
    {
        std::vector<std::string> result = expandUserKey(key);
        expandedKeys.insert(expandedKeys.end(), result.begin(), result.end());
    }

    return expandedKeys;
}

std::vector<std::string> IEExtensionsProvider::getRegistryPaths()
{
    std::vector<std::string> regPaths;
    std::vector<std::string> expandedUserKeys = expandUserKeys(CLSIDS_KEYS);

    getRegistryPathsFromKeys(HKEY_LOCAL_MACHINE, CLSIDS_KEYS, regPaths);
    getRegistryPathsFromKeys(HKEY_USERS, expandedUserKeys, regPaths);

    return regPaths;
}

void IEExtensionsProvider::getExecutablesFromKey(HKEY hive, const std::string& registryPath, std::vector<std::string>& executables)
{
    HKEY hKey = getHKeyFromKeyString(hive, registryPath);

    if (hKey != nullptr)
    {
        std::string executable = getDefaultValueFromHKey(hKey);
        m_ieExtensionsWrapper->RegCloseKeyWrapper(hKey);

        if (executable != "")
        {
            executables.emplace_back(executable);
        }
    }
}

std::string IEExtensionsProvider::extractClsid(const std::string& regPath)
{
    size_t pos = regPath.find_last_of("\\");

    if (pos == std::string::npos)
    {
        return regPath; // no backslash found, return whole string
    }

    return regPath.substr(pos + 1);
}

std::vector<std::string> IEExtensionsProvider::getExecutables(const std::string& registryPath)
{
    std::vector<std::string> executables;
    std::vector<std::string> expandedUserKeys = expandUserKey(EXECUTABLES_BASE_KEY);
    std::string clsid = extractClsid(registryPath);

    for (const auto& subKey : CLASS_EXECUTABLES_SUBKEYS)
    {
        getExecutablesFromKey(HKEY_LOCAL_MACHINE, EXECUTABLES_BASE_KEY + SEPARATOR + clsid + SEPARATOR + subKey, executables);

        for (const auto& userKey : expandedUserKeys)
        {
            getExecutablesFromKey(HKEY_USERS, userKey + SEPARATOR + clsid + SEPARATOR + subKey, executables);
        }
    }

    return executables;
}

std::string IEExtensionsProvider::GetFileVersion(const std::string& filePath)
{
    // Convert std::string (UTF-8/ANSI) to std::wstring (UTF-16)
    std::wstring wFilePath(filePath.begin(), filePath.end());

    DWORD handle = 0;
    DWORD size = m_ieExtensionsWrapper->GetFileVersionInfoSizeWWrapper(wFilePath.c_str(), &handle);

    if (size == 0)
    {
        return "No version info";
    }

    std::vector<BYTE> buffer(size);

    if (!m_ieExtensionsWrapper->GetFileVersionInfoWWrapper(wFilePath.c_str(), handle, size, buffer.data()))
    {
        return "Failed to get version info";
    }

    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT len = 0;

    if (!m_ieExtensionsWrapper->VerQueryValueWWrapper(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &len))
    {
        return "Failed to query version value";
    }

    if (fileInfo)
    {
        DWORD major = HIWORD(fileInfo->dwFileVersionMS);
        DWORD minor = LOWORD(fileInfo->dwFileVersionMS);
        DWORD build = HIWORD(fileInfo->dwFileVersionLS);
        DWORD revision = LOWORD(fileInfo->dwFileVersionLS);

        const size_t MAX_VERSION_STR = 64;
        std::vector<char> verStr(MAX_VERSION_STR);
        sprintf_s(verStr.data(), verStr.size(), "%u.%u.%u.%u", major, minor, build, revision);
        return std::string(verStr.data());
    }

    return "Unknown version";
}

std::string IEExtensionsProvider::getExecutableName(const std::string& registryPath)
{
    std::string clsid = extractClsid(registryPath);
    std::string keyPath = "CLSID" + SEPARATOR + clsid;
    HKEY hKey = getHKeyFromKeyString(HKEY_CLASSES_ROOT, keyPath);
    std::string execName = ""; // Default value

    if (hKey != nullptr)
    {
        execName = getDefaultValueFromHKey(hKey);
        m_ieExtensionsWrapper->RegCloseKeyWrapper(hKey);
    }

    return execName;
}

IEExtensionsProvider::IEExtensionsProvider(std::shared_ptr<IIEExtensionsWrapper> ieExtensionsWrapper) : m_ieExtensionsWrapper(std::move(ieExtensionsWrapper)) {}

IEExtensionsProvider::IEExtensionsProvider() : m_ieExtensionsWrapper(std::make_shared<IEExtensionsWrapper>()) {}

bool IEExtensionsProvider::isValidPath(const std::string& path)
{
    if (path.empty() ||
            path.find("..") != std::string::npos ||
            path.find("//") != std::string::npos ||
            path.length() > MAX_PATH_LENGTH)
    {
        return false;
    }

    return true;
}

nlohmann::json IEExtensionsProvider::collect()
{
    nlohmann::json jExtensions = nlohmann::json::array();
    std::vector<std::string> regPaths = getRegistryPaths();

    for (const auto& registryPath : regPaths)
    {
        std::vector<std::string> executables = getExecutables(registryPath);

        for (const auto& exec : executables)
        {
            // Validate executable path for security
            if (!isValidPath(exec))
            {
                continue;
            }

            nlohmann::json jExtension;
            jExtension["name"] = getExecutableName(registryPath);
            jExtension["path"] = exec;
            jExtension["registry_path"] = registryPath;
            jExtension["version"] = GetFileVersion(exec);
            jExtensions.push_back(jExtension);
        }
    }

    return jExtensions;
}
