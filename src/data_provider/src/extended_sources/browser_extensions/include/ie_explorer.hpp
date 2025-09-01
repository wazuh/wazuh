/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <iostream>
#include <vector>
#include <windows.h>
#include "json.hpp"
#include "ie_extensions_wrapper.hpp"
#include <map>

/**
 * @brief List of registry keys where Internet Explorer Browser Helper Objects (BHOs) are stored.
 */
const std::vector<std::string> CLSIDS_KEYS =
{
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    "SOFTWARE\\Microsoft\\Internet Explorer\\URLSearchHooks",
};

/**
 * @brief Base registry key for CLSID executable definitions.
 */
const std::string EXECUTABLES_BASE_KEY = "SOFTWARE\\Classes\\CLSID";

/**
 * @brief Subkeys under each CLSID that may point to an executable or library.
 */
const std::vector<std::string> CLASS_EXECUTABLES_SUBKEYS =
{
    "InProcServer",     ///< 16-bit legacy server
    "InProcServer32",   ///< 32-bit server (most common)
    "InProcServer64",   ///< 64-bit server (rare)
    "InProcHandler",    ///< 16-bit legacy handler
    "InProcHandler32",  ///< 32-bit handler (common)
    "InProcHandler64",  ///< 64-bit handler (rare)
    "LocalServer",      ///< 16-bit legacy local server
    "LocalServer32",    ///< 32-bit local server (common)
    "LocalServer64"     ///< 64-bit local server (rare)
};

const std::map<HKEY, std::string> HKEY_TO_STRING_MAP =
{
    {HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"},
    {HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"},
    {HKEY_USERS, "HKEY_USERS"},
};

/**
 * @brief Registry path separator string.
 */
const std::string SEPARATOR = "\\";

/**
 * @brief Maximum allowed path length for security validation.
 */
#define MAX_PATH_LENGTH 4096

/**
 * @class IEExtensionsProvider
 * @brief Provides functionality to enumerate Internet Explorer extensions
 *        (such as Browser Helper Objects and URL search hooks) from the Windows Registry.
 *
 * This class interacts with the Windows Registry (through an abstraction layer provided by
 * IIEExtensionsWrapper) to collect information about installed IE extensions, including their
 * CLSIDs, associated executables, and version information.
 */
class IEExtensionsProvider
{
    public:
        /**
         * @brief Construct an IEExtensionsProvider with a custom registry wrapper.
         * @param ieExtensionsWrapper Shared pointer to an implementation of IIEExtensionsWrapper.
         */
        explicit IEExtensionsProvider(std::shared_ptr<IIEExtensionsWrapper> ieExtensionsWrapper);

        /**
         * @brief Construct an IEExtensionsProvider with the default registry wrapper.
         */
        IEExtensionsProvider();

        /**
         * @brief Destructor.
         */
        ~IEExtensionsProvider() = default;

        /**
         * @brief Collect information about installed IE extensions.
         * @return JSON object containing extension data (CLSIDs, executables, versions).
         */
        nlohmann::json collect();

    private:
        /**
         * @brief Retrieve the string value stored in a registry key.
         * @param hKey Handle to the registry key.
         * @return String value read from the key, or empty string if not found.
         */
        std::string getValueFromHKey(HKEY hKey);

        /**
         * @brief Retrieve the default (unnamed) value from a registry key.
         * @param hKey Handle to the registry key.
         * @return Default value as string, or empty string if not found.
         */
        std::string getDefaultValueFromHKey(HKEY hKey);

        /**
         * @brief Open a registry key from a hive and subkey path.
         * @param hive Root hive handle (e.g., HKEY_LOCAL_MACHINE).
         * @param key Subkey path string.
         * @return Handle to the opened registry key, or nullptr on failure.
         */
        HKEY getHKeyFromKeyString(HKEY hive, const std::string& key);

        /**
         * @brief Get the name of a subkey from a registry key handle.
         * @param hKey Handle to the registry key.
         * @return Subkey name as string.
         */
        std::string getSubKeyNameFromHKey(HKEY hKey);

        /**
         * @brief Convert a registry handle to a string representation.
         * @param hKey Registry handle.
         * @return String representation of the handle.
         */
        std::string HKeyToString(HKEY hKey);

        /**
         * @brief Collect registry paths from a set of CLSID keys.
         * @param hive Root hive handle.
         * @param clsidKeys List of CLSID subkeys to enumerate.
         * @param regPaths Vector to append found registry paths.
         */
        void getRegistryPathsFromKeys(HKEY hive, const std::vector<std::string> clsidKeys, std::vector<std::string>& regPaths);

        /**
         * @brief Enumerate subkeys under a given registry hive.
         * @param hive Root hive handle.
         * @return Vector of subkey names.
         */
        std::vector<std::string> listSubKeys(HKEY hive);

        /**
         * @brief Expand a registry key that may contain user-specific paths (e.g., SIDs).
         * @param key Registry path string with possible user placeholders.
         * @return Expanded list of registry paths.
         */
        std::vector<std::string> expandUserKey(const std::string key);

        /**
         * @brief Expand multiple registry keys containing user placeholders.
         * @param keys Vector of registry paths.
         * @return Vector of expanded registry paths.
         */
        std::vector<std::string> expandUserKeys(const std::vector<std::string>& keys);

        /**
         * @brief Collect all relevant registry paths for IE extensions.
         * @return Vector of registry path strings.
         */
        std::vector<std::string> getRegistryPaths();

        /**
         * @brief Retrieve executable paths associated with a registry key.
         * @param hive Root hive handle.
         * @param registryPath Subkey path string.
         * @param executables Vector to append found executable paths.
         */
        void getExecutablesFromKey(HKEY hive, const std::string& registryPath, std::vector<std::string>& executables);

        /**
         * @brief Extract the CLSID from a registry path.
         * @param regPath Registry path string.
         * @return CLSID string.
         */
        std::string extractClsid(const std::string& regPath);

        /**
         * @brief Get executable file paths from a given registry path.
         * @param registryPath Registry path string.
         * @return Vector of executable file paths.
         */
        std::vector<std::string> getExecutables(const std::string& registryPath);

        /**
         * @brief Retrieve the file version of an executable.
         * @param filePath Path to the executable file.
         * @return File version string.
         */
        std::string GetFileVersion(const std::string& filePath);

        /**
         * @brief Extract the executable name from a registry path.
         * @param registryPath Registry path string.
         * @return Executable file name.
         */
        std::string getExecutableName(const std::string& registryPath);

        /**
         * @brief Validates path security to prevent directory traversal attacks.
         * @param path Path to validate.
         * @return true if path is safe, false otherwise.
         */
        bool isValidPath(const std::string& path);

        /**
         * @brief Wrapper used for accessing the Windows Registry.
         */
        std::shared_ptr<IIEExtensionsWrapper> m_ieExtensionsWrapper;
};
