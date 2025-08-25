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

const std::vector<std::string> CLSIDS_KEYS = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    "SOFTWARE\\Microsoft\\Internet Explorer\\URLSearchHooks",
};

const std::string EXECUTABLES_BASE_KEY = "SOFTWARE\\Classes\\CLSID";

const std::vector<std::string> kClassExecSubKeys = {
    "InProcServer",     // 16-bit legacy
    "InProcServer32",   // 32-bit (most common)
    "InProcServer64",   // 64-bit (rare)
    "InProcHandler",    // 16-bit legacy  
    "InProcHandler32",  // 32-bit (common)
    "InProcHandler64",  // 64-bit (rare)
    "LocalServer",      // 16-bit legacy
    "LocalServer32",    // 32-bit (common)
    "LocalServer64"     // 64-bit (rare)
};

// Registry path separator
const std::string kRegSep = "\\";

class IEExtensionsProvider {
    public:
    IEExtensionsProvider();
    ~IEExtensionsProvider() = default;
		nlohmann::json collect();
    private:
		std::string getValueFromHKey(HKEY hKey);
		std::string getDefaultValueFromHKey(HKEY hKey);
		HKEY getHKeyFromKeyString(HKEY hive, const std::string& key);
		std::string getSubKeyNameFromHKey(HKEY hKey);
		std::string HKeyToString(HKEY hKey);
		void getRegistryPathsFromKeys(HKEY hive, const std::vector<std::string> clsidKeys, std::vector<std::string>& regPaths);
		std::vector<std::string> listSubKeys(HKEY hive);
		std::vector<std::string> expandUserKey(const std::string key);
		std::vector<std::string> expandUserKeys(const std::vector<std::string>& keys);
		std::vector<std::string> getRegistryPaths();
		void getExecutablesFromKey(HKEY hive, const std::string& registryPath, std::vector<std::string>& executables);
		std::string extractClsid(const std::string& regPath);
		std::vector<std::string> getExecutables(const std::string& registryPath);
		std::string GetFileVersion(const std::string& filePath);
		std::string getExecutableName(const std::string& registryPath);
};
