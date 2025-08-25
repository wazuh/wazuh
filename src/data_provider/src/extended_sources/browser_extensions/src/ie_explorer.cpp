#include "ie_explorer.hpp"
#include <iostream>
#include <string>
#include <algorithm>

std::string IEExtensionsProvider::getValueFromHKey(HKEY hKey){
    // If no subKeys, then get the value name
    char valueName[256];
    DWORD valueNameSize;
    DWORD valueType;
    BYTE data[1024];
    DWORD dataSize;

    // Enumerate all values in the key
    valueNameSize = sizeof(valueName);
    dataSize = sizeof(data);

    LONG valResult = RegEnumValueA(
        hKey,
        0,
        valueName,
        &valueNameSize,
        nullptr,
        &valueType,
        data,
        &dataSize
    );

    if (valResult == ERROR_SUCCESS) {
        return std::string(valueName);
    } else if (valResult == ERROR_NO_MORE_ITEMS) {
        return "";
    } else {
        std::cerr << "Failed to enumerate values. Error: " << valResult << std::endl;
        return "";
    }
}

std::string IEExtensionsProvider::getDefaultValueFromHKey(HKEY hKey) {
    DWORD dataSize = 1024;
    BYTE data[1024];
    DWORD valueType;
    
    // Query the default value by passing empty string as value name
    LONG result = RegQueryValueExA(
        hKey,
        "",          // Empty string for default value
        nullptr,     // Reserved
        &valueType,  // Type of data
        data,        // Data buffer
        &dataSize    // Size of data
    );
    
    if (result == ERROR_SUCCESS && valueType == REG_SZ) {
        return std::string(reinterpret_cast<char*>(data));
    }
    return "";
}

HKEY IEExtensionsProvider::getHKeyFromKeyString(HKEY hive, const std::string& key){
    HKEY hKey;
    if (RegOpenKeyExA(hive, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
        return hKey;
    } else {
        return nullptr;
    }
}

std::string IEExtensionsProvider::getSubKeyNameFromHKey(HKEY hKey){
    char keyName[256];
    DWORD keyNameSize = sizeof(keyName);
    FILETIME lastWriteTime;

    keyNameSize = sizeof(keyName); // Reset for each call
    LONG result = RegEnumKeyExA(
        hKey,
        0,
        keyName,
        &keyNameSize,
        nullptr,
        nullptr,
        nullptr,
        &lastWriteTime);

    if (result == ERROR_SUCCESS)
    {
        return keyName;
    }
    if (result == ERROR_NO_MORE_ITEMS) {
        return "";
    }
    else
    {
        std::cerr << "Failed to enumerate subkeys. Error: " << result << std::endl;
        return "";
    }
}

std::string IEExtensionsProvider::HKeyToString(HKEY hKey) {
    if (hKey == HKEY_CLASSES_ROOT) return "HKEY_CLASSES_ROOT";
    if (hKey == HKEY_CURRENT_USER) return "HKEY_CURRENT_USER";
    if (hKey == HKEY_LOCAL_MACHINE) return "HKEY_LOCAL_MACHINE";
    if (hKey == HKEY_USERS) return "HKEY_USERS";
    if (hKey == HKEY_CURRENT_CONFIG) return "HKEY_CURRENT_CONFIG";
    if (hKey == HKEY_PERFORMANCE_DATA) return "HKEY_PERFORMANCE_DATA";
    if (hKey == HKEY_DYN_DATA) return "HKEY_DYN_DATA"; // legacy, 9x
    return "UNKNOWN_HKEY";
}


void IEExtensionsProvider::getRegistryPathsFromKeys(HKEY hive, const std::vector<std::string> clsidKeys, std::vector<std::string>& regPaths){
    for(auto& subKey : clsidKeys){
        HKEY hKey = getHKeyFromKeyString(hive, subKey);
        // Open the registry key
        if (hKey != nullptr)
        {
            std::string clsid;
            std::string subKeyName = getSubKeyNameFromHKey(hKey);
            if(subKeyName == "") {
                clsid = getValueFromHKey(hKey);
            } else {
                clsid = subKeyName;
            }

            std::string registryPath = HKeyToString(hive) + kRegSep + subKey + kRegSep + clsid;
            if (std::find(regPaths.begin(), regPaths.end(), registryPath) == regPaths.end()) {
                regPaths.push_back(registryPath);  // Insert only if not already present
            }

            // Close the key
            RegCloseKey(hKey);
        }
    }
}

std::vector<std::string> IEExtensionsProvider::listSubKeys(HKEY hive) {
    std::vector<std::string> subKeys;

    DWORD index = 0;
    char subKey[256];
    DWORD subKeySize = sizeof(subKey);
    FILETIME ft;

    // Enumerate all SIDs under hive
    while (RegEnumKeyExA(hive, index, subKey, &subKeySize, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
        subKeys.emplace_back(std::string(subKey));
        index++;
        subKeySize = sizeof(subKey); // Reset buffer size for next item
    }

    return subKeys;
}

std::vector<std::string> IEExtensionsProvider::expandUserKey(const std::string key) {
    std::vector<std::string> expandedKeys;
    for(const auto& prefix : listSubKeys(HKEY_USERS)){
        expandedKeys.emplace_back(prefix + kRegSep + key);
    }
    return expandedKeys;
}

std::vector<std::string> IEExtensionsProvider::expandUserKeys(const std::vector<std::string>& keys) {
    std::vector<std::string> expandedKeys;
        
    for(const auto& key : keys){
        std::vector<std::string> result = expandUserKey(key);
        expandedKeys.insert(expandedKeys.end(), result.begin(), result.end());
    }

    return expandedKeys;
}

std::vector<std::string> IEExtensionsProvider::getRegistryPaths(){
    std::vector<std::string> regPaths;
    std::vector<std::string> expandedUserKeys = expandUserKeys(CLSIDS_KEYS);

    getRegistryPathsFromKeys(HKEY_LOCAL_MACHINE, CLSIDS_KEYS, regPaths);
    getRegistryPathsFromKeys(HKEY_USERS, expandedUserKeys, regPaths);

    return regPaths;
}

void IEExtensionsProvider::getExecutablesFromKey(HKEY hive, const std::string& registryPath, std::vector<std::string>& executables){
    HKEY hKey = getHKeyFromKeyString(hive, registryPath);
    if(hKey != nullptr) {
        std::string executable = getDefaultValueFromHKey(hKey);
        RegCloseKey(hKey);
        if(executable != ""){
            executables.emplace_back(executable);
        }
    }
}

std::string IEExtensionsProvider::extractClsid(const std::string& regPath) {
    size_t pos = regPath.find_last_of("\\");
    if (pos == std::string::npos) {
        return regPath; // no backslash found, return whole string
    }
    return regPath.substr(pos + 1);
}

std::vector<std::string> IEExtensionsProvider::getExecutables(const std::string& registryPath){
    std::vector<std::string> executables;
    std::vector<std::string> expandedUserKeys = expandUserKey(EXECUTABLES_BASE_KEY);
    std::string clsid = extractClsid(registryPath);
    for(const auto& subKey : kClassExecSubKeys){
        getExecutablesFromKey(HKEY_LOCAL_MACHINE, EXECUTABLES_BASE_KEY + kRegSep + clsid + kRegSep + subKey, executables);
        for(const auto& userKey : expandedUserKeys){
            getExecutablesFromKey(HKEY_USERS, userKey + kRegSep + clsid + kRegSep + subKey, executables);
        }
    }

    return executables;
}

std::string IEExtensionsProvider::GetFileVersion(const std::string& filePath)
{
    // Convert std::string (UTF-8/ANSI) to std::wstring (UTF-16)
    std::wstring wFilePath(filePath.begin(), filePath.end());

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(wFilePath.c_str(), &handle);
    if (size == 0)
        return "No version info";

    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoW(wFilePath.c_str(), handle, size, buffer.data()))
        return "Failed to get version info";

    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &len))
        return "Failed to query version value";

    if (fileInfo)
    {
        DWORD major = HIWORD(fileInfo->dwFileVersionMS);
        DWORD minor = LOWORD(fileInfo->dwFileVersionMS);
        DWORD build = HIWORD(fileInfo->dwFileVersionLS);
        DWORD revision = LOWORD(fileInfo->dwFileVersionLS);

        char verStr[64];
        sprintf_s(verStr, "%u.%u.%u.%u", major, minor, build, revision);
        return std::string(verStr);
    }

    return "Unknown version";
}

std::string IEExtensionsProvider::getExecutableName(const std::string& registryPath){
    std::string clsid = extractClsid(registryPath);
    std::string keyPath = "CLSID" + kRegSep + clsid;
    HKEY hKey = getHKeyFromKeyString(HKEY_CLASSES_ROOT, keyPath);
    std::string execName = ""; // Default value
    if(hKey != nullptr) {
        execName = getDefaultValueFromHKey(hKey);
        RegCloseKey(hKey);
    }
    return execName;
}

IEExtensionsProvider::IEExtensionsProvider() {}

nlohmann::json IEExtensionsProvider::collect() {
		nlohmann::json jExtensions = nlohmann::json::array();
		std::vector<std::string> regPaths = getRegistryPaths();

		for(const auto& registryPath : regPaths){
				std::vector<std::string> executables = getExecutables(registryPath);

				for(const auto& exec: executables){
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
