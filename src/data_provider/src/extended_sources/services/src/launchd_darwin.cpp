/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "launchd_darwin.hpp"
#include <CoreFoundation/CoreFoundation.h>
#include <fstream>
#include <sstream>
#include <pwd.h>

#include <filesystem_wrapper.hpp>

LaunchdProvider::LaunchdProvider(std::unique_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper) : std::make_unique<file_system::FileSystemWrapper>())
{
}

static bool cfStringToStd(CFStringRef value, std::string& out)
{
    const CFIndex length = CFStringGetLength(value);
    const CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;

    if (maxSize <= 0)
    {
        return false;
    }

    std::vector<char> buffer(maxSize);

    if (!CFStringGetCString(value, buffer.data(), maxSize, kCFStringEncodingUTF8))
    {
        return false;
    }

    out.assign(buffer.data());
    return true;
}

/// Reads a plist file and returns its root dictionary, or nullptr if it cannot be read or is not
/// a dictionary. The caller owns the result and must CFRelease it.
static CFDictionaryRef readPlistDictionary(const std::string& path)
{
    CFURLRef fileURL = CFURLCreateFromFileSystemRepresentation(
                           kCFAllocatorDefault,
                           reinterpret_cast<const UInt8*>(path.c_str()),
                           path.length(),
                           false
                       );

    if (!fileURL)
    {
        return nullptr;
    }

    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    CFRelease(fileURL);

    if (!stream)
    {
        return nullptr;
    }

    if (!CFReadStreamOpen(stream))
    {
        CFRelease(stream);
        return nullptr;
    }

    CFPropertyListRef plist = CFPropertyListCreateWithStream(
                                  kCFAllocatorDefault,
                                  stream,
                                  0,
                                  kCFPropertyListImmutable,
                                  nullptr,
                                  nullptr
                              );

    CFReadStreamClose(stream);
    CFRelease(stream);

    if (!plist)
    {
        return nullptr;
    }

    if (CFGetTypeID(plist) != CFDictionaryGetTypeID())
    {
        CFRelease(plist);
        return nullptr;
    }

    return static_cast<CFDictionaryRef>(plist);
}

void LaunchdProvider::loadDisabledOverrides()
{
    m_disabledOverrides.clear();

    std::vector<std::string> overrideFiles;

    try
    {
        if (!m_fileSystemWrapper->is_directory(m_launchdOverridesPath))
        {
            return;
        }

        for (const auto& entry : m_fileSystemWrapper->list_directory(m_launchdOverridesPath))
        {
            const auto name = std::filesystem::path(entry).filename().string();

            // "disabled.plist" for the system domain, "disabled.<uid>.plist" per user domain.
            if (name.rfind("disabled", 0) == 0 && std::filesystem::path(name).extension() == ".plist")
            {
                overrideFiles.push_back(std::filesystem::path(m_launchdOverridesPath) / name);
            }
        }
    }
    catch (...)
    {
        return;
    }

    for (const auto& file : overrideFiles)
    {
        CFDictionaryRef dict = readPlistDictionary(file);

        if (!dict)
        {
            continue;
        }

        const CFIndex count = CFDictionaryGetCount(dict);

        if (count > 0)
        {
            std::vector<const void*> keys(count);
            std::vector<const void*> values(count);
            CFDictionaryGetKeysAndValues(dict, keys.data(), values.data());

            for (CFIndex i = 0; i < count; ++i)
            {
                if (!keys[i] || !values[i] ||
                        CFGetTypeID(static_cast<CFTypeRef>(keys[i])) != CFStringGetTypeID() ||
                        CFGetTypeID(static_cast<CFTypeRef>(values[i])) != CFBooleanGetTypeID())
                {
                    continue;
                }

                std::string label;

                if (!cfStringToStd(static_cast<CFStringRef>(keys[i]), label) || label.empty())
                {
                    continue;
                }

                const bool disabled = CFBooleanGetValue(static_cast<CFBooleanRef>(values[i]));

                // A label may appear in more than one domain. Any domain that disables it wins,
                // since a single row cannot express a per-domain state.
                auto it = m_disabledOverrides.find(label);

                if (it == m_disabledOverrides.end())
                {
                    m_disabledOverrides.emplace(label, disabled);
                }
                else if (disabled)
                {
                    it->second = true;
                }
            }
        }

        CFRelease(dict);
    }
}

nlohmann::json LaunchdProvider::collect()
{
    nlohmann::json result = nlohmann::json::array();

    loadDisabledOverrides();

    std::vector<std::string> launchers;
    getLauncherPaths(launchers);

    for (const auto& path : launchers)
    {
        try
        {
            if (!m_fileSystemWrapper->is_regular_file(path))
            {
                continue;
            }

            LaunchdService service;

            if (parsePlistFile(path, service))
            {
                // launchctl enable/disable records the state in the override database rather
                // than in the job plist, so it is authoritative over whatever the plist says.
                if (!service.label.empty())
                {
                    const auto overrideEntry = m_disabledOverrides.find(service.label);

                    if (overrideEntry != m_disabledOverrides.end())
                    {
                        service.disabled = overrideEntry->second ? "true" : "false";
                    }
                }

                nlohmann::json serviceJson;
                serviceJson["path"] = service.path;
                serviceJson["name"] = service.name;
                serviceJson["label"] = service.label;
                serviceJson["run_at_load"] = service.runAtLoad;
                serviceJson["keep_alive"] = service.keepAlive;
                serviceJson["stdout_path"] = service.stdoutPath;
                serviceJson["stderr_path"] = service.stderrPath;
                serviceJson["inetd_compatibility"] = service.inetdCompatibility;
                serviceJson["start_interval"] = service.startInterval;
                serviceJson["program"] = service.program;
                serviceJson["start_on_mount"] = service.startOnMount;
                serviceJson["on_demand"] = service.onDemand;
                serviceJson["disabled"] = service.disabled;
                serviceJson["username"] = service.username;
                serviceJson["groupname"] = service.groupname;
                serviceJson["root_directory"] = service.rootDirectory;
                serviceJson["working_directory"] = service.workingDirectory;
                serviceJson["process_type"] = service.processType;
                serviceJson["program_arguments"] = service.programArguments;
                serviceJson["watch_paths"] = service.watchPaths;
                serviceJson["queue_directories"] = service.queueDirectories;

                result.push_back(serviceJson);
            }
        }
        catch (...)
        {
            // Skip files we can't access
            continue;
        }
    }

    return result;
}

void LaunchdProvider::getLauncherPaths(std::vector<std::string>& launchers)
{
    // Search standard launchd paths
    for (const auto& searchPath : m_launchdSearchPaths)
    {
        try
        {
            if (m_fileSystemWrapper->is_directory(searchPath))
            {
                auto entries = m_fileSystemWrapper->list_directory(searchPath);

                for (const auto& entry : entries)
                {
                    std::filesystem::path fullPath = std::filesystem::path(searchPath) / entry;

                    try
                    {
                        if (m_fileSystemWrapper->is_regular_file(fullPath) && std::filesystem::path(fullPath).extension() == ".plist")
                        {
                            launchers.push_back(fullPath);
                        }
                    }
                    catch (...)
                    {
                        // Skip files we can't access
                        continue;
                    }
                }
            }
        }
        catch (...)
        {
            // Skip directories we can't access
            continue;
        }
    }

    // Search user-specific paths
    // Get all home directories
    setpwent();

    try
    {
        struct passwd* pw;

        while ((pw = getpwent()) != nullptr)
        {
            if (pw->pw_dir != nullptr)
            {
                std::string homeDir(pw->pw_dir);

                for (const auto& path : m_userLaunchdSearchPaths)
                {
                    std::string userPath = homeDir;

                    if (!userPath.empty() && userPath.back() != '/')
                    {
                        userPath += '/';
                    }

                    userPath += path;

                    try
                    {
                        if (m_fileSystemWrapper->is_directory(userPath))
                        {
                            auto entries = m_fileSystemWrapper->list_directory(userPath);

                            for (const auto& entry : entries)
                            {
                                std::filesystem::path fullPath = std::filesystem::path(userPath) / entry;

                                try
                                {
                                    if (m_fileSystemWrapper->is_regular_file(fullPath) && std::filesystem::path(fullPath).extension() == ".plist")
                                    {
                                        launchers.push_back(fullPath);
                                    }
                                }
                                catch (...)
                                {
                                    // Skip files we can't access
                                    continue;
                                }
                            }
                        }
                    }
                    catch (...)
                    {
                        // Skip directories we can't access
                        continue;
                    }
                }
            }
        }
    }
    catch (...)
    {
        endpwent();
        throw;
    }

    endpwent();
}

bool LaunchdProvider::parsePlistFile(const std::string& path, LaunchdService& service)
{
    service.path = path;
    service.name = std::filesystem::path(path).filename().string();

    CFDictionaryRef dict = readPlistDictionary(path);

    if (!dict)
    {
        return false;
    }


    // Extract string values
    for (const auto& keyPair : m_launchdTopLevelStringKeys)
    {
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, keyPair.first.c_str(), kCFStringEncodingUTF8);

        if (key)
        {
            CFTypeRef value = CFDictionaryGetValue(dict, key);

            if (value)
            {
                if (CFGetTypeID(value) == CFStringGetTypeID())
                {
                    std::string stringVal;

                    if (cfStringToStd(static_cast<CFStringRef>(value), stringVal))
                    {
                        if (keyPair.second == "label") service.label = stringVal;
                        else if (keyPair.second == "run_at_load") service.runAtLoad = stringVal;
                        else if (keyPair.second == "keep_alive") service.keepAlive = stringVal;
                        else if (keyPair.second == "stdout_path") service.stdoutPath = stringVal;
                        else if (keyPair.second == "stderr_path") service.stderrPath = stringVal;
                        else if (keyPair.second == "inetd_compatibility") service.inetdCompatibility = stringVal;
                        else if (keyPair.second == "start_interval") service.startInterval = stringVal;
                        else if (keyPair.second == "program") service.program = stringVal;
                        else if (keyPair.second == "start_on_mount") service.startOnMount = stringVal;
                        else if (keyPair.second == "on_demand") service.onDemand = stringVal;
                        else if (keyPair.second == "disabled") service.disabled = stringVal;
                        else if (keyPair.second == "username") service.username = stringVal;
                        else if (keyPair.second == "groupname") service.groupname = stringVal;
                        else if (keyPair.second == "root_directory") service.rootDirectory = stringVal;
                        else if (keyPair.second == "working_directory") service.workingDirectory = stringVal;
                        else if (keyPair.second == "process_type") service.processType = stringVal;
                    }
                }
                else if (CFGetTypeID(value) == CFBooleanGetTypeID())
                {
                    CFBooleanRef boolValue = static_cast<CFBooleanRef>(value);
                    std::string stringVal = CFBooleanGetValue(boolValue) ? "true" : "false";

                    if (keyPair.second == "run_at_load") service.runAtLoad = stringVal;
                    else if (keyPair.second == "keep_alive") service.keepAlive = stringVal;
                    else if (keyPair.second == "start_on_mount") service.startOnMount = stringVal;
                    else if (keyPair.second == "on_demand") service.onDemand = stringVal;
                    else if (keyPair.second == "disabled") service.disabled = stringVal;
                }
                else if (CFGetTypeID(value) == CFNumberGetTypeID())
                {
                    CFNumberRef numberValue = static_cast<CFNumberRef>(value);
                    long long intValue;

                    if (CFNumberGetValue(numberValue, kCFNumberLongLongType, &intValue))
                    {
                        std::string stringVal = std::to_string(intValue);

                        // A plist may spell any of these as a number instead of a boolean.
                        if (keyPair.second == "start_interval") service.startInterval = stringVal;
                        else if (keyPair.second == "run_at_load") service.runAtLoad = stringVal;
                        else if (keyPair.second == "keep_alive") service.keepAlive = stringVal;
                        else if (keyPair.second == "start_on_mount") service.startOnMount = stringVal;
                        else if (keyPair.second == "on_demand") service.onDemand = stringVal;
                        else if (keyPair.second == "disabled") service.disabled = stringVal;
                    }
                }
                else if (CFGetTypeID(value) == CFDictionaryGetTypeID())
                {
                    // inetdCompatibility is declared as a dictionary, so its mere presence marks
                    // the job as inetd compatible.
                    if (keyPair.second == "inetd_compatibility") service.inetdCompatibility = "true";
                    // Disabled may hold a feature flag conditional that cannot be evaluated here.
                    // Flag it so it is not mistaken for an absent key, which means enabled.
                    else if (keyPair.second == "disabled") service.disabled = LAUNCHD_UNEVALUATED_VALUE;
                }
            }

            CFRelease(key);
        }
    }

    // Extract array values
    for (const auto& keyPair : m_launchdTopLevelArrayKeys)
    {
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, keyPair.first.c_str(), kCFStringEncodingUTF8);

        if (key)
        {
            CFTypeRef value = CFDictionaryGetValue(dict, key);

            if (value && CFGetTypeID(value) == CFArrayGetTypeID())
            {
                CFArrayRef arrayValue = static_cast<CFArrayRef>(value);
                CFIndex count = CFArrayGetCount(arrayValue);
                std::vector<std::string> elements;

                for (CFIndex i = 0; i < count; ++i)
                {
                    CFTypeRef element = CFArrayGetValueAtIndex(arrayValue, i);

                    if (element && CFGetTypeID(element) == CFStringGetTypeID())
                    {
                        std::string elementVal;

                        if (cfStringToStd(static_cast<CFStringRef>(element), elementVal))
                        {
                            elements.push_back(std::move(elementVal));
                        }
                    }
                }

                std::string joinedValue = joinArrayElements(elements);

                if (keyPair.second == "program_arguments")
                {
                    service.programArguments = joinedValue;

                    // A job may declare its executable either in Program or as the first element of
                    // ProgramArguments. Fall back to the latter, which is the more common form.
                    if (service.program.empty() && !elements.empty())
                    {
                        service.program = elements.front();
                    }
                }
                else if (keyPair.second == "watch_paths") service.watchPaths = joinedValue;
                else if (keyPair.second == "queue_directories") service.queueDirectories = joinedValue;
            }

            CFRelease(key);
        }
    }

    CFRelease(dict);
    return true;
}

std::string LaunchdProvider::joinArrayElements(const std::vector<std::string>& arrayElements)
{
    if (arrayElements.empty())
    {
        return "";
    }

    std::ostringstream oss;

    for (size_t i = 0; i < arrayElements.size(); ++i)
    {
        if (i > 0)
        {
            oss << " ";
        }

        oss << arrayElements[i];
    }

    return oss.str();
}
