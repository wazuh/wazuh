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
#include "filesystemHelper.h"

LaunchdProvider::LaunchdProvider()
{
}

nlohmann::json LaunchdProvider::collect()
{
    nlohmann::json result = nlohmann::json::array();

    std::vector<std::string> launchers;
    getLauncherPaths(launchers);

    for (const auto& path : launchers)
    {
        if (!Utils::existsRegular(path))
        {
            continue;
        }

        LaunchdService service;

        if (parsePlistFile(path, service))
        {
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

    return result;
}

void LaunchdProvider::getLauncherPaths(std::vector<std::string>& launchers)
{
    // Search standard launchd paths
    for (const auto& searchPath : m_launchdSearchPaths)
    {
        if (Utils::existsDir(searchPath))
        {
            try
            {
                std::vector<std::string> entries = Utils::enumerateDir(searchPath);

                for (const auto& entry : entries)
                {
                    std::string fullPath = searchPath + "/" + entry;

                    if (Utils::existsRegular(fullPath) && fullPath.substr(fullPath.length() - 6) == ".plist")
                    {
                        launchers.push_back(fullPath);
                    }
                }
            }
            catch (...)
            {
                // Skip directories we can't read
                continue;
            }
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

                    if (Utils::existsDir(userPath))
                    {
                        try
                        {
                            std::vector<std::string> entries = Utils::enumerateDir(userPath);

                            for (const auto& entry : entries)
                            {
                                std::string fullPath = userPath + "/" + entry;

                                if (Utils::existsRegular(fullPath) && fullPath.substr(fullPath.length() - 6) == ".plist")
                                {
                                    launchers.push_back(fullPath);
                                }
                            }
                        }
                        catch (...)
                        {
                            // Skip directories we can't read
                            continue;
                        }
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
    service.name = Utils::getFilename(path);

    // Read the plist file
    CFURLRef fileURL = CFURLCreateFromFileSystemRepresentation(
                           kCFAllocatorDefault,
                           reinterpret_cast<const UInt8*>(path.c_str()),
                           path.length(),
                           false
                       );

    if (!fileURL)
    {
        return false;
    }

    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    CFRelease(fileURL);

    if (!stream)
    {
        return false;
    }

    if (!CFReadStreamOpen(stream))
    {
        CFRelease(stream);
        return false;
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
        return false;
    }

    if (CFGetTypeID(plist) != CFDictionaryGetTypeID())
    {
        CFRelease(plist);
        return false;
    }

    CFDictionaryRef dict = static_cast<CFDictionaryRef>(plist);

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
                    CFStringRef stringValue = static_cast<CFStringRef>(value);
                    CFIndex length = CFStringGetLength(stringValue);
                    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;

                    // Validate maxSize to prevent buffer allocation issues
                    if (maxSize <= 0 || maxSize == kCFNotFound + 1)
                    {
                        CFRelease(key);
                        continue;
                    }

                    std::vector<char> buffer(maxSize);

                    if (CFStringGetCString(stringValue, buffer.data(), maxSize, kCFStringEncodingUTF8))
                    {
                        std::string stringVal(buffer.data());

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

                        if (keyPair.second == "start_interval") service.startInterval = stringVal;
                    }
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
                        CFStringRef stringElement = static_cast<CFStringRef>(element);
                        CFIndex length = CFStringGetLength(stringElement);
                        CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;

                        // Validate maxSize to prevent buffer allocation issues
                        if (maxSize <= 0 || maxSize == kCFNotFound + 1)
                        {
                            continue;
                        }

                        std::vector<char> buffer(maxSize);

                        if (CFStringGetCString(stringElement, buffer.data(), maxSize, kCFStringEncodingUTF8))
                        {
                            elements.push_back(std::string(buffer.data()));
                        }
                    }
                }

                std::string joinedValue = joinArrayElements(elements);

                if (keyPair.second == "program_arguments") service.programArguments = joinedValue;
                else if (keyPair.second == "watch_paths") service.watchPaths = joinedValue;
                else if (keyPair.second == "queue_directories") service.queueDirectories = joinedValue;
            }

            CFRelease(key);
        }
    }

    CFRelease(plist);
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
