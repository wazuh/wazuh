/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "argsParser.hpp"
#include "homedirHelper.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include <filesystem>
#include <fstream>
#include <functional>
#include <grp.h>
#include <pwd.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
constexpr auto RUNTIME_USER = "wazuh-manager";
constexpr auto RUNTIME_GROUP = "wazuh-manager";

void dropPrivilegesIfAvailable()
{
    if (geteuid() != 0)
    {
        return;
    }

    const auto* user = getpwnam(RUNTIME_USER);
    if (user == nullptr)
    {
        // Standalone build-tree QA environments do not install runtime accounts.
        return;
    }
    const uid_t uid = user->pw_uid;

    const auto* group = getgrnam(RUNTIME_GROUP);
    if (group == nullptr)
    {
        return;
    }
    const gid_t gid = group->gr_gid;
    if (initgroups(RUNTIME_USER, gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
    {
        throw std::runtime_error {"Cannot drop privileges to wazuh-manager."};
    }

    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid)
    {
        throw std::runtime_error {"Cannot verify wazuh-manager identity."};
    }

    umask(0007);
}
} // namespace

int main(int argc, char* argv[])
{
    std::string family;
    std::string key;
    std::string value;
    std::string valuePath;

    Log::assignLogFunction(
        [](const int logLevel, const char*, const char*, const int, const char*, const char* str, va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str, args);

            if (logLevel == Log::LOGLEVEL_ERROR || logLevel == Log::LOGLEVEL_CRITICAL ||
                logLevel == Log::LOGLEVEL_WARNING)
            {
                std::cerr << formattedStr << "\n";
            }
            else
            {
                std::cout << formattedStr << "\n";
            }
        });
    Log::setModuleLogFn(LogFn {"wazuh-keystore"});

    try
    {
        // Define current working directory
        std::filesystem::path home_path = Utils::findHomeDirectory();
        std::filesystem::current_path(home_path);

        CmdLineArgs args(argc, argv);

        family = args.getColumnFamily();
        key = args.getKey();
        value = args.getValue();
        valuePath = args.getValuePath();

        std::string secret;
        if (value.empty() && valuePath.empty())
        {
            std::getline(std::cin, secret);

            if (secret.empty())
            {
                throw CmdLineArgsException("Error reading from stdin.");
            }
        }
        else if (!value.empty() && valuePath.empty())
        {
            secret = value;
        }
        else if (!valuePath.empty() && value.empty())
        {
            std::ifstream file(valuePath);
            if (!file.is_open())
            {
                throw CmdLineArgsException("Error opening file.");
            }

            if (!std::getline(file, secret))
            {
                throw CmdLineArgsException("Error reading file.");
            }
        }
        else
        {
            throw CmdLineArgsException("Invalid arguments.");
        }

        dropPrivilegesIfAvailable();
        Keystore::put(family, key, secret);
    }
    catch (const CmdLineArgsException& e)
    {
        std::cerr << e.what() << "\n";
        CmdLineArgs::showHelp();
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
