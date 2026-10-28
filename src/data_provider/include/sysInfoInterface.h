/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_INFO_INTERFACE
#define _SYS_INFO_INTERFACE

#include <functional>
#include <string>

#include "json.hpp"

// The names a process can be matched by. comm is the kernel task name
// (/proc/<pid>/comm on Linux): it survives a process rewriting its argv[0] (nginx's
// "nginx: master process ...") and names a script rather than its interpreter
// (firewalld instead of python3). Empty where the platform has no such name.
struct ProcessNames
{
    std::string name;
    std::string commandLine;
    std::string comm;
};

class ISysInfo
{
    public:
        ISysInfo() = default;
        // LCOV_EXCL_START
        virtual ~ISysInfo() = default;
        // LCOV_EXCL_STOP
        virtual nlohmann::json hardware() = 0;
        virtual nlohmann::json packages() = 0;
        virtual nlohmann::json os() = 0;
        virtual nlohmann::json processes() = 0;
        virtual nlohmann::json networks() = 0;
        virtual nlohmann::json ports() = 0;
        virtual nlohmann::json hotfixes() = 0;
        virtual nlohmann::json groups() = 0;
        virtual nlohmann::json users() = 0;
        virtual nlohmann::json services() = 0;
        virtual nlohmann::json browserExtensions() = 0;
        virtual void packages(std::function<void(nlohmann::json&)>) = 0;
        virtual void processes(std::function<void(nlohmann::json&)>) = 0;

        // Lightweight process listing for callers that only match processes by name.
        // The default derives name and commandLine from processes() and leaves comm
        // empty; platforms whose process name can differ from comm override it.
        virtual void processNames(std::function<void(const ProcessNames&)> callback)
        {
            processes([&callback](nlohmann::json & process)
            {
                const auto stringField = [&process](const char* key)
                {
                    const auto it = process.find(key);
                    return it != process.end() && it->is_string() ? it->get<std::string>() : std::string {};
                };

                callback({stringField("name"), stringField("command_line"), {}});
            });
        }

        // Releases any per-thread resources allocated on the calling thread, on the
        // calling thread, before that thread exits. Must be called explicitly instead of
        // relying on automatic (e.g. thread_local) teardown, which is not guaranteed to
        // run correctly for a module loaded dynamically at runtime. Windows-only in
        // practice (releases hotfixes()' per-thread COM context); a no-op elsewhere.
        virtual void releaseThreadResources() = 0;
};

#endif //_SYS_INFO_INTERFACE
