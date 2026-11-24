/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_ARGS_H
#define _PROCESS_ARGS_H

#include <string>
#include <vector>
#include "json.hpp"

namespace ProcessArgs
{
    // Collects the arguments that follow argv[0] in a NULL-terminated argv array, skipping
    // empty ones so the list matches args_count on every platform.
    inline std::vector<std::string> fromArgv(const char* const* argv)
    {
        std::vector<std::string> args;

        if (argv && argv[0])
        {
            for (auto idx = 1; argv[idx]; ++idx)
            {
                if (argv[idx][0] != '\0')
                {
                    args.emplace_back(argv[idx]);
                }
            }
        }

        return args;
    }

    // Encodes the arguments as a JSON array string. The dbsync column is TEXT, which only holds
    // strings, and joining the arguments with any separator loses the boundary of an argument
    // that contains that separator. An empty list is stored as "" so the field reaches the
    // document as null.
    inline std::string encode(const std::vector<std::string>& args)
    {
        if (args.empty())
        {
            return "";
        }

        // Replace rather than throw on invalid UTF-8, so one malformed argument cannot abort the scan.
        return nlohmann::json(args).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }

    // Rebuilds a human-readable command line: the executable followed by its arguments,
    // separated by spaces.
    inline std::string commandLine(const std::string& executable, const std::vector<std::string>& args)
    {
        std::string result {executable};

        for (const auto& arg : args)
        {
            if (!result.empty())
            {
                result += ' ';
            }

            result += arg;
        }

        return result;
    }
} // namespace ProcessArgs

#endif // _PROCESS_ARGS_H
