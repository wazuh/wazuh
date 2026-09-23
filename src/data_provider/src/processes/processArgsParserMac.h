/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_ARGS_PARSER_MAC_H
#define _PROCESS_ARGS_PARSER_MAC_H

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

struct ProcessArgs
{
    std::string executablePath;
    std::vector<std::string> argv;
};

// Parses the buffer returned by sysctl({CTL_KERN, KERN_PROCARGS2, pid}), laid out as:
//   int argc | exec path '\0' | '\0' padding to pointer alignment | argv[0] '\0' ... argv[argc - 1] '\0' | envp ...
// Only argc strings are read so the environment that follows argv is never collected.
// Returns false if the buffer is too small or malformed.
static inline bool parseProcArgs2(const char* buffer, const size_t size, ProcessArgs& result)
{
    result = {};

    int argc {};

    if (!buffer || size < sizeof(argc))
    {
        return false;
    }

    std::memcpy(&argc, buffer, sizeof(argc));

    if (argc < 0)
    {
        return false;
    }

    const char* current {buffer + sizeof(argc)};
    const char* const end {buffer + size};

    const char* const pathEnd {std::find(current, end, '\0')};

    if (pathEnd == end)
    {
        return false;
    }

    result.executablePath.assign(current, pathEnd);

    // The kernel pads the path with NULs only up to the next pointer-aligned offset, so any
    // NUL past that boundary is an empty argument (e.g. an empty argv[0]), not padding.
    constexpr size_t PTR_SIZE {sizeof(void*)};
    const size_t pathSize {static_cast<size_t>(pathEnd - current) + 1};
    const size_t alignedPathSize {(pathSize + PTR_SIZE - 1) & ~(PTR_SIZE - 1)};
    current += std::min(alignedPathSize, static_cast<size_t>(end - current));

    while (static_cast<int>(result.argv.size()) < argc && current < end)
    {
        const char* const argEnd {std::find(current, end, '\0')};
        result.argv.emplace_back(current, argEnd);
        current = argEnd == end ? end : argEnd + 1;
    }

    return true;
}

struct ProcessCommandLine
{
    std::string commandLine;
    std::string args;
    unsigned int argsCount {0};
};

// Builds the inventory fields from the executable path and the parsed arguments.
// commandLine is the full invocation (executable path followed by its arguments),
// args holds the non-empty arguments after argv[0] joined with spaces.
// If executablePath is empty, the path found in the argument area is used instead.
static inline ProcessCommandLine buildProcessCommandLine(const std::string& executablePath, const ProcessArgs& processArgs)
{
    ProcessCommandLine result;
    result.commandLine = executablePath.empty() ? processArgs.executablePath : executablePath;

    // argv[0] is the program name, the same as the executable path.
    for (size_t idx = 1; idx < processArgs.argv.size(); ++idx)
    {
        if (!processArgs.argv[idx].empty())
        {
            if (result.argsCount > 0)
            {
                result.args += " ";
            }

            result.args += processArgs.argv[idx];
            result.argsCount++;
        }
    }

    if (!result.args.empty())
    {
        result.commandLine += result.commandLine.empty() ? result.args : " " + result.args;
    }

    return result;
}

#endif // _PROCESS_ARGS_PARSER_MAC_H
