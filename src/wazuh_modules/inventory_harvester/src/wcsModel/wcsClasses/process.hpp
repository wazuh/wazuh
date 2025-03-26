/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESSES_WCS_MODEL_HPP
#define _PROCESSES_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>
#include <vector>

struct Process final
{
    struct Parent final
    {
        std::int64_t pid = DEFAULT_INT_VALUE;

        REFLECTABLE(MAKE_FIELD("pid", &Parent::pid));
    };

    std::vector<std::string_view> args;
    std::string_view command_line;
    std::string_view executable;
    std::string_view name;
    std::int64_t pid = DEFAULT_INT_VALUE;
    std::string_view start;
    Parent parent;

    REFLECTABLE(MAKE_FIELD("args", &Process::args),
                MAKE_FIELD("command_line", &Process::command_line),
                MAKE_FIELD("executable", &Process::executable),
                MAKE_FIELD("name", &Process::name),
                MAKE_FIELD("pid", &Process::pid),
                MAKE_FIELD("start", &Process::start),
                MAKE_FIELD("parent", &Process::parent));
};

#endif // _PROCESSES_WCS_MODEL_HPP
