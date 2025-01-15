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

struct Process
{
    std::vector<std::string_view> args;
    std::uint32_t args_count;
    std::string_view command_line;
    std::string_view end;
    std::string_view entity_id;
    std::vector<std::string_view> env_vars;
    std::string_view executable;
    std::uint32_t exit_code;
    bool interactive;
    std::string_view name;
    std::uint32_t pgid;
    std::uint32_t pid;
    bool same_as_process;
    std::string_view start;
    std::string_view title;
    std::string_view working_directory;

    REFLECTABLE(MAKE_FIELD("args", &Process::args),
                MAKE_FIELD("args_count", &Process::args_count),
                MAKE_FIELD("command_line", &Process::command_line),
                MAKE_FIELD("end", &Process::end),
                MAKE_FIELD("entity_id", &Process::entity_id),
                MAKE_FIELD("env_vars", &Process::env_vars),
                MAKE_FIELD("executable", &Process::executable),
                MAKE_FIELD("exit_code", &Process::exit_code),
                MAKE_FIELD("interactive", &Process::interactive),
                MAKE_FIELD("name", &Process::name),
                MAKE_FIELD("pgid", &Process::pgid),
                MAKE_FIELD("pid", &Process::pid),
                MAKE_FIELD("same_as_process", &Process::same_as_process),
                MAKE_FIELD("start", &Process::start),
                MAKE_FIELD("title", &Process::title),
                MAKE_FIELD("working_directory", &Process::working_directory));
};

#endif // _PROCESSES_WCS_MODEL_HPP
