/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SERVICE_WCS_MODEL_HPP
#define _SERVICE_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Service final
{
    struct ServiceInfo final
    {
        std::string_view id;          // service.id (ECS)
        std::string_view name;        // service.name (ECS)
        std::string_view description; // service.description (Custom)
        std::string_view state;       // service.state (ECS)
        std::string_view sub_state;   // service.sub_state (Custom)
        std::string_view start_type;  // service.start_type (Custom)
        std::string_view type;        // service.type (ECS)
        long exit_code;               // service.exit_code (Custom)
        std::string_view enabled;     // service.enabled (Custom)

        REFLECTABLE(MAKE_FIELD("id", &ServiceInfo::id),
                    MAKE_FIELD("name", &ServiceInfo::name),
                    MAKE_FIELD("description", &ServiceInfo::description),
                    MAKE_FIELD("state", &ServiceInfo::state),
                    MAKE_FIELD("sub_state", &ServiceInfo::sub_state),
                    MAKE_FIELD("start_type", &ServiceInfo::start_type),
                    MAKE_FIELD("type", &ServiceInfo::type),
                    MAKE_FIELD("exit_code", &ServiceInfo::exit_code),
                    MAKE_FIELD("enabled", &ServiceInfo::enabled));
    };

    struct Process final
    {
        long pid;                           // process.pid (ECS)
        std::string_view executable;        // process.executable (ECS)
        std::string_view args;              // process.args (ECS)
        std::string_view working_directory; // process.working_directory (ECS)

        REFLECTABLE(MAKE_FIELD("pid", &Process::pid),
                    MAKE_FIELD("executable", &Process::executable),
                    MAKE_FIELD("args", &Process::args),
                    MAKE_FIELD("working_directory", &Process::working_directory));
    };

    struct User final
    {
        std::string_view name; // user.name (ECS)

        REFLECTABLE(MAKE_FIELD("name", &User::name));
    };

    struct File final
    {
        std::string_view path;           // file.path (ECS)
        std::string_view log_path;       // file.log.path (Custom)
        std::string_view error_log_path; // file.error_log.path (Custom)

        REFLECTABLE(MAKE_FIELD("path", &File::path),
                    MAKE_FIELD("log_path", &File::log_path),
                    MAKE_FIELD("error_log_path", &File::error_log_path));
    };
};

#endif // _SERVICE_WCS_MODEL_HPP
