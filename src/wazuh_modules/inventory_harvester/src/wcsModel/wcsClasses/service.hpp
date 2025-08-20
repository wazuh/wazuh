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
        std::string_view id;                    // service.id (ECS)
        std::string_view name;                  // service.name (ECS) 
        std::string_view description;           // service.description (Custom)
        std::string_view state;                 // service.state (ECS)
        std::string_view sub_state;             // service.sub_state (Custom)
        std::string_view start_type;            // service.start_type (Custom)
        std::string_view type;                  // service.type (ECS)
        long exit_code;                         // service.exit_code (Custom)
        std::string_view enabled;               // service.enabled (Custom)
        
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
        long pid;                               // process.pid (ECS)
        std::string_view executable;           // process.executable (ECS)
        
        REFLECTABLE(MAKE_FIELD("pid", &Process::pid),
                    MAKE_FIELD("executable", &Process::executable));
    };

    struct User final
    {
        std::string_view name;                  // user.name (ECS)
        
        REFLECTABLE(MAKE_FIELD("name", &User::name));
    };
};

#endif // _SERVICE_WCS_MODEL_HPP
