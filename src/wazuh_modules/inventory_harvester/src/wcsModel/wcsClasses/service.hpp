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
    struct File final
    {
        std::string_view path; // file.path (ECS)

        REFLECTABLE(MAKE_FIELD("path", &File::path));
    };

    struct Process final
    {
        struct Group final
        {
            std::string_view name; // process.group.name (ECS)

            REFLECTABLE(MAKE_FIELD("name", &Group::name));
        };

        struct User final
        {
            std::string_view name; // process.user.name (ECS)

            REFLECTABLE(MAKE_FIELD("name", &User::name));
        };

        std::vector<std::string_view> args;   // process.args (ECS)
        std::string_view executable;          // process.executable (ECS)
        Group group;                          // process.group (ECS)
        std::int64_t pid = DEFAULT_INT_VALUE; // process.pid (ECS)
        std::string_view root_directory;      // process.root_directory (ECS)
        User user;                            // process.user (ECS)
        std::string_view working_directory;   // process.working_directory (ECS)

        REFLECTABLE(MAKE_FIELD("args", &Process::args),
                    MAKE_FIELD("executable", &Process::executable),
                    MAKE_FIELD("group", &Process::group),
                    MAKE_FIELD("pid", &Process::pid),
                    MAKE_FIELD("root_directory", &Process::root_directory),
                    MAKE_FIELD("user", &Process::user),
                    MAKE_FIELD("working_directory", &Process::working_directory));
    };

    struct ServiceInfo final
    {
        struct Starts final
        {
            bool on_mount = false;
            std::vector<std::string_view> on_not_empty_directory;
            std::vector<std::string_view> on_path_modified;

            REFLECTABLE(MAKE_FIELD("on_mount", &Starts::on_mount),
                        MAKE_FIELD("on_not_empty_directory", &Starts::on_not_empty_directory),
                        MAKE_FIELD("on_path_modified", &Starts::on_path_modified));
        };

        struct Target
        {
            std::string_view address; // service.target.address (Custom)
            std::string ephemeral_id; // service.target.ephemeral_id (Custom)
            std::string_view type;    // service.type (ECS)

            REFLECTABLE(MAKE_FIELD("address", &Target::address),
                        MAKE_FIELD("ephemeral_id", &Target::ephemeral_id),
                        MAKE_FIELD("type", &Target::type));
        };

        std::string_view address;                           // service.address (Custom)
        std::string_view description;                       // service.description (Custom)
        std::string_view enabled;                           // service.enabled (Custom)
        std::int32_t exit_code = DEFAULT_INT32_VALUE;       // service.exit_code (Custom)
        std::string_view following;                         // service.following (Custom)
        std::int64_t frequency = DEFAULT_INT_VALUE;         // service.frequency (Custom)
        std::string_view id;                                // service.id (ECS)
        bool inetd_compatibility = false;                   // service.inetd_compatibility (Custom)
        std::string_view name;                              // service.name (ECS)
        std::string_view object_path;                       // service.object_path (Custom)
        std::string_view restart;                           // service.restart (Custom)
        std::string_view start_type;                        // service.start_type (Custom)
        Starts starts;                                      // service.starts (Custom)
        std::string_view state;                             // service.state (ECS)
        std::string_view sub_state;                         // service.sub_state (Custom)
        Target target;                                      // service.target (Custom)
        std::string type;                                   // service.type (Custom)
        std::int32_t win32_exit_code = DEFAULT_INT32_VALUE; // service.win32_exit_code (Custom)

        REFLECTABLE(MAKE_FIELD("address", &ServiceInfo::address),
                    MAKE_FIELD("description", &ServiceInfo::description),
                    MAKE_FIELD("enabled", &ServiceInfo::enabled),
                    MAKE_FIELD("exit_code", &ServiceInfo::exit_code),
                    MAKE_FIELD("following", &ServiceInfo::following),
                    MAKE_FIELD("frequency", &ServiceInfo::frequency),
                    MAKE_FIELD("id", &ServiceInfo::id),
                    MAKE_FIELD("inetd_compatibility", &ServiceInfo::inetd_compatibility),
                    MAKE_FIELD("name", &ServiceInfo::name),
                    MAKE_FIELD("object_path", &ServiceInfo::object_path),
                    MAKE_FIELD("restart", &ServiceInfo::restart),
                    MAKE_FIELD("start_type", &ServiceInfo::start_type),
                    MAKE_FIELD("starts", &ServiceInfo::starts),
                    MAKE_FIELD("state", &ServiceInfo::state),
                    MAKE_FIELD("sub_state", &ServiceInfo::sub_state),
                    MAKE_FIELD("target", &ServiceInfo::target),
                    MAKE_FIELD("type", &ServiceInfo::type),
                    MAKE_FIELD("win32_exit_code", &ServiceInfo::win32_exit_code));
    };

    struct Log final
    {
        struct File final
        {
            std::string_view path;

            REFLECTABLE(MAKE_FIELD("path", &File::path));
        };

        File file;
        std::string_view message;
        std::int32_t level = DEFAULT_INT32_VALUE;

        REFLECTABLE(MAKE_FIELD("file", &Log::file),
                    MAKE_FIELD("message", &Log::message),
                    MAKE_FIELD("level", &Log::level));
    };

    struct Error final
    {
        struct Log final
        {
            struct File final
            {
                std::string_view path;

                REFLECTABLE(MAKE_FIELD("path", &File::path));
            };

            File file;

            REFLECTABLE(MAKE_FIELD("file", &Log::file));
        };

        Log log;

        REFLECTABLE(MAKE_FIELD("log", &Error::log));
    };
};

#endif // _SERVICE_WCS_MODEL_HPP
