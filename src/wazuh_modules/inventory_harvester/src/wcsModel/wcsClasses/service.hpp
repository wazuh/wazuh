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
        std::string_view id;
        std::string_view name;
        std::string_view description;
        std::string_view type;
        std::string_view state;
        std::string_view sub_state;
        std::string_view enabled;
        std::string_view start_type;
        std::string_view restart;
        long frequency;
        bool starts_on_mount;
        std::string_view starts_on_path_modified;
        std::string_view starts_on_not_empty_directory;
        bool inetd_compatibility;
        std::string_view address;
        long exit_code;
        long win32_exit_code;
        std::string_view following;
        std::string_view object_path;

        REFLECTABLE(MAKE_FIELD("id", &ServiceInfo::id),
                    MAKE_FIELD("name", &ServiceInfo::name),
                    MAKE_FIELD("description", &ServiceInfo::description),
                    MAKE_FIELD("type", &ServiceInfo::type),
                    MAKE_FIELD("state", &ServiceInfo::state),
                    MAKE_FIELD("sub_state", &ServiceInfo::sub_state),
                    MAKE_FIELD("enabled", &ServiceInfo::enabled),
                    MAKE_FIELD("start_type", &ServiceInfo::start_type),
                    MAKE_FIELD("restart", &ServiceInfo::restart),
                    MAKE_FIELD("frequency", &ServiceInfo::frequency),
                    MAKE_FIELD("starts_on_mount", &ServiceInfo::starts_on_mount),
                    MAKE_FIELD("starts_on_path_modified", &ServiceInfo::starts_on_path_modified),
                    MAKE_FIELD("starts_on_not_empty_directory", &ServiceInfo::starts_on_not_empty_directory),
                    MAKE_FIELD("inetd_compatibility", &ServiceInfo::inetd_compatibility),
                    MAKE_FIELD("address", &ServiceInfo::address),
                    MAKE_FIELD("exit_code", &ServiceInfo::exit_code),
                    MAKE_FIELD("win32_exit_code", &ServiceInfo::win32_exit_code),
                    MAKE_FIELD("following", &ServiceInfo::following),
                    MAKE_FIELD("object_path", &ServiceInfo::object_path));
    };

    struct Process final
    {
        long pid;
        std::string_view executable;
        std::string_view args;
        std::string_view working_directory;
        std::string_view root_directory;

        struct User final
        {
            std::string_view name;

            REFLECTABLE(MAKE_FIELD("name", &User::name));
        };

        struct Group final
        {
            std::string_view name;

            REFLECTABLE(MAKE_FIELD("name", &Group::name));
        };

        User user;
        Group group;

        REFLECTABLE(MAKE_FIELD("pid", &Process::pid),
                    MAKE_FIELD("executable", &Process::executable),
                    MAKE_FIELD("args", &Process::args),
                    MAKE_FIELD("working_directory", &Process::working_directory),
                    MAKE_FIELD("root_directory", &Process::root_directory),
                    MAKE_FIELD("user", &Process::user),
                    MAKE_FIELD("group", &Process::group));
    };

    struct File final
    {
        std::string_view path;

        REFLECTABLE(MAKE_FIELD("path", &File::path));
    };

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

    struct Target final
    {
        long ephemeral_id;
        std::string_view type;
        std::string_view address;

        REFLECTABLE(MAKE_FIELD("ephemeral_id", &Target::ephemeral_id),
                    MAKE_FIELD("type", &Target::type),
                    MAKE_FIELD("address", &Target::address));
    };
};

#endif // _SERVICE_WCS_MODEL_HPP
