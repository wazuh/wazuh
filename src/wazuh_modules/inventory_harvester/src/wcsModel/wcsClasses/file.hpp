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

#ifndef _FILE_WCS_MODEL_HPP
#define _FILE_WCS_MODEL_HPP

#include "hash.hpp"
#include "reflectiveJson.hpp"
#include <string_view>

struct File final
{
    std::string_view name;
    std::string path;
    std::string_view gid;
    std::string_view group;
    std::string_view inode;
    std::string mtime;
    std::string_view mode;
    std::uint32_t size = 0;
    std::string_view target_path;
    std::string_view type;
    std::string_view uid;
    std::string_view owner;
    Hash hash;

    REFLECTABLE(MAKE_FIELD("name", &File::name),
                MAKE_FIELD("path", &File::path),
                MAKE_FIELD("gid", &File::gid),
                MAKE_FIELD("group", &File::group),
                MAKE_FIELD("inode", &File::inode),
                MAKE_FIELD("mtime", &File::mtime),
                MAKE_FIELD("mode", &File::mode),
                MAKE_FIELD("size", &File::size),
                MAKE_FIELD("target_path", &File::target_path),
                MAKE_FIELD("type", &File::type),
                MAKE_FIELD("uid", &File::uid),
                MAKE_FIELD("owner", &File::owner),
                MAKE_FIELD("hash", &File::hash));
};

#endif // _FILE_WCS_MODEL_HPP
