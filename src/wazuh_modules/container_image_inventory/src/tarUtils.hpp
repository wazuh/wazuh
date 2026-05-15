/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TAR_UTILS_HPP
#define _TAR_UTILS_HPP

#include <string>
#include <vector>

namespace container_image_inventory
{
    struct TarMember
    {
        std::string normalized;
        std::string raw_name;
        bool is_file{false};
    };

    // Lists members of a tar (or gzip-wrapped tar) loaded in memory.
    std::vector<TarMember> list_tar_members(const std::vector<unsigned char>& bytes);

    // Extracts a single member, identified by raw_name, into out_bytes.
    // Returns true if found.
    bool extract_tar_member(const std::vector<unsigned char>& bytes,
                            const std::string& raw_name,
                            std::vector<unsigned char>& out_bytes);
} // namespace container_image_inventory

#endif
