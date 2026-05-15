/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_INVENTORY_SCANNER_HPP
#define _PACKAGE_INVENTORY_SCANNER_HPP

#include <string>
#include <vector>

#include "containerImageInventoryTypes.hpp"

namespace container_image_inventory
{
    // dpkg/status parser. Mirrors PackageLinuxHelper::parseDpkg.
    std::vector<Package> parse_dpkg(const std::string& content);

    // apk/installed parser. Mirrors PackageLinuxHelper::parseApk.
    std::vector<Package> parse_apk(const std::string& content);

    // RPM SQLite reader. Opens immutable+ro, yields header blobs and parses.
    std::vector<Package> parse_rpm_sqlite(const std::string& sqlite_path);

    // RPM Berkeley DB hash-file walker (matches poc_rpm_extract.py).
    std::vector<Package> parse_rpm_bdb(const std::string& bdb_path);
} // namespace container_image_inventory

#endif
