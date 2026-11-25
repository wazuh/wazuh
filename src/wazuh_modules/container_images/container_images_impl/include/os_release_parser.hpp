/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OS_RELEASE_PARSER_HPP
#define _OS_RELEASE_PARSER_HPP

#include "image_inventory_types.hpp"

#include <string>
#include <vector>

namespace containerimages
{
    /// @brief In-image paths of the `os-release` file, in the order os-release(5) prefers
    /// them. Normalized, no leading slash.
    const std::vector<std::string>& osReleasePaths();

    /// @brief Parse the content of an `os-release` file.
    ///
    /// Reads the `KEY=value` lines, with bare, single-quoted and double-quoted values as
    /// os-release(5) allows. Comments, blank lines and malformed lines are skipped, and
    /// when a key repeats the last one wins, as it does when the file is sourced.
    ///
    /// @param content Full content of the file.
    /// @return The operating system, empty when the content holds no recognized key.
    ImageOperatingSystem parseOsRelease(const std::string& content);
} // namespace containerimages

#endif // _OS_RELEASE_PARSER_HPP
