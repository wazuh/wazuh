/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <vector>
#include <string>

namespace utils::string {

    /**
     * @brief Split a string into a vector of strings
     *
     * @param str String to be split
     * @param delimiter Delimiter to split the string
     * @return std::vector<std::string>
     */
    std::vector<std::string> split(std::string_view str, char delimiter);

}

#endif // _STRING_UTILS_H
