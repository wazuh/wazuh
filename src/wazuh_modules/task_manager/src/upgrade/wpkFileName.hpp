/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_WPK_FILE_NAME_HPP
#define _TASK_MANAGER_UPGRADE_WPK_FILE_NAME_HPP

#include <string_view>

namespace task_manager::upgrade
{
    inline bool isValidWpkFileName(const std::string_view name)
    {
        return !name.empty() && name != "." && name != ".." && name.find_first_of("/\\") == std::string_view::npos &&
               name.find('\0') == std::string_view::npos;
    }
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_WPK_FILE_NAME_HPP
