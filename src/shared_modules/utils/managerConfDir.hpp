/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 13, 2026.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _MANAGER_CONF_DIR_HPP
#define _MANAGER_CONF_DIR_HPP

#include <string_view>

namespace Utils
{
    /**
     * @brief The manager's configuration directory. Fixed and absolute: a custom installation home
     * moves the home only, never the configuration.
     *
     * Defined once per language and kept identical in all of them: here, WAZUH_MANAGER_CONF_DIR in
     * src/shared/include/defs.h, MANAGER_CONF_DIR in the engine's base/managerConfig.hpp,
     * framework/wazuh/core/common.py (CONF_PATH) and src/init/shared.sh (CONF_DIR).
     */
    inline constexpr std::string_view MANAGER_CONF_DIR {"/etc/wazuh-manager"};

    /**
     * @brief Whether @p path names something inside MANAGER_CONF_DIR. Meant for a static_assert next to
     * a default path spelled as a literal (a `const char*` default cannot be concatenated at compile
     * time), so the literal can never drift from the directory.
     */
    constexpr bool isInManagerConfDir(std::string_view path)
    {
        return path.size() > MANAGER_CONF_DIR.size() + 1 &&
               path.substr(0, MANAGER_CONF_DIR.size()) == MANAGER_CONF_DIR && path[MANAGER_CONF_DIR.size()] == '/';
    }
} // namespace Utils

#endif // _MANAGER_CONF_DIR_HPP
