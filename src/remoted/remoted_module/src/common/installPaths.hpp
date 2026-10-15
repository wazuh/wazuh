/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 * October 13, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_INSTALL_PATHS_HPP
#define _REMOTED_COMMON_INSTALL_PATHS_HPP

#include "managerConfDir.hpp"

/**
 * @brief Installation paths the module opens.
 *
 * remoted changes to the installation directory at startup (src/remoted/src/main.c), so the relative paths here
 * resolve against it, like the C side's MULTIGROUPS_DIR and WDB_LOCAL_SOCK (src/shared/include/defs.h). The shared
 * group files live in the manager's fixed configuration directory instead, so kSharedDir is absolute, like
 * SHAREDCFG_DIR.
 * They are installation details, not configuration: nothing reads them from the C-ABI struct. Each path is defined
 * once, here; consumers default to these constants and tests may override them.
 */
namespace remoted::paths
{
    /// wazuh-db's request socket.
    inline constexpr const char* kWdbSocket = "queue/sockets/wdb.sock";
    /// The task manager's HTTP socket (modulesd), which hands over pending agent tasks.
    inline constexpr const char* kTaskSocket = "queue/sockets/task-http.sock";
    /// The vulnerability detector's HTTP socket (modulesd): /offset and scan requests.
    inline constexpr const char* kVdSocket = "queue/sockets/vd-http.sock";
    /// Per-group shared files (merged.mg and the group's agent.conf).
    inline constexpr const char* kSharedDir = "/etc/wazuh-manager/shared";
    static_assert(Utils::isInManagerConfDir(kSharedDir));
    /// Merged files of agents that belong to several groups.
    inline constexpr const char* kMultigroupsDir = "var/multigroups";
    /// WPK packages served to agents for upgrades.
    inline constexpr const char* kWpkDir = "var/upgrade";
} // namespace remoted::paths

#endif // _REMOTED_COMMON_INSTALL_PATHS_HPP
