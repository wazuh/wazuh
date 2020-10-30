/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SHARED_DEFS_H
#define _SHARED_DEFS_H

constexpr auto WM_SYS_HW_DIR{"/sys/class/dmi/id/board_serial"};
constexpr auto WM_SYS_CPU_DIR{"/proc/cpuinfo"};
constexpr auto WM_SYS_MEM_DIR{"/proc/meminfo"};
constexpr auto WM_SYS_IFDATA_DIR {"/sys/class/net/"};
constexpr auto WM_SYS_IF_FILE {"/etc/network/interfaces"};
constexpr auto WM_SYS_IF_DIR_RH {"/etc/sysconfig/network-scripts/"};
constexpr auto WM_SYS_IF_DIR_SUSE {"/etc/sysconfig/network/"};
constexpr auto WM_SYS_NET_DIR {"/proc/net/" };

constexpr auto DPKG_PATH {"/var/lib/dpkg/"};
constexpr auto DPKG_STATUS_PATH {"/var/lib/dpkg/status"};

#endif //_SHARED_DEFS_H