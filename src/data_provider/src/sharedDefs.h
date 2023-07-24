/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SHARED_DEFS_H
#define _SHARED_DEFS_H

constexpr auto WM_SYS_HW_DIR {"/sys/class/dmi/id/board_serial"};
constexpr auto WM_SYS_CPU_DIR {"/proc/cpuinfo"};
constexpr auto WM_SYS_CPU_FREC_DIR { "/sys/devices/system/cpu/" };
constexpr auto WM_SYS_MEM_DIR {"/proc/meminfo"};
constexpr auto WM_SYS_IFDATA_DIR {"/sys/class/net/"};
constexpr auto WM_SYS_IF_FILE {"/etc/network/interfaces"};
constexpr auto WM_SYS_IF_DIR_RH {"/etc/sysconfig/network-scripts/"};
constexpr auto WM_SYS_IF_DIR_SUSE {"/etc/sysconfig/network/"};
constexpr auto WM_SYS_NET_DIR {"/proc/net/" };

constexpr auto DPKG_PATH {"/var/lib/dpkg/"};
constexpr auto DPKG_STATUS_PATH {"/var/lib/dpkg/status"};

constexpr auto RPM_PATH {"/var/lib/rpm/"};

constexpr auto PACMAN_PATH {"/var/lib/pacman"};

constexpr auto APK_PATH {"/lib/apk/db"};
constexpr auto APK_DB_PATH {"/lib/apk/db/installed"};
constexpr auto SNAP_PATH {"/var/lib/snapd"};

constexpr auto UNKNOWN_VALUE { " " };
constexpr auto MAC_ADDRESS_COUNT_SEGMENTS
{
    6ull
};

#define ROUNDUP(a) ((a) > 0 ? (1 + (((a)-1) | (sizeof(long) - 1))) : sizeof(long))


enum OSPlatformType
{
    LINUX,
    BSDBASED,
    WINDOWS,
    SOLARIS
};

enum LinuxType
{
    STANDARD,
    LEGACY
};

enum PortType
{
    UDP_IPV4,
    UDP_IPV6,
    TCP_IPV4,
    TCP_IPV6,
    SIZE_PORT_TYPE
};

enum Protocol
{
    TCP,
    UDP,
    PROTOCOL_SIZE
};

enum IPVersion
{
    IPV4,
    IPV6,
    IPVERSION_SIZE
};

enum MacOsPackageTypes
{
    PKG,
    BREW
};

enum RPMFields
{
    RPM_FIELDS_NAME,
    RPM_FIELDS_ARCHITECTURE,
    RPM_FIELDS_SUMMARY,
    RPM_FIELDS_PACKAGE_SIZE,
    RPM_FIELDS_EPOCH,
    RPM_FIELDS_RELEASE,
    RPM_FIELDS_VERSION,
    RPM_FIELDS_VENDOR,
    RPM_FIELDS_INSTALLTIME,
    RPM_FIELDS_GROUPS,
    RPM_FIELDS_SIZE
};

enum MacOSArchitecture
{
    X86_64,
    ARM64
};

#endif //_SHARED_DEFS_H
