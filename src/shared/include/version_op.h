/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VERSION_H
#define VERSION_H


#define MAC_SYSVERSION "/System/Library/CoreServices/SystemVersion.plist"
#define MAC_SERVERVERSION "/System/Library/CoreServices/ServerVersion.plist"

/**
 * @struct os_info
 * @brief Stores information about the operating system version.
 */
typedef struct os_info {
    char *os_name;      ///< Operating system name.
    char *os_major;     ///< OS version number (major).
    char *os_minor;     ///< OS version number (minor).
    char *os_patch;     ///< OS version number (patch).
    char *os_build;     ///< OS version number (build).
    char *os_version;   ///< OS version (major.minor[.build])
    char *os_codename;  ///< OS version codename.
    char *os_platform;  ///< OS version ID.
    char *sysname;      ///< Operating system name (UNIX).
    char *nodename;     ///< Name within "some implementation-defined network" (UNIX).
    char *release;      ///< Operating system release (UNIX).
    char *version;      ///< Operating system version (UNIX).
    char *machine;      ///< Hardware identifier (UNIX).
    char *os_release;   ///< OS release.
    char *os_display_version;   ///< OS display version (Windows).
} os_info;


/**
 * @brief Get the macOS release name corresponding to a version number.
 *
 * @param version Version number.
 * @return Reselase name.
 */
const char *OSX_ReleaseName(int version);


/**
 * @brief Get the Windows version information.
 *
 * @return Pointer to allocated os_info struct.
 */
os_info *get_win_version();


/**
 * @brief Get the version information. (UNIX based systems).
 *
 * @return Pointer to allocated os_info struct.
 */
os_info *get_unix_version();


/**
 * @brief Deallocates the memory used by the os_info struct.
 *
 * @param osinfo Pointer to allocated os_info struct.
 */
void free_osinfo(os_info * osinfo);


/**
 * @brief Get number of processors
 *
 * @return Number of processors and 1 on error.
 */
int get_nproc();

/**
 * Compare two versions with format v4.0.0
 * @param version1 char * with the string version
 * @param version2 char * with the string version
 * @param compare_patch bool to compare or not patch version
 * @return return_code
 * @retval 0 equals
 * @retval 1 version1 > version2
 * @retval -1 version1 < version2
 * */
int compare_wazuh_versions(const char *version1, const char *version2, bool compare_patch);

#endif /* VERSION_H */
