/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_syscollector_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_wdb_osinfo_save(__attribute__((unused)) wdb_t * wdb,
                           const char * scan_id,
                           const char * scan_time,
                           const char * hostname,
                           const char * architecture,
                           const char * os_name,
                           const char * os_version,
                           const char * os_codename,
                           const char * os_major,
                           const char * os_minor,
                           const char * os_patch,
                           const char * os_build,
                           const char * os_platform,
                           const char * sysname,
                           const char * release,
                           const char * version,
                           const char * os_release,
                           const char * os_display_version,
                           const char * checksum,
                           const bool replace) {
    if (scan_id) check_expected(scan_id);
    if (scan_time) check_expected(scan_time);
    if (hostname) check_expected(hostname);
    if (architecture) check_expected(architecture);
    if (os_name) check_expected(os_name);
    if (os_version) check_expected(os_version);
    if (os_codename) check_expected(os_codename);
    if (os_major) check_expected(os_major);
    if (os_minor) check_expected(os_minor);
    if (os_patch) check_expected(os_patch);
    if (os_build) check_expected(os_build);
    if (os_platform) check_expected(os_platform);
    if (sysname) check_expected(sysname);
    if (release) check_expected(release);
    if (version) check_expected(version);
    if (os_release) check_expected(os_release);
    if (os_display_version) check_expected(os_display_version);
    if (checksum) check_expected(checksum);
    check_expected(replace);
    return mock();
}
