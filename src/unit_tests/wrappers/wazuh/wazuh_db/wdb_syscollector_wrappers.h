/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_SYSCOLLECTOR_WRAPPERS_H
#define WDB_SYSCOLLECTOR_WRAPPERS_H

#include "../wazuh_db/wdb.h"

int __wrap_wdb_osinfo_save(wdb_t * wdb,
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
                           const bool replace);

#endif
