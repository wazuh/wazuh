/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __VERSION_H
#define __VERSION_H


typedef struct os_info {
    char *os_name;
    char *os_major;
    char *os_minor;
    char *os_build;
    char *os_version;
    char *os_codename;
    char *os_platform;
    char *sysname;
    char *nodename;
    char *release;
    char *version;
    char *machine;
} os_info;

char *OSX_ReleaseName(const int version);

os_info *get_win_version();

os_info *get_unix_version();

void free_osinfo(os_info * osinfo);

// Get number of processors
// Returns 1 on error
int get_nproc();

#endif
