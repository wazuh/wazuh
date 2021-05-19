/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Syscheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 */

#include "shared.h"
#include "syscheck.h"
#include "rootcheck/rootcheck.h"
#include "db/fim_db_files.h"

// Global variables
syscheck_config syscheck;

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_cookie = 0;


void init_magic(magic_t *cookie_ptr)
{
    if (!cookie_ptr || *cookie_ptr) {
        return;
    }

    *cookie_ptr = magic_open(MAGIC_MIME_TYPE);

    if (!*cookie_ptr) {
        const char *err = magic_error(*cookie_ptr);
        mterror(SYSCHECK_LOGTAG, FIM_ERROR_LIBMAGIC_START, err ? err : "unknown");
    } else if (magic_load(*cookie_ptr, NULL) < 0) {
        const char *err = magic_error(*cookie_ptr);
        mterror(SYSCHECK_LOGTAG, FIM_ERROR_LIBMAGIC_LOAD, err ? err : "unknown");
        magic_close(*cookie_ptr);
        *cookie_ptr = 0;
    }
}
#endif /* USE_MAGIC */

/* Read syscheck internal options */
void read_internal(int debug_level)
{
    syscheck.rt_delay = getDefine_Int("syscheck", "rt_delay", 0, 1000);
    syscheck.max_depth = getDefine_Int("syscheck", "default_max_depth", 1, 320);
    syscheck.file_max_size = (size_t)getDefine_Int("syscheck", "file_max_size", 0, 4095) * 1024 * 1024;
    syscheck.sym_checker_interval = getDefine_Int("syscheck", "symlink_scan_interval", 1, 2592000);

#ifndef WIN32
    syscheck.max_audit_entries = getDefine_Int("syscheck", "max_audit_entries", 1, 4096);
#endif
}


void fim_initialize() {
    // Create store data
    syscheck.database = fim_db_init(syscheck.database_store);

    if (!syscheck.database) {
        merror_exit(FIM_CRITICAL_DATA_CREATE, "sqlite3 db");
    }

    w_mutex_init(&syscheck.fim_entry_mutex, NULL);
    w_mutex_init(&syscheck.fim_scan_mutex, NULL);
    w_mutex_init(&syscheck.fim_realtime_mutex, NULL);
#ifndef WIN32
    w_mutex_init(&syscheck.fim_symlink_mutex, NULL)
#endif
}