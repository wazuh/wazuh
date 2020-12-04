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
pthread_cond_t audit_thread_started;
pthread_cond_t audit_hc_started;
pthread_cond_t audit_db_consistency;
int sys_debug_level;

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
        merror(FIM_ERROR_LIBMAGIC_START, err ? err : "unknown");
    } else if (magic_load(*cookie_ptr, NULL) < 0) {
        const char *err = magic_error(*cookie_ptr);
        merror(FIM_ERROR_LIBMAGIC_LOAD, err ? err : "unknown");
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
    sys_debug_level = getDefine_Int("syscheck", "debug", 0, 2);

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        int debug_level = sys_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    return;
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

}


#ifdef WIN32
/* syscheck main for Windows */
int Start_win32_Syscheck()
{
    int debug_level = 0;
    int r = 0;
    char *cfg = DEFAULTCPATH;
    /* Read internal options */
    read_internal(debug_level);

    mdebug1(STARTED_MSG);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        merror(RCONFIG_ERROR, SYSCHECK, cfg);
        syscheck.disabled = 1;
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        /* Disabled */
        if (!syscheck.dir) {
            minfo(FIM_DIRECTORY_NOPROVIDED);
            dump_syscheck_file(&syscheck, "", 0, NULL, 0, NULL, NULL, -1);
        } else if (!syscheck.dir[0]) {
            minfo(FIM_DIRECTORY_NOPROVIDED);
        }

        os_free(syscheck.dir[0]);

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            os_free(syscheck.ignore[0]);
        }

        if (!syscheck.registry) {
            dump_syscheck_registry(&syscheck, "", 0, NULL, NULL,  0, NULL, 0, -1);
        }
        os_free(syscheck.registry[0].entry);

        minfo(FIM_DISABLED);
    }

    /* Rootcheck config */
    if (rootcheck_init(0) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    if (!syscheck.disabled) {
#ifndef WIN_WHODATA
        int whodata_notification = 0;
        /* Remove whodata attributes */
        for (r = 0; syscheck.dir[r]; r++) {
            if (syscheck.opts[r] & WHODATA_ACTIVE) {
                if (!whodata_notification) {
                    whodata_notification = 1;
                    minfo(FIM_REALTIME_INCOMPATIBLE);
                }
                syscheck.opts[r] &= ~WHODATA_ACTIVE;
                syscheck.opts[r] |= REALTIME_ACTIVE;
            }
        }
#endif

        /* Print options */
        r = 0;
        // TODO: allow sha256 sum on registries
        while (syscheck.registry[r].entry != NULL) {
            char optstr[1024];
            minfo(FIM_MONITORING_REGISTRY, syscheck.registry[r].entry,
                  syscheck.registry[r].arch == ARCH_64BIT ? " [x64]" : "",
                  syscheck_opts2str(optstr, sizeof(optstr), syscheck.registry[r].opts));
            if (syscheck.file_size_enabled){
                minfo(FIM_DIFF_FILE_SIZE_LIMIT, syscheck.registry[r].diff_size_limit, syscheck.registry[r].entry);
            }
            r++;
        }

        /* Print directories to be monitored */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            char optstr[ 1024 ];

            minfo(FIM_MONITORING_DIRECTORY, syscheck.dir[r], syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));

            if (syscheck.tag && syscheck.tag[r] != NULL) {
                mdebug1(FIM_TAG_ADDED, syscheck.tag[r], syscheck.dir[r]);
            }

            // Print diff file size limit
            if ((syscheck.opts[r] & CHECK_SEECHANGES) && syscheck.file_size_enabled) {
                mdebug2(FIM_DIFF_FILE_SIZE_LIMIT, syscheck.diff_size_limit[r], syscheck.dir[r]);
            }

            r++;
        }

        if (!syscheck.file_size_enabled) {
            minfo(FIM_FILE_SIZE_LIMIT_DISABLED);
        }

        // Print maximum disk quota to be used by the queue\diff\local folder
        if (syscheck.disk_quota_enabled) {
            mdebug2(FIM_DISK_QUOTA_LIMIT, syscheck.disk_quota_limit);
        }
        else {
            minfo(FIM_DISK_QUOTA_LIMIT_DISABLED);
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "file", syscheck.ignore[r]);

        /* Print sregex ignores. */
        if(syscheck.ignore_regex)
            for (r = 0; syscheck.ignore_regex[r] != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "file", syscheck.ignore_regex[r]->raw);

        /* Print registry ignores. */
        if(syscheck.key_ignore)
            for (r = 0; syscheck.key_ignore[r].entry != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "registry", syscheck.key_ignore[r].entry);

        /* Print sregex registry ignores. */
        if(syscheck.key_ignore_regex)
            for (r = 0; syscheck.key_ignore_regex[r].regex != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "registry", syscheck.key_ignore_regex[r].regex->raw);

        if(syscheck.value_ignore)
            for (r = 0; syscheck.value_ignore[r].entry != NULL; r++)
                minfo(FIM_PRINT_IGNORE_ENTRY, "value", syscheck.value_ignore[r].entry);

        /* Print sregex registry ignores. */
        if(syscheck.value_ignore_regex)
            for (r = 0; syscheck.value_ignore_regex[r].regex != NULL; r++)
                minfo(FIM_PRINT_IGNORE_SREGEX, "value", syscheck.value_ignore_regex[r].regex->raw);

        /* Print registry values with nodiff. */
        if(syscheck.registry_nodiff)
            for (r = 0; syscheck.registry_nodiff[r].entry != NULL; r++)
                minfo(FIM_NO_DIFF_REGISTRY, "registry value", syscheck.registry_nodiff[r].entry);

        /* Print sregex registry values with nodiff. */
        if(syscheck.registry_nodiff_regex)
            for (r = 0; syscheck.registry_nodiff_regex[r].regex != NULL; r++)
                minfo(FIM_NO_DIFF_REGISTRY, "registry sregex", syscheck.registry_nodiff_regex[r].regex->raw);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                minfo(FIM_NO_DIFF, syscheck.nodiff[r]);
                r++;
            }
        }

        /* Start up message */
        minfo(STARTUP_MSG, getpid());
    }

    /* Some sync time */
    fim_initialize();

    /* Wait if agent started properly */
    os_wait();

    start_daemon();

    return 0;
}
#endif /* WIN32 */
