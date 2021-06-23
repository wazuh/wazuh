/*
 * Wazuh module for SYSCHECK
 * Copyright (C) 2015-2021, Wazuh Inc.
 * March 31, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <stdlib.h>
#include "../../wmodules_def.h"
#include "wmodules.h"
#include "wm_syscheck.h"
#include "syscheckd/syscheck.h"
#include "rootcheck/rootcheck.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"

static void* wm_syscheck_main(wm_syscheck_t *sys);        // Module main function. It won't return
static void wm_syscheck_destroy(wm_syscheck_t *sys);      // Destroy data
static cJSON *wm_syscheck_dump(const wm_syscheck_t *sys);

const wm_context WM_SYSCHECK_CONTEXT = {
    "syscheck",
    (wm_routine)wm_syscheck_main,
    (wm_routine)(void *)wm_syscheck_destroy,
    (cJSON * (*)(const void *))wm_syscheck_dump,
    (int(*)(const char*))NULL,
};

static void wm_syscheck_print_info(void) {
    int r = 0;
    directory_t *dir_it = NULL;
    OSListNode *node_it;
#ifdef WIN32
#ifndef WIN_WHODATA
    int whodata_notification = 0;
    /* Remove whodata attributes */
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & WHODATA_ACTIVE) {
            if (!whodata_notification) {
                whodata_notification = 1;
                minfo(FIM_REALTIME_INCOMPATIBLE);
            }
            dir_it->options &= ~WHODATA_ACTIVE;
            dir_it->options |= REALTIME_ACTIVE;
        }
    }
#endif //WIN_WHODATA
    /* Print options */
    r = 0;
    // TODO: allow sha256 sum on registries
    while (syscheck.registry[r].entry != NULL) {
        char optstr[1024];
        mtinfo(SYSCHECK_LOGTAG, FIM_MONITORING_REGISTRY, syscheck.registry[r].entry,
                syscheck.registry[r].arch == ARCH_64BIT ? " [x64]" : "",
                syscheck_opts2str(optstr, sizeof(optstr), syscheck.registry[r].opts));
        if (syscheck.file_size_enabled){
            mtinfo(SYSCHECK_LOGTAG, FIM_DIFF_FILE_SIZE_LIMIT, syscheck.registry[r].diff_size_limit, syscheck.registry[r].entry);
        }
        r++;
    }
#endif //WIN32
    /* Print directories to be monitored */
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        char optstr[ 1024 ];

#ifdef WIN32
        mtinfo(SYSCHECK_LOGTAG, FIM_MONITORING_DIRECTORY, dir_it->path, syscheck_opts2str(optstr, sizeof(optstr), dir_it->options));
#else

        if (dir_it->symbolic_links == NULL) {
            mtinfo(SYSCHECK_LOGTAG, FIM_MONITORING_DIRECTORY, dir_it->path,
                    syscheck_opts2str(optstr, sizeof(optstr), dir_it->options));
        } else {
            mtinfo(SYSCHECK_LOGTAG, FIM_MONITORING_LDIRECTORY, dir_it->path, dir_it->symbolic_links,
                    syscheck_opts2str(optstr, sizeof(optstr), dir_it->options));
        }
#endif //WIN32

        if (dir_it->tag != NULL)
            mtdebug1(SYSCHECK_LOGTAG, FIM_TAG_ADDED, dir_it->tag, dir_it->path);

        // Print diff file size limit
        if ((dir_it->options & CHECK_SEECHANGES) && syscheck.file_size_enabled) {
            mtdebug2(SYSCHECK_LOGTAG, FIM_DIFF_FILE_SIZE_LIMIT, dir_it->diff_size_limit, dir_it->path);
        }
    }

    if (!syscheck.file_size_enabled) {
        mtinfo(SYSCHECK_LOGTAG, FIM_FILE_SIZE_LIMIT_DISABLED);
    }

    // Print maximum disk quota to be used by the queue/diff/local folder
    if (syscheck.disk_quota_enabled) {
        mtdebug2(SYSCHECK_LOGTAG, FIM_DISK_QUOTA_LIMIT, syscheck.disk_quota_limit);
    }
    else {
        mtinfo(SYSCHECK_LOGTAG, FIM_DISK_QUOTA_LIMIT_DISABLED);
    }

    /* Print ignores. */
    if(syscheck.ignore)
        for (r = 0; syscheck.ignore[r] != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_PRINT_IGNORE_ENTRY, "file", syscheck.ignore[r]);

    /* Print sregex ignores. */
    if(syscheck.ignore_regex)
        for (r = 0; syscheck.ignore_regex[r] != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_PRINT_IGNORE_SREGEX, "file", syscheck.ignore_regex[r]->raw);

#ifdef WIN32
    /* Print registry ignores. */
    if(syscheck.key_ignore)
        for (r = 0; syscheck.key_ignore[r].entry != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_PRINT_IGNORE_ENTRY, "registry", syscheck.key_ignore[r].entry);

    /* Print sregex registry ignores. */
    if(syscheck.key_ignore_regex)
        for (r = 0; syscheck.key_ignore_regex[r].regex != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_PRINT_IGNORE_SREGEX, "registry", syscheck.key_ignore_regex[r].regex->raw);

    if(syscheck.value_ignore)
        for (r = 0; syscheck.value_ignore[r].entry != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_PRINT_IGNORE_ENTRY, "value", syscheck.value_ignore[r].entry);

    /* Print sregex registry ignores. */
    if(syscheck.value_ignore_regex)
        for (r = 0; syscheck.value_ignore_regex[r].regex != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_PRINT_IGNORE_SREGEX, "value", syscheck.value_ignore_regex[r].regex->raw);

    /* Print registry values with nodiff. */
    if(syscheck.registry_nodiff)
        for (r = 0; syscheck.registry_nodiff[r].entry != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_NO_DIFF_REGISTRY, "registry value", syscheck.registry_nodiff[r].entry);

    /* Print sregex registry values with nodiff. */
    if(syscheck.registry_nodiff_regex)
        for (r = 0; syscheck.registry_nodiff_regex[r].regex != NULL; r++)
            mtinfo(SYSCHECK_LOGTAG, FIM_NO_DIFF_REGISTRY, "registry sregex", syscheck.registry_nodiff_regex[r].regex->raw);

#endif //WIN32


    /* Print files with no diff. */
    if (syscheck.nodiff){
        r = 0;
        while (syscheck.nodiff[r] != NULL) {
            mtinfo(SYSCHECK_LOGTAG, FIM_NO_DIFF, syscheck.nodiff[r]);
            r++;
        }
    }

    /* Check directories set for real time */
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
#if defined (INOTIFY_ENABLED) || defined (WIN32)
            mtinfo(SYSCHECK_LOGTAG, FIM_REALTIME_MONITORING_DIRECTORY, dir_it->path);
#else
            mtwarn(SYSCHECK_LOGTAG, FIM_WARN_REALTIME_DISABLED, dir_it->path);
            dir_it->options &= ~REALTIME_ACTIVE;
            dir_it->options |= SCHEDULED_ACTIVE;
#endif
        }
    }
}

static void wm_syscheck_log_config(const wm_syscheck_t *sys) {
    cJSON * config_json = wm_syscheck_dump(sys);
    if (config_json) {
        char * config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(SYSCHECK_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

void* wm_syscheck_main(wm_syscheck_t *sys) {
    syscheck_config* config = (syscheck_config*)sys;
    syscheck = *config;
    read_internal(0);
    mtdebug1(SYSCHECK_LOGTAG, "Starting syscheck.");
    if (syscheck.disabled == 1) {
        if (syscheck.directories == NULL || OSList_GetFirstNode(syscheck.directories) == NULL) {
            mtinfo(SYSCHECK_LOGTAG, FIM_DIRECTORY_NOPROVIDED);
        }

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            os_free(syscheck.ignore[0]);
        }
#ifdef WIN32
        if (!syscheck.registry) {
            dump_syscheck_registry(&syscheck, "", 0, NULL, NULL,  0, NULL, 0, -1);
        }
        os_free(syscheck.registry[0].entry);
#endif //WIN32

        mtinfo(SYSCHECK_LOGTAG, FIM_DISABLED);
        mtinfo(SYSCHECK_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }
    wm_syscheck_log_config(sys);
    /* Rootcheck config */
    syscheck.rootcheck = !rootcheck_init(0);
#ifndef WIN32
    // Start com request thread
    w_create_thread(syscom_main, NULL);

    if (syscheck.rootcheck) {
        rootcheck_connect();
    }
    /* Connect to the queue */
    if ((syscheck.queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        mterror_exit(SYSCHECK_LOGTAG, QUEUE_FATAL, DEFAULTQUEUE);
    }
#endif //WIN32
    wm_syscheck_print_info();
    fim_initialize();
#ifndef WIN32
    // Audit events thread
    if (syscheck.enable_whodata) {
#ifdef ENABLE_AUDIT
        if (audit_init() < 0) {
            directory_t *dir_it;
            OSListNode *node_it;
            mtwarn(SYSCHECK_LOGTAG, FIM_WARN_AUDIT_THREAD_NOSTARTED);

            // Switch who-data to real-time mode

        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
                if (dir_it->options & WHODATA_ACTIVE) {
                    dir_it->options &= ~WHODATA_ACTIVE;
                    dir_it->options |= REALTIME_ACTIVE;
                }
            }
        }
#else
        mterror(SYSCHECK_LOGTAG, FIM_ERROR_WHODATA_AUDIT_SUPPORT);
#endif
    }
#endif //WIN32
    /* Start the daemon */
    start_daemon();
    mtinfo(SYSCHECK_LOGTAG, "Module finished.");
    return 0;
}

void wm_syscheck_destroy(wm_syscheck_t *data) {
    mtinfo(SYSCHECK_LOGTAG, "Destroy received for Syscheck.");
    syscheck_config* config = (syscheck_config*)data;
    Free_Syscheck(config);
}

static cJSON *wm_syscheck_dump(const wm_syscheck_t *sys) {
    (void)sys;
    return getSyscheckConfig();
}