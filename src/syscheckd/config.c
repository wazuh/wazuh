/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "config/config.h"
#include "rootcheck/rootcheck.h"

#ifdef WIN32
static char *SYSCHECK_EMPTY[] = { NULL };
static registry REGISTRY_EMPTY[] = { { NULL, 0, NULL } };
#endif


int Read_Syscheck_Config(const char *cfgfile)
{
    int modules = 0;
    int it = 0;
    modules |= CSYSCHECK;

    syscheck.rootcheck      = 0;
    syscheck.disabled       = SK_CONF_UNPARSED;
    syscheck.database_store = FIM_DB_DISK;
    syscheck.skip_fs.nfs    = 1;
    syscheck.skip_fs.dev    = 1;
    syscheck.skip_fs.sys    = 1;
    syscheck.skip_fs.proc   = 1;
    syscheck.scan_on_start  = 1;
    syscheck.time           = 43200;
    syscheck.ignore         = NULL;
    syscheck.ignore_regex   = NULL;
    syscheck.nodiff         = NULL;
    syscheck.nodiff_regex   = NULL;
    syscheck.scan_day       = NULL;
    syscheck.scan_time      = NULL;
    syscheck.file_limit_enabled = true;
    syscheck.file_limit     = 100000;
    syscheck.dir            = NULL;
    syscheck.opts           = NULL;
    syscheck.enable_synchronization = 1;
    syscheck.restart_audit  = 1;
    syscheck.enable_whodata = 0;
    syscheck.realtime       = NULL;
    syscheck.audit_healthcheck = 1;
    syscheck.process_priority = 10;
#ifdef WIN_WHODATA
    syscheck.wdata.interval_scan = 0;
    syscheck.wdata.fd      = NULL;
#endif
#ifdef WIN32
    syscheck.realtime_change = 0;
    syscheck.registry       = NULL;
    syscheck.registry_ignore = NULL;
    syscheck.registry_ignore_regex = NULL;
    syscheck.max_fd_win_rt  = 0;
#endif
    syscheck.prefilter_cmd  = NULL;
    syscheck.sync_interval  = 300;
    syscheck.max_sync_interval = 3600;
    syscheck.sync_response_timeout = 30;
    syscheck.sync_queue_size = 16384;
    syscheck.sync_max_eps = 10;
    syscheck.max_eps        = 100;
    syscheck.allow_remote_prefilter_cmd  = false;
    syscheck.disk_quota_enabled = true;
    syscheck.disk_quota_limit = 1024 * 1024; // 1 GB
    syscheck.file_size_enabled = true;
    syscheck.file_size_limit = 50 * 1024; // 50 MB
    syscheck.diff_folder_size = 0;
    syscheck.comp_estimation_perc = 0.9;    // 90%
    syscheck.disk_quota_full_msg = true;
    syscheck.audit_key = NULL;

    mdebug1(FIM_CONFIGURATION_FILE, cfgfile);

    /* Read config */
    if (ReadConfig(modules, cfgfile, &syscheck, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    mdebug1(FIM_CLIENT_CONFIGURATION, cfgfile);

    /* Read shared config */
    modules |= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &syscheck, NULL);
#endif

    // Check directories options to determine whether to start the whodata thread or not
    if (syscheck.dir) {
        for (it = 0; syscheck.dir[it]; it++) {
            if (syscheck.opts[it] & WHODATA_ACTIVE) {
                syscheck.enable_whodata = 1;

                break;  // Exit loop with the first whodata directory
            }
        }
    }

    if (syscheck.diff_size_limit) {
        for (it = 0; syscheck.diff_size_limit[it]; it++) {
            if (syscheck.diff_size_limit[it] == -1) {
                syscheck.diff_size_limit[it] = syscheck.file_size_limit;
            }
        }
    }

    switch (syscheck.disabled) {
    case SK_CONF_UNPARSED:
        syscheck.disabled = 1;
        break;
    case SK_CONF_UNDEFINED:
        syscheck.disabled = 0;
    }

#ifndef WIN32
    /* We must have at least one directory to check */
    if (!syscheck.dir || syscheck.dir[0] == NULL) {
        return (1);
    }
#else
    /* We must have at least one directory or registry key to check. Since
       it's possible on Windows to have syscheck enabled but only monitoring
       either the filesystem or the registry, both lists must be valid,
       even if empty.
     */
    if (!syscheck.dir) {
        syscheck.dir = SYSCHECK_EMPTY;
    }
    if (!syscheck.registry) {
            syscheck.registry = REGISTRY_EMPTY;
    }
    if ((syscheck.dir[0] == NULL) && (syscheck.registry[0].entry == NULL)) {
        return (1);
    }
    syscheck.max_fd_win_rt = getDefine_Int("syscheck", "max_fd_win_rt", 1, 1024);
#endif

    return (0);
}

void free_whodata_event(whodata_evt *w_evt) {
    if (w_evt == NULL) return;
    if (w_evt->user_name) free(w_evt->user_name);
#ifndef WIN32
    if (w_evt->cwd) free(w_evt->cwd);
    if (w_evt->audit_name) free(w_evt->audit_name);
    if (w_evt->audit_uid) free(w_evt->audit_uid);
    if (w_evt->effective_name) free(w_evt->effective_name);
    if (w_evt->effective_uid) free(w_evt->effective_uid);
    if (w_evt->group_id) free(w_evt->group_id);
    if (w_evt->parent_name) free(w_evt->parent_name);
    if (w_evt->parent_cwd) free(w_evt->parent_cwd);
    if (w_evt->inode) free(w_evt->inode);
    if (w_evt->dev) free(w_evt->dev);
    if (w_evt->user_id) free(w_evt->user_id);
#else
    if (w_evt->user_id) LocalFree(w_evt->user_id);
#endif
    if (w_evt->path) free(w_evt->path);
    if (w_evt->process_name) free(w_evt->process_name);
    free(w_evt);
}

cJSON *getSyscheckConfig(void) {

    if (!syscheck.dir) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *syscfg = cJSON_CreateObject();
    unsigned int i;

    if (syscheck.disabled) cJSON_AddStringToObject(syscfg,"disabled","yes"); else cJSON_AddStringToObject(syscfg,"disabled","no");
    cJSON_AddNumberToObject(syscfg,"frequency",syscheck.time);
    cJSON_AddStringToObject(syscfg, "skip_nfs", syscheck.skip_fs.nfs ? "yes" : "no");
    cJSON_AddStringToObject(syscfg, "skip_dev", syscheck.skip_fs.dev ? "yes" : "no");
    cJSON_AddStringToObject(syscfg, "skip_sys", syscheck.skip_fs.sys ? "yes" : "no");
    cJSON_AddStringToObject(syscfg, "skip_proc", syscheck.skip_fs.proc ? "yes" : "no");
    if (syscheck.scan_on_start) cJSON_AddStringToObject(syscfg,"scan_on_start","yes"); else cJSON_AddStringToObject(syscfg,"scan_on_start","no");
    if (syscheck.scan_day) cJSON_AddStringToObject(syscfg,"scan_day",syscheck.scan_day);
    if (syscheck.scan_time) cJSON_AddStringToObject(syscfg,"scan_time",syscheck.scan_time);

    cJSON * file_limit = cJSON_CreateObject();
    cJSON_AddStringToObject(file_limit, "enabled", syscheck.file_limit_enabled ? "yes" : "no");
    cJSON_AddNumberToObject(file_limit, "entries", syscheck.file_limit);
    cJSON_AddItemToObject(syscfg, "file_limit", file_limit);

    cJSON *diff = cJSON_CreateObject();

    cJSON *disk_quota = cJSON_CreateObject();
    cJSON_AddStringToObject(disk_quota, "enabled", syscheck.disk_quota_enabled ? "yes" : "no");
    cJSON_AddNumberToObject(disk_quota, "limit", syscheck.disk_quota_limit);
    cJSON_AddItemToObject(diff, "disk_quota", disk_quota);

    cJSON *file_size = cJSON_CreateObject();
    cJSON_AddStringToObject(file_size, "enabled", syscheck.file_size_enabled ? "yes" : "no");
    cJSON_AddNumberToObject(file_size, "limit", syscheck.file_size_limit);
    cJSON_AddItemToObject(diff, "file_size", file_size);

    cJSON_AddItemToObject(syscfg, "diff", diff);

    if (syscheck.dir) {
        cJSON *dirs = cJSON_CreateArray();
        for (i=0;syscheck.dir[i];i++) {
            cJSON *pair = cJSON_CreateObject();
            cJSON *opts = cJSON_CreateArray();
            if (syscheck.opts[i] & CHECK_MD5SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_md5sum"));
            if (syscheck.opts[i] & CHECK_SHA1SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha1sum"));
            if (syscheck.opts[i] & CHECK_PERM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_perm"));
            if (syscheck.opts[i] & CHECK_SIZE) cJSON_AddItemToArray(opts, cJSON_CreateString("check_size"));
            if (syscheck.opts[i] & CHECK_OWNER) cJSON_AddItemToArray(opts, cJSON_CreateString("check_owner"));
            if (syscheck.opts[i] & CHECK_GROUP) cJSON_AddItemToArray(opts, cJSON_CreateString("check_group"));
            if (syscheck.opts[i] & CHECK_MTIME) cJSON_AddItemToArray(opts, cJSON_CreateString("check_mtime"));
            if (syscheck.opts[i] & CHECK_INODE) cJSON_AddItemToArray(opts, cJSON_CreateString("check_inode"));
            if (syscheck.opts[i] & REALTIME_ACTIVE) cJSON_AddItemToArray(opts, cJSON_CreateString("realtime"));
            if (syscheck.opts[i] & CHECK_SEECHANGES) cJSON_AddItemToArray(opts, cJSON_CreateString("report_changes"));
            if (syscheck.opts[i] & CHECK_SHA256SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha256sum"));
            if (syscheck.opts[i] & WHODATA_ACTIVE) cJSON_AddItemToArray(opts, cJSON_CreateString("check_whodata"));
#ifdef WIN32
            if (syscheck.opts[i] & CHECK_ATTRS) cJSON_AddItemToArray(opts, cJSON_CreateString("check_attrs"));
#endif
            if (syscheck.opts[i] & CHECK_FOLLOW) cJSON_AddItemToArray(opts, cJSON_CreateString("follow_symbolic_link"));
            cJSON_AddItemToObject(pair,"opts",opts);
            cJSON_AddStringToObject(pair,"dir",syscheck.dir[i]);
            if (syscheck.symbolic_links[i]) cJSON_AddStringToObject(pair,"symbolic_link",syscheck.symbolic_links[i]);
            cJSON_AddNumberToObject(pair,"recursion_level",syscheck.recursion_level[i]);
            if (syscheck.filerestrict && syscheck.filerestrict[i]) {
                cJSON_AddStringToObject(pair,"restrict",syscheck.filerestrict[i]->raw);
            }
            if (syscheck.tag && syscheck.tag[i]) {
                cJSON_AddStringToObject(pair,"tags",syscheck.tag[i]);
            }

            if (syscheck.file_size_enabled && syscheck.diff_size_limit[i]) {
                cJSON_AddNumberToObject(pair, "diff_size_limit", syscheck.diff_size_limit[i]);
            }

            cJSON_AddItemToArray(dirs, pair);
        }
        cJSON_AddItemToObject(syscfg,"directories",dirs);
    }
    if (syscheck.nodiff) {
        cJSON *ndfs = cJSON_CreateArray();
        for (i=0;syscheck.nodiff[i];i++) {
            cJSON_AddItemToArray(ndfs, cJSON_CreateString(syscheck.nodiff[i]));
        }
        cJSON_AddItemToObject(syscfg,"nodiff",ndfs);
    }
    if (syscheck.ignore) {
        cJSON *igns = cJSON_CreateArray();
        for (i=0;syscheck.ignore[i];i++) {
            cJSON_AddItemToArray(igns, cJSON_CreateString(syscheck.ignore[i]));
        }
        cJSON_AddItemToObject(syscfg,"ignore",igns);
    }
    if (syscheck.ignore_regex) {
        cJSON *igns = cJSON_CreateArray();
        for (i=0;syscheck.ignore_regex[i];i++) {
            cJSON_AddItemToArray(igns, cJSON_CreateString(syscheck.ignore_regex[i]->raw));
        }
        cJSON_AddItemToObject(syscfg,"ignore_sregex",igns);
    }
#ifndef WIN32
    cJSON *whodata = cJSON_CreateObject();
    if (syscheck.restart_audit) {
        cJSON_AddStringToObject(whodata,"restart_audit","yes");
    } else {
        cJSON_AddStringToObject(whodata,"restart_audit","no");
    }
    if (syscheck.audit_key) {
        cJSON *audkey = cJSON_CreateArray();
        for (i=0;syscheck.audit_key[i];i++) {
            cJSON_AddItemToArray(audkey, cJSON_CreateString(syscheck.audit_key[i]));
        }
        if (cJSON_GetArraySize(audkey) > 0) {
            cJSON_AddItemToObject(whodata,"audit_key",audkey);
        } else {
            cJSON_free(audkey);
        }
    }
    if (syscheck.audit_healthcheck) {
        cJSON_AddStringToObject(whodata,"startup_healthcheck","yes");
    } else {
        cJSON_AddStringToObject(whodata,"startup_healthcheck","no");
    }
    cJSON_AddItemToObject(syscfg,"whodata",whodata);
#endif

#ifdef WIN32
    cJSON_AddNumberToObject(syscfg, "windows_audit_interval", syscheck.wdata.interval_scan);

    if (syscheck.registry) {
        cJSON *rg = cJSON_CreateArray();

        for (i=0; syscheck.registry[i].entry; i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair, "entry", syscheck.registry[i].entry);

            if (syscheck.registry[i].arch == 0) {
                cJSON_AddStringToObject(pair, "arch", "32bit");
            } else {
                cJSON_AddStringToObject(pair, "arch", "64bit");
            }

            if (syscheck.registry[i].tag) {
                cJSON_AddStringToObject(pair, "tags", syscheck.registry[i].tag);
            }

            cJSON_AddItemToArray(rg, pair);
        }
        cJSON_AddItemToObject(syscfg, "registry", rg);
    }

    if (syscheck.registry_ignore) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0; syscheck.registry_ignore[i].entry; i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair, "entry", syscheck.registry_ignore[i].entry);

            if (syscheck.registry_ignore[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg, "registry_ignore", rgi);
    }

    if (syscheck.registry_ignore_regex) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0;syscheck.registry_ignore_regex[i].regex;i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair,"entry",syscheck.registry_ignore_regex[i].regex->raw);

            if (syscheck.registry_ignore_regex[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg,"registry_ignore_sregex",rgi);
    }
#endif

    cJSON_AddStringToObject(syscfg, "allow_remote_prefilter_cmd", syscheck.allow_remote_prefilter_cmd ? "yes" : "no");

    if (syscheck.prefilter_cmd) {
        cJSON_AddStringToObject(syscfg,"prefilter_cmd",syscheck.prefilter_cmd);
    }

    cJSON * synchronization = cJSON_CreateObject();
    cJSON_AddStringToObject(synchronization, "enabled", syscheck.enable_synchronization ? "yes" : "no");
    cJSON_AddNumberToObject(synchronization, "max_interval", syscheck.max_sync_interval);
    cJSON_AddNumberToObject(synchronization, "interval", syscheck.sync_interval);
    cJSON_AddNumberToObject(synchronization, "response_timeout", syscheck.sync_response_timeout);
    cJSON_AddNumberToObject(synchronization, "queue_size", syscheck.sync_queue_size);
    cJSON_AddNumberToObject(synchronization, "max_eps", syscheck.sync_max_eps);
    cJSON_AddItemToObject(syscfg, "synchronization", synchronization);

    cJSON_AddNumberToObject(syscfg, "max_eps", syscheck.max_eps);
    cJSON_AddNumberToObject(syscfg, "process_priority", syscheck.process_priority);

    // Add sql database information
    cJSON_AddStringToObject(syscfg, "database", syscheck.database_store ? "memory" : "disk");


    cJSON_AddItemToObject(root,"syscheck",syscfg);

    return root;
}

cJSON *getSyscheckInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON *syscheckd = cJSON_CreateObject();

    cJSON_AddNumberToObject(syscheckd,"rt_delay",syscheck.rt_delay);
    cJSON_AddNumberToObject(syscheckd,"default_max_depth",syscheck.max_depth);
    cJSON_AddNumberToObject(syscheckd,"symlink_scan_interval",syscheck.sym_checker_interval);
    cJSON_AddNumberToObject(syscheckd,"debug",sys_debug_level);
    cJSON_AddNumberToObject(syscheckd,"file_max_size",syscheck.file_max_size);
#ifdef WIN32
    cJSON_AddNumberToObject(syscheckd,"max_fd_win_rt",syscheck.max_fd_win_rt);
#else
    cJSON_AddNumberToObject(syscheckd,"max_audit_entries",syscheck.max_audit_entries);
#endif

    cJSON_AddItemToObject(internals,"syscheck",syscheckd);

    cJSON *rootcheckd = cJSON_CreateObject();

    cJSON_AddNumberToObject(rootcheckd,"sleep",rootcheck.tsleep);
    cJSON_AddItemToObject(internals,"rootcheck",rootcheckd);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
