/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
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
    modules |= CSYSCHECK;

    syscheck.rootcheck      = 0;
    syscheck.disabled       = SK_CONF_UNPARSED;
    syscheck.skip_nfs       = 1;
    syscheck.scan_on_start  = 1;
    syscheck.time           = 43200;
    syscheck.ignore         = NULL;
    syscheck.ignore_regex   = NULL;
    syscheck.nodiff         = NULL;
    syscheck.nodiff_regex   = NULL;
    syscheck.scan_day       = NULL;
    syscheck.scan_time      = NULL;
    syscheck.dir            = NULL;
    syscheck.opts           = NULL;
    syscheck.restart_audit  = 1;
    syscheck.enable_whodata = 0;
    syscheck.realtime       = NULL;
#ifdef WIN_WHODATA
    syscheck.wdata.interval_scan = 0;
    syscheck.wdata.fd      = NULL;
#endif
#ifdef WIN32
    syscheck.registry       = NULL;
    syscheck.reg_fp         = NULL;
    syscheck.max_fd_win_rt  = 0;
#endif
    syscheck.prefilter_cmd  = NULL;

    mdebug2("Reading Configuration [%s]", cfgfile);

    /* Read config */
    if (ReadConfig(modules, cfgfile, &syscheck, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    mdebug2("Reading Client Configuration [%s]", cfgfile);

    /* Read shared config */
    modules |= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &syscheck, NULL);
#endif

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


void init_whodata_event(whodata_evt *w_evt) {
    w_evt->user_id = NULL;
    w_evt->user_name = NULL;
    w_evt->group_id = NULL;
    w_evt->group_name = NULL;
    w_evt->process_name = NULL;
    w_evt->path = NULL;
    w_evt->audit_uid = NULL;
    w_evt->audit_name = NULL;
    w_evt->effective_uid = NULL;
    w_evt->effective_name = NULL;
    w_evt->ppid = -1;
    w_evt->process_id = 0;
}


void free_whodata_event(whodata_evt *w_evt) {
    if (w_evt->user_name) free(w_evt->user_name);
    if (w_evt->user_id) {
#ifndef WIN32
        free(w_evt->user_id);
#else
        LocalFree(w_evt->user_id);
#endif
    }
    if (w_evt->audit_name) free(w_evt->audit_name);
    if (w_evt->audit_uid) free(w_evt->audit_uid);
    if (w_evt->effective_name) free(w_evt->effective_name);
    if (w_evt->effective_uid) free(w_evt->effective_uid);
    if (w_evt->group_name) free(w_evt->group_name);
    if (w_evt->group_id) free(w_evt->group_id);
    if (w_evt->path) free(w_evt->path);
    if (w_evt->process_name) free(w_evt->process_name);
    if (w_evt->inode) free(w_evt->inode);
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
    if (syscheck.skip_nfs) cJSON_AddStringToObject(syscfg,"skip_nfs","yes"); else cJSON_AddStringToObject(syscfg,"skip_nfs","no");
    if (syscheck.restart_audit) cJSON_AddStringToObject(syscfg,"restart_audit","yes"); else cJSON_AddStringToObject(syscfg,"restart_audit","no");
    if (syscheck.scan_on_start) cJSON_AddStringToObject(syscfg,"scan_on_start","yes"); else cJSON_AddStringToObject(syscfg,"scan_on_start","no");
    if (syscheck.scan_day) cJSON_AddStringToObject(syscfg,"scan_day",syscheck.scan_day);
    if (syscheck.scan_time) cJSON_AddStringToObject(syscfg,"scan_time",syscheck.scan_time);
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
            if (syscheck.opts[i] & CHECK_REALTIME) cJSON_AddItemToArray(opts, cJSON_CreateString("realtime"));
            if (syscheck.opts[i] & CHECK_SEECHANGES) cJSON_AddItemToArray(opts, cJSON_CreateString("report_changes"));
            if (syscheck.opts[i] & CHECK_SHA256SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha256sum"));
            if (syscheck.opts[i] & CHECK_WHODATA) cJSON_AddItemToArray(opts, cJSON_CreateString("check_whodata"));
#ifdef WIN32
            if (syscheck.opts[i] & CHECK_ATTRS) cJSON_AddItemToArray(opts, cJSON_CreateString("check_attrs"));
#endif
            if (syscheck.opts[i] & CHECK_FOLLOW) cJSON_AddItemToArray(opts, cJSON_CreateString("follow_symbolic_link"));
            cJSON_AddItemToObject(pair,"opts",opts);
            cJSON_AddStringToObject(pair,"dir",syscheck.dir[i]);
            cJSON_AddNumberToObject(pair,"recursion_level",syscheck.recursion_level[i]);
            if (syscheck.filerestrict && syscheck.filerestrict[i]) {
                cJSON_AddStringToObject(pair,"restrict",syscheck.filerestrict[i]->raw);
            }
            if (syscheck.tag && syscheck.tag[i]) {
                cJSON_AddStringToObject(pair,"tags",syscheck.tag[i]);
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
    cJSON *whodata = cJSON_CreateObject();
    if (syscheck.audit_key) {
        cJSON *audkey = cJSON_CreateArray();
        for (i=0;syscheck.audit_key[i];i++) {
            cJSON_AddItemToArray(audkey, cJSON_CreateString(syscheck.audit_key[i]));
        }
        if (cJSON_GetArraySize(audkey) > 0) {
            cJSON_AddItemToObject(whodata,"audit_key",audkey);
            cJSON_AddItemToObject(syscfg,"whodata",whodata);
        }
    }
#ifdef WIN32
    cJSON_AddNumberToObject(syscfg,"windows_audit_interval",syscheck.wdata.interval_scan);
    if (syscheck.registry) {
        cJSON *rg = cJSON_CreateArray();
        for (i=0;syscheck.registry[i].entry;i++) {
            cJSON *pair = cJSON_CreateObject();
            cJSON_AddStringToObject(pair,"entry",syscheck.registry[i].entry);
            if (syscheck.registry[i].arch == 0) cJSON_AddStringToObject(pair,"arch","32bit"); else cJSON_AddStringToObject(pair,"arch","64bit");
            if (syscheck.registry[i].tag) cJSON_AddStringToObject(pair,"tags",syscheck.registry[i].tag);
            cJSON_AddItemToArray(rg, pair);
        }
        cJSON_AddItemToObject(syscfg,"registry",rg);
    }
    if (syscheck.registry_ignore) {
        cJSON *rgi = cJSON_CreateArray();
        for (i=0;syscheck.registry_ignore[i].entry;i++) {
            cJSON *pair = cJSON_CreateObject();
            cJSON_AddStringToObject(pair,"entry",syscheck.registry_ignore[i].entry);
            if (syscheck.registry_ignore[i].arch == 0) cJSON_AddStringToObject(pair,"arch","32bit"); else cJSON_AddStringToObject(pair,"arch","64bit");
            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg,"registry_ignore",rgi);
    }
#endif
    if (syscheck.prefilter_cmd) cJSON_AddStringToObject(syscfg,"prefilter_cmd",syscheck.prefilter_cmd);

    cJSON_AddItemToObject(root,"syscheck",syscfg);

    return root;
}


cJSON *getSyscheckInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON *syscheckd = cJSON_CreateObject();

    cJSON_AddNumberToObject(syscheckd,"sleep",syscheck.tsleep);
    cJSON_AddNumberToObject(syscheckd,"sleep_after",syscheck.sleep_after);
    cJSON_AddNumberToObject(syscheckd,"rt_delay",syscheck.rt_delay);
    cJSON_AddNumberToObject(syscheckd,"default_max_depth",syscheck.max_depth);
    cJSON_AddNumberToObject(syscheckd,"debug",sys_debug_level);
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
