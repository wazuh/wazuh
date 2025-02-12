/* Copyright (C) 2015, Wazuh Inc.
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
#include "../config/config.h"
#include "../rootcheck/rootcheck.h"

#ifdef WIN32
static registry_t REGISTRY_EMPTY[] = { { NULL, 0, 0, 512, 0, NULL, NULL, NULL} };
#endif


int Read_Syscheck_Config(const char *cfgfile)
{
    int modules = 0;
    directory_t *dir_it;
    OSListNode *node_it;

    modules |= CSYSCHECK;

    if (initialize_syscheck_configuration(&syscheck) == OS_INVALID) {
        return OS_INVALID;
    }

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

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->diff_size_limit == -1) {
            dir_it->diff_size_limit = syscheck.file_size_limit;
        }

        // Check directories options to determine whether to start the whodata thread or not
        if (dir_it->options & WHODATA_ACTIVE) {
            if (dir_it->options & AUDIT_DRIVER) {
                syscheck.enable_whodata_audit = 1;
            }
            if (dir_it->options & EBPF_DRIVER) {
                syscheck.enable_whodata_ebpf = 1;
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
    if (OSList_GetFirstNode(syscheck.directories) == NULL && syscheck.wildcards == NULL) {
        return (1);
    }
#else
    /* It used to be that we needed to ensure the dir array was not null
       and had at least a null element, this is no longer the case. In Windows,
       if syscheck.directories is null nothing will go wrong.
       syscheck.registry though... That's a different story.
     */
    if (!syscheck.registry) {
            syscheck.registry = REGISTRY_EMPTY;
    } else {
        int it = 0;
        while (syscheck.registry[it].entry) {
            if (syscheck.registry[it].diff_size_limit == -1) {
                syscheck.registry[it].diff_size_limit = syscheck.file_size_limit;
            }
            it++;
        }
    }
    if ((OSList_GetFirstNode(syscheck.directories) == NULL) && (syscheck.registry[0].entry == NULL && syscheck.wildcards == NULL)) {
        return (1);
    }
    syscheck.max_fd_win_rt = (unsigned int) getDefine_Int("syscheck", "max_fd_win_rt", 1, 1024);
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
    if (w_evt->group_name) free(w_evt->group_name);
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
#ifndef WIN32
    w_rwlock_rdlock(&syscheck.directories_lock);
    if (OSList_GetFirstNode(syscheck.directories) == NULL) {
        w_rwlock_unlock(&syscheck.directories_lock);
        return NULL;
    }
    w_rwlock_unlock(&syscheck.directories_lock);
#endif

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
    cJSON_AddNumberToObject(syscfg, "max_files_per_second", syscheck.max_files_per_second);

    cJSON * file_limit = cJSON_CreateObject();
    cJSON_AddStringToObject(file_limit, "enabled", syscheck.file_limit_enabled ? "yes" : "no");
    cJSON_AddNumberToObject(file_limit, "entries", syscheck.file_entry_limit);
    cJSON_AddItemToObject(syscfg, "file_limit", file_limit);
#ifdef WIN32
    cJSON * registry_limit = cJSON_CreateObject();
    cJSON_AddStringToObject(registry_limit, "enabled", syscheck.registry_limit_enabled ? "yes" : "no");
    cJSON_AddNumberToObject(registry_limit, "entries", syscheck.db_entry_registry_limit);
    cJSON_AddItemToObject(syscfg, "registry_limit", registry_limit);
#endif

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

    w_rwlock_rdlock(&syscheck.directories_lock);
    if (OSList_GetFirstNode(syscheck.directories) != NULL) {
        directory_t *dir_it;
        cJSON *dirs = cJSON_CreateArray();
        OSListNode *node_it;

        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            cJSON *pair = cJSON_CreateObject();
            cJSON *opts = cJSON_CreateArray();
            if (dir_it->options & CHECK_MD5SUM) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_md5sum"));
            }
            if (dir_it->options & CHECK_SHA1SUM) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha1sum"));
            }
            if (dir_it->options & CHECK_PERM) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_perm"));
            }
            if (dir_it->options & CHECK_SIZE) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_size"));
            }
            if (dir_it->options & CHECK_OWNER) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_owner"));
            }
            if (dir_it->options & CHECK_GROUP) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_group"));
            }
            if (dir_it->options & CHECK_MTIME) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_mtime"));
            }
            if (dir_it->options & CHECK_INODE) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_inode"));
            }
            if (dir_it->options & REALTIME_ACTIVE) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("realtime"));
            }
            if (dir_it->options & CHECK_SEECHANGES) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("report_changes"));
            }
            if (dir_it->options & CHECK_SHA256SUM) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha256sum"));
            }
            if (dir_it->options & WHODATA_ACTIVE) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_whodata"));
            }
#ifdef WIN32
            if (dir_it->options & CHECK_ATTRS) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("check_attrs"));
            }
#endif
            if (dir_it->options & CHECK_FOLLOW) {
                cJSON_AddItemToArray(opts, cJSON_CreateString("follow_symbolic_link"));
            }

            cJSON_AddItemToObject(pair,"opts",opts);
            cJSON_AddStringToObject(pair, "dir", dir_it->path);
            if (dir_it->symbolic_links) {
                cJSON_AddStringToObject(pair, "symbolic_link", dir_it->symbolic_links);
            }
            cJSON_AddNumberToObject(pair, "recursion_level", dir_it->recursion_level);
            if (dir_it->filerestrict) {
                cJSON_AddStringToObject(pair, "restrict", dir_it->filerestrict->raw);
            }
            if (dir_it->tag) {
                cJSON_AddStringToObject(pair, "tags", dir_it->tag);
            }

            if (syscheck.file_size_enabled && dir_it->diff_size_limit) {
                cJSON_AddNumberToObject(pair, "diff_size_limit", dir_it->diff_size_limit);
            }

            cJSON_AddItemToArray(dirs, pair);
        }
        cJSON_AddItemToObject(syscfg,"directories",dirs);
    }
    w_rwlock_unlock(&syscheck.directories_lock);

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
    cJSON_AddNumberToObject(whodata, "queue_size", syscheck.queue_size);

    cJSON_AddItemToObject(syscfg,"whodata",whodata);
#endif

#ifdef WIN32
    cJSON_AddNumberToObject(syscfg, "windows_audit_interval", syscheck.wdata.interval_scan);

    if (syscheck.registry) {
        cJSON *rg = cJSON_CreateArray();

        for (i=0; syscheck.registry[i].entry; i++) {
            cJSON *pair = cJSON_CreateObject();
            cJSON *opts = cJSON_CreateArray();

            if (syscheck.registry[i].opts & CHECK_MD5SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_md5sum"));
            if (syscheck.registry[i].opts & CHECK_SHA1SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha1sum"));
            if (syscheck.registry[i].opts & CHECK_SHA256SUM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_sha256sum"));
            if (syscheck.registry[i].opts & CHECK_SIZE) cJSON_AddItemToArray(opts, cJSON_CreateString("check_size"));
            if (syscheck.registry[i].opts & CHECK_OWNER) cJSON_AddItemToArray(opts, cJSON_CreateString("check_owner"));
            if (syscheck.registry[i].opts & CHECK_GROUP) cJSON_AddItemToArray(opts, cJSON_CreateString("check_group"));
            if (syscheck.registry[i].opts & CHECK_PERM) cJSON_AddItemToArray(opts, cJSON_CreateString("check_perm"));
            if (syscheck.registry[i].opts & CHECK_MTIME) cJSON_AddItemToArray(opts, cJSON_CreateString("check_mtime"));
            if (syscheck.registry[i].opts & CHECK_TYPE) cJSON_AddItemToArray(opts, cJSON_CreateString("check_type"));
            if (syscheck.registry[i].opts & CHECK_SEECHANGES) cJSON_AddItemToArray(opts, cJSON_CreateString("report_changes"));

            cJSON_AddItemToObject(pair,"opts",opts);
            cJSON_AddStringToObject(pair, "entry", syscheck.registry[i].entry);

            if (syscheck.registry[i].arch == 0) {
                cJSON_AddStringToObject(pair, "arch", "32bit");
            } else {
                cJSON_AddStringToObject(pair, "arch", "64bit");
            }

            if (syscheck.registry[i].tag) {
                cJSON_AddStringToObject(pair, "tags", syscheck.registry[i].tag);
            }

            if (syscheck.registry[i].restrict_key) {
                cJSON_AddStringToObject(pair,"restrict_key", syscheck.registry[i].restrict_key->raw);
            }
            if (syscheck.registry[i].restrict_value) {
                cJSON_AddStringToObject(pair,"restrict_value", syscheck.registry[i].restrict_value->raw);
            }

            if (syscheck.file_size_enabled && syscheck.registry[i].diff_size_limit) {
                cJSON_AddNumberToObject(pair, "diff_size_limit", syscheck.registry[i].diff_size_limit);
            }

            cJSON_AddNumberToObject(pair,"recursion_level",syscheck.registry[i].recursion_level);

            cJSON_AddItemToArray(rg, pair);
        }
        cJSON_AddItemToObject(syscfg, "registry", rg);
    }

    if (syscheck.key_ignore) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0; syscheck.key_ignore[i].entry; i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair, "entry", syscheck.key_ignore[i].entry);

            if (syscheck.key_ignore[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg, "key_ignore", rgi);
    }

    if (syscheck.key_ignore_regex) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0;syscheck.key_ignore_regex[i].regex;i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair,"entry",syscheck.key_ignore_regex[i].regex->raw);

            if (syscheck.key_ignore_regex[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg,"key_ignore_sregex",rgi);
    }

     if (syscheck.value_ignore) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0; syscheck.value_ignore[i].entry; i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair, "entry", syscheck.value_ignore[i].entry);

            if (syscheck.value_ignore[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg, "value_ignore", rgi);
    }

    if (syscheck.value_ignore_regex) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0;syscheck.value_ignore_regex[i].regex;i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair,"entry",syscheck.value_ignore_regex[i].regex->raw);

            if (syscheck.value_ignore_regex[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg,"value_ignore_sregex",rgi);
    }

    if (syscheck.registry_nodiff) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0; syscheck.registry_nodiff[i].entry; i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair, "entry", syscheck.registry_nodiff[i].entry);

            if (syscheck.registry_nodiff[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg, "registry_nodiff", rgi);
    }

    if (syscheck.registry_nodiff_regex) {
        cJSON *rgi = cJSON_CreateArray();

        for (i=0;syscheck.registry_nodiff_regex[i].regex;i++) {
            cJSON *pair = cJSON_CreateObject();

            cJSON_AddStringToObject(pair,"entry",syscheck.registry_nodiff_regex[i].regex->raw);

            if (syscheck.registry_nodiff_regex[i].arch == 0) {
                cJSON_AddStringToObject(pair,"arch","32bit");
            } else {
                cJSON_AddStringToObject(pair,"arch","64bit");
            }

            cJSON_AddItemToArray(rgi, pair);
        }
        cJSON_AddItemToObject(syscfg,"registry_nodiff_sregex",rgi);
    }
#endif

    cJSON_AddStringToObject(syscfg, "allow_remote_prefilter_cmd", syscheck.allow_remote_prefilter_cmd ? "yes" : "no");

    if (syscheck.prefilter_cmd) {
        char *full_command;
        os_strdup(syscheck.prefilter_cmd[0], full_command);
        for (int i = 1; syscheck.prefilter_cmd[i]; i++) {
            wm_strcat(&full_command, syscheck.prefilter_cmd[i], ' ');
        }
        cJSON_AddStringToObject(syscfg,"prefilter_cmd", full_command);
        os_free(full_command);
    }

    cJSON * synchronization = cJSON_CreateObject();
    cJSON_AddStringToObject(synchronization, "enabled", syscheck.enable_synchronization ? "yes" : "no");
#ifdef WIN32
    cJSON_AddStringToObject(synchronization, "registry_enabled",
                            syscheck.enable_registry_synchronization ? "yes" : "no");
#endif
    cJSON_AddNumberToObject(synchronization, "queue_size", syscheck.sync_queue_size);
    cJSON_AddNumberToObject(synchronization, "interval", syscheck.sync_interval);
    cJSON_AddNumberToObject(synchronization, "max_eps", syscheck.sync_max_eps);
    cJSON_AddNumberToObject(synchronization, "response_timeout", syscheck.sync_response_timeout);
    cJSON_AddNumberToObject(synchronization, "max_interval", syscheck.sync_max_interval);
    cJSON_AddNumberToObject(synchronization, "thread_pool", syscheck.sync_thread_pool);

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
