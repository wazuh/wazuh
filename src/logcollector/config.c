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
#include "logcollector.h"

int accept_remote;
int lc_debug_level;
#ifndef WIN32
rlim_t nofile;
#endif

void _getLocalfilesListJSON(logreader *list, cJSON *array);

/* Read the config file (the localfiles) */
int LogCollectorConfig(const char *cfgfile)
{
    int modules = 0;
    logreader_config log_config;

    modules |= CLOCALFILE;
    modules |= CSOCKET;

    log_config.config = NULL;
    log_config.globs = NULL;
    log_config.socket_list = NULL;
    log_config.agent_cfg = 0;
    accept_remote = getDefine_Int("logcollector", "remote_commands", 0, 1);
    log_config.accept_remote = accept_remote;

    /* Get loop timeout */
    loop_timeout = getDefine_Int("logcollector", "loop_timeout", 1, 120);
    open_file_attempts = getDefine_Int("logcollector", "open_attempts", 0, 998);
    vcheck_files = getDefine_Int("logcollector", "vcheck_files", 0, 1024);
    maximum_lines = getDefine_Int("logcollector", "max_lines", 0, 1000000);
    maximum_files = getDefine_Int("logcollector", "max_files", 1, 100000);
    sock_fail_time = getDefine_Int("logcollector", "sock_fail_time", 1, 3600);
    sample_log_length = getDefine_Int("logcollector", "sample_log_length", 1, 4096);
    force_reload = getDefine_Int("logcollector", "force_reload", 0, 1);
    reload_interval = getDefine_Int("logcollector", "reload_interval", 1, 86400);
    reload_delay = getDefine_Int("logcollector", "reload_delay", 0, 30000);

    if (force_reload && reload_interval < vcheck_files) {
        mwarn("Reload interval (%d) must be greater or equal than the checking interval (%d).", reload_interval, vcheck_files);
    }

#ifndef WIN32
    nofile = getDefine_Int("logcollector", "rlimit_nofile", 1024, 1048576);
#endif

    if (maximum_lines > 0 && maximum_lines < 100) {
        merror("Definition 'logcollector.max_lines' must be 0 or 100..1000000.");
        return OS_INVALID;
    }

#ifndef WIN32
    if (maximum_files > (int)nofile - 100) {
        merror("Definition 'logcollector.max_files' must be lower than ('logcollector.rlimit_nofile' - 100).");
        return OS_SIZELIM;
    }
#endif

    if (ReadConfig(modules, cfgfile, &log_config, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    modules |= CAGENT_CONFIG;
    log_config.agent_cfg = 1;
    ReadConfig(modules, AGENTCONFIG, &log_config, NULL);
    log_config.agent_cfg = 0;
#endif

    logff = log_config.config;
    globs = log_config.globs;
    logsk = log_config.socket_list;

    return (1);
}


void _getLocalfilesListJSON(logreader *list, cJSON *array) {

    unsigned int i = 0;
    unsigned int j;

    while (list[i].target) {
        cJSON *file = cJSON_CreateObject();

        if (list[i].file) cJSON_AddStringToObject(file,"file",list[i].file);
        if (list[i].logformat) cJSON_AddStringToObject(file,"logformat",list[i].logformat);
        if (list[i].command) cJSON_AddStringToObject(file,"command",list[i].command);
        if (list[i].djb_program_name) cJSON_AddStringToObject(file,"djb_program_name",list[i].djb_program_name);
        if (list[i].alias) cJSON_AddStringToObject(file,"alias",list[i].alias);
        if (list[i].query) cJSON_AddStringToObject(file,"query",list[i].query);
        if (list[i].target && *list[i].target) {
            cJSON *target = cJSON_CreateArray();
            for (j=0;list[i].target[j];j++) {
                cJSON_AddItemToArray(target, cJSON_CreateString(list[i].target[j]));
            }
            cJSON_AddItemToObject(file,"target",target);
        }
        if (list[i].out_format && *list[i].out_format) {
            cJSON *outformat = cJSON_CreateArray();
            for (j=0;list[i].out_format[j] && list[i].out_format[j]->format;j++) {
                cJSON *item = cJSON_CreateObject();
                if (list[i].out_format[j]->target)
                    cJSON_AddStringToObject(item,"target",list[i].out_format[j]->target);
                else
                    cJSON_AddStringToObject(item,"target","all");
                cJSON_AddStringToObject(item,"format",list[i].out_format[j]->format);
                cJSON_AddItemToArray(outformat, item);
            }
            cJSON_AddItemToObject(file,"out_format",outformat);
        }
        if (list[i].duplicated) cJSON_AddNumberToObject(file,"duplicate",list[i].duplicated);
        if (list[i].labels && list[i].labels[0].key) {
            cJSON *label = cJSON_CreateObject();
            for (j=0;list[i].labels[j].key;j++) {
                cJSON_AddStringToObject(label,list[i].labels[j].key,list[i].labels[j].value);
            }
            cJSON_AddItemToObject(file,"labels",label);
        }
        if (list[i].ign) cJSON_AddNumberToObject(file,"frequency",list[i].ign);
        if (list[i].future) cJSON_AddStringToObject(file,"only-future-events","yes");

        cJSON_AddItemToArray(array, file);
        i++;
    }
}


cJSON *getLocalfileConfig(void) {

    if (!logff) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();

    cJSON *localfiles = cJSON_CreateArray();
    _getLocalfilesListJSON(logff, localfiles);

    unsigned int i = 0;
    while (globs[i].gfiles) {
        _getLocalfilesListJSON(globs[i].gfiles, localfiles);
        i++;
    }
    if (cJSON_GetArraySize(localfiles) > 0) {
        cJSON_AddItemToObject(root,"localfile",localfiles);
    }

    return root;
}

cJSON *getSocketConfig(void) {

    if (!logsk) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *targets = cJSON_CreateArray();
    int i;

    for (i=0;logsk[i].name;i++) {
        cJSON *target = cJSON_CreateObject();

        cJSON_AddStringToObject(target,"name",logsk[i].name);
        cJSON_AddStringToObject(target,"location",logsk[i].location);
        if (logsk[i].mode == UDP_PROTO) {
            cJSON_AddStringToObject(target,"mode","udp");
        } else {
            cJSON_AddStringToObject(target,"mode","tcp");
        }
        if (logsk[i].prefix) cJSON_AddStringToObject(target,"prefix",logsk[i].prefix);

        cJSON_AddItemToArray(targets, target);
    }

    if (cJSON_GetArraySize(targets) > 0) {
        cJSON_AddItemToObject(root,"target",targets);
    }

    return root;
}

cJSON *getLogcollectorInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();
    cJSON *logcollector = cJSON_CreateObject();

    cJSON_AddNumberToObject(logcollector,"remote_commands",accept_remote);
    cJSON_AddNumberToObject(logcollector,"loop_timeout",loop_timeout);
    cJSON_AddNumberToObject(logcollector,"open_attempts",open_file_attempts);
    cJSON_AddNumberToObject(logcollector,"vcheck_files",vcheck_files);
    cJSON_AddNumberToObject(logcollector,"max_lines",maximum_lines);
    cJSON_AddNumberToObject(logcollector,"max_files",maximum_files);
    cJSON_AddNumberToObject(logcollector,"sock_fail_time",sock_fail_time);
    cJSON_AddNumberToObject(logcollector,"debug",lc_debug_level);
    cJSON_AddNumberToObject(logcollector,"sample_log_length",sample_log_length);
    cJSON_AddNumberToObject(logcollector,"queue_size",OUTPUT_QUEUE_SIZE);
    cJSON_AddNumberToObject(logcollector,"input_threads",N_INPUT_THREADS);
    cJSON_AddNumberToObject(logcollector,"force_reload",force_reload);
    cJSON_AddNumberToObject(logcollector,"reload_interval",reload_interval);
    cJSON_AddNumberToObject(logcollector,"reload_delay",reload_delay);
#ifndef WIN32
    cJSON_AddNumberToObject(logcollector,"rlimit_nofile",nofile);
#endif

    cJSON_AddItemToObject(internals,"logcollector",logcollector);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
