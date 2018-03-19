/* Copyright (C) 2009 Trend Micro Inc.
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
    open_file_attempts = getDefine_Int("logcollector", "open_attempts", 2, 998);
    vcheck_files = getDefine_Int("logcollector", "vcheck_files", 0, 1024);
    maximum_lines = getDefine_Int("logcollector", "max_lines", 0, 1000000);
    maximum_files = getDefine_Int("logcollector", "max_files", 1, 100000);
    sock_fail_time = getDefine_Int("logcollector", "sock_fail_time", 1, 3600);
    sample_log_length = getDefine_Int("logcollector", "sample_log_length", 1, 4096);

    if (maximum_lines > 0 && maximum_lines < 100) {
        merror("Definition 'logcollector.max_lines' must be 0 or 100..1000000.");
        return OS_INVALID;
    }

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

cJSON *getLocalfileConfig(void) {

    if (!max_file) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *localfiles = cJSON_CreateArray();
    int i, j;

    for (i=0;i<max_file ;i++) {
        cJSON *file = cJSON_CreateObject();

        if (logff[i].file) cJSON_AddStringToObject(file,"file",logff[i].file);
        if (logff[i].logformat) cJSON_AddStringToObject(file,"logformat",logff[i].logformat);
        if (logff[i].command) cJSON_AddStringToObject(file,"command",logff[i].command);
        if (logff[i].djb_program_name) cJSON_AddStringToObject(file,"djb_program_name",logff[i].djb_program_name);
        if (logff[i].alias) cJSON_AddStringToObject(file,"alias",logff[i].alias);
        if (logff[i].query) cJSON_AddStringToObject(file,"query",logff[i].query);
        if (logff[i].outformat) cJSON_AddStringToObject(file,"outformat",logff[i].outformat);
        if (*logff[i].target) {
            cJSON *target = cJSON_CreateArray();
            for (j=0;logff[i].target[j];j++) {
                cJSON_AddItemToArray(target, cJSON_CreateString(logff[i].target[j]));
            }
            cJSON_AddItemToObject(file,"target",target);
        }
        if (logff[i].duplicated) cJSON_AddNumberToObject(file,"duplicate",logff[i].duplicated);
        if (logff[i].labels[0].key) {
            cJSON *label = cJSON_CreateObject();
            for (j=0;logff[i].labels[j].key;j++) {
                cJSON_AddStringToObject(label,logff[i].labels[j].key,logff[i].labels[j].value);
            }
            cJSON_AddItemToObject(file,"labels",label);
        }
        if (logff[i].ign) cJSON_AddNumberToObject(file,"frequency",logff[i].ign);
        if (logff[i].future) cJSON_AddStringToObject(file,"only-future-events","yes");

        cJSON_AddItemToArray(localfiles, file);
    }

    if (cJSON_GetArraySize(localfiles) > 0) {
        cJSON_AddItemToObject(root,"localfiles",localfiles);
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
        cJSON_AddItemToObject(root,"targets",targets);
    }

    return root;
}

cJSON *getLogcollectorInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON_AddNumberToObject(internals,"logcollector.remote_commands",accept_remote);
    cJSON_AddNumberToObject(internals,"logcollector.loop_timeout",loop_timeout);
    cJSON_AddNumberToObject(internals,"logcollector.open_attempts",open_file_attempts);
    cJSON_AddNumberToObject(internals,"logcollector.vcheck_files",vcheck_files);
    cJSON_AddNumberToObject(internals,"logcollector.max_lines",maximum_lines);
    cJSON_AddNumberToObject(internals,"logcollector.debug",debug_level);

    cJSON_AddItemToObject(root,"internal_options",internals);

    return root;
}
