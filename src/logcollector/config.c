/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

/* Set logcollector options to default */
static void init_conf()
{
    log_config.loop_timeout = options.logcollector.loop_timeout.def;
    log_config.open_attempts = options.logcollector.open_attempts.def;
    log_config.accept_remote = options.logcollector.remote_commands.def;
    log_config.vcheck_files = options.logcollector.vcheck_files.def;
    log_config.max_lines = options.logcollector.max_lines.def;
    log_config.max_files = options.logcollector.max_files.def;
    log_config.sock_fail_time = options.logcollector.sock_fail_time.def;
    log_config.input_threads = options.logcollector.input_threads.def;
    log_config.queue_size = options.logcollector.queue_size.def;
    log_config.sample_log_length = options.logcollector.sample_log_length.def;
#ifndef WIN32
    log_config.rlimit_nofile = options.logcollector.rlimit_nofile.def;
#endif
    log_config.force_reload = options.logcollector.force_reload.def;
    log_config.reload_interval = options.logcollector.reload_interval.def;
    log_config.reload_delay = options.logcollector.reload_delay.def;
    log_config.exclude_files_interval = options.logcollector.exclude_files_interval.def;
    log_config.log_level = options.logcollector.log_level.def;
    log_config.thread_stack_size = options.global.thread_stack_size.def;

    return;
}

/* Set logcollector internal options */
static void read_internal()
{
    int aux;
    struct stat st_buf;
    char internal_file[OS_FLSIZE + 1];
    char local_internal_file[OS_FLSIZE + 1];

#ifndef WIN32
    if (isChroot()) {
        snprintf(internal_file, OS_FLSIZE, "%s", OSSEC_DEFINES);
        snprintf(local_internal_file, OS_FLSIZE, "%s", OSSEC_LDEFINES);
    } else {
        snprintf(internal_file, OS_FLSIZE, "%s%s", DEFAULTDIR, OSSEC_DEFINES);
        snprintf(local_internal_file, OS_FLSIZE, "%s%s", DEFAULTDIR, OSSEC_LDEFINES);
    }
#else
    snprintf(internal_file, OS_FLSIZE, "%s", OSSEC_DEFINES);
    snprintf(local_internal_file, OS_FLSIZE, "%s", OSSEC_LDEFINES);
#endif

    if (stat(local_internal_file, &st_buf) == 0) {
        mwarn("The file '%s' is being deprecated, it won't be used in next versions. It's recommended to configure all options in 'ossec.conf'", OSSEC_LDEFINES);
    }

    if (stat(internal_file, &st_buf) == 0) {
        mwarn("The file '%s' is being ignored as it is not going to be used anymore.", OSSEC_DEFINES);
    }

    if ((aux = getDefine_Int("logcollector", "loop_timeout", options.logcollector.loop_timeout.min, options.logcollector.loop_timeout.max)) != INT_OPT_NDEF)
        log_config.loop_timeout = aux;
    if ((aux = getDefine_Int("logcollector", "open_attempts", options.logcollector.open_attempts.min, options.logcollector.open_attempts.max)) != INT_OPT_NDEF)
        log_config.open_attempts = aux;
    if ((aux = getDefine_Int("logcollector", "remote_commands", options.logcollector.remote_commands.min, options.logcollector.remote_commands.max)) != INT_OPT_NDEF)
        log_config.accept_remote = aux;
    if ((aux = getDefine_Int("logcollector", "vcheck_files", options.logcollector.vcheck_files.min, options.logcollector.vcheck_files.max)) != INT_OPT_NDEF)
        log_config.vcheck_files = aux;
    if ((aux = getDefine_Int("logcollector", "max_lines", options.logcollector.max_lines.min, options.logcollector.max_lines.max)) != INT_OPT_NDEF)
        log_config.max_lines = aux;
    if ((aux = getDefine_Int("logcollector", "max_files", options.logcollector.max_files.min, options.logcollector.max_files.max)) != INT_OPT_NDEF)
        log_config.max_files = aux;
    if ((aux = getDefine_Int("logcollector", "sock_fail_time", options.logcollector.sock_fail_time.min, options.logcollector.sock_fail_time.max)) != INT_OPT_NDEF)
        log_config.sock_fail_time = aux;
    if ((aux = getDefine_Int("logcollector", "input_threads", options.logcollector.input_threads.min, options.logcollector.input_threads.max)) != INT_OPT_NDEF)
        log_config.input_threads = aux;
    if ((aux = getDefine_Int("logcollector", "queue_size", options.logcollector.queue_size.min, options.logcollector.queue_size.max)) != INT_OPT_NDEF)
        log_config.queue_size = aux;
    if ((aux = getDefine_Int("logcollector", "sample_log_length", options.logcollector.sample_log_length.min, options.logcollector.sample_log_length.max)) != INT_OPT_NDEF)
        log_config.sample_log_length = aux;
#ifndef WIN32
    if ((aux = getDefine_Int("logcollector", "rlimit_nofile", options.logcollector.rlimit_nofile.min, options.logcollector.rlimit_nofile.max)) != INT_OPT_NDEF)
        log_config.rlimit_nofile = aux;
#endif
    if ((aux = getDefine_Int("logcollector", "force_reload", options.logcollector.force_reload.min, options.logcollector.force_reload.max)) != INT_OPT_NDEF)
        log_config.force_reload = aux;
    if ((aux = getDefine_Int("logcollector", "reload_interval", options.logcollector.reload_interval.min, options.logcollector.reload_interval.max)) != INT_OPT_NDEF)
        log_config.reload_interval = aux;
    if ((aux = getDefine_Int("logcollector", "reload_delay", options.logcollector.reload_delay.min, options.logcollector.reload_delay.max)) != INT_OPT_NDEF)
        log_config.reload_delay = aux;
    if ((aux = getDefine_Int("logcollector", "exclude_files_interval", options.logcollector.exclude_files_interval.min, options.logcollector.exclude_files_interval.max)) != INT_OPT_NDEF)
        log_config.exclude_files_interval = aux;
    if ((aux = getDefine_Int("logcollector", "debug", options.logcollector.log_level.min, options.logcollector.log_level.max)) != INT_OPT_NDEF)
        log_config.log_level = aux;
    if ((aux = getDefine_Int("wazuh", "thread_stack_size", options.global.thread_stack_size.min, options.global.thread_stack_size.max)) != INT_OPT_NDEF)
        log_config.thread_stack_size = aux;

    return;
}

void _getLocalfilesListJSON(logreader *list, cJSON *array, int gl);

/* Read the config file (the localfiles) */
int LogCollectorConfig(const char *cfgfile)
{
    init_conf();

    int modules = 0;

    modules |= CLOGCOLLECTOR;

    if (ReadConfig(modules, cfgfile, &log_config, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    modules |= CAGENT_CONFIG;
    log_config.agent_cfg = 1;
    ReadConfig(modules, AGENTCONFIG, &log_config, NULL);
    log_config.agent_cfg = 0;
#endif

    read_internal();

    if (log_config.force_reload && log_config.reload_interval < log_config.vcheck_files) {
        mwarn("Reload interval (%d) must be greater or equal than the checking interval (%d).", log_config.reload_interval, log_config.vcheck_files);
    }

    if (log_config.max_lines > 0 && log_config.max_lines < 100) {
        merror("Definition 'logcollector.max_lines' must be 0 or 100..1000000.");
        return OS_INVALID;
    }

#ifndef WIN32
    if (log_config.max_files > (int)log_config.rlimit_nofile - 100) {
        merror("Definition 'logcollector.max_files' must be lower than ('logcollector.rlimit_nofile' - 100).");
        return OS_SIZELIM;
    }
#else
    if (log_config.max_files > WIN32_MAX_FILES) {
        /* Limit files on Windows as file descriptors are shared */
        log_config.max_files = WIN32_MAX_FILES;
        mdebug1("The maximum number of files to monitor cannot exceed %d in Windows, so it will be limited.", WIN32_MAX_FILES);
    }
#endif    

    maximum_files = log_config.max_files;

    modules = 0;

    modules |= CLOCALFILE;
    modules |= CSOCKET;

    log_config.config = NULL;
    log_config.globs = NULL;
    log_config.socket_list = NULL;
    log_config.agent_cfg = 0;

    /* Current and total files counter */
    total_files = 0;
    current_files = 0;

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


void _getLocalfilesListJSON(logreader *list, cJSON *array, int gl) {

    unsigned int i = 0;
    unsigned int j;

    while ((!gl && list[i].target) || (gl && list[i].file)) {
        cJSON *file = cJSON_CreateObject();

        if (list[i].file) cJSON_AddStringToObject(file,"file",list[i].file);
        if (list[i].logformat) cJSON_AddStringToObject(file,"logformat",list[i].logformat);
        if (list[i].command) cJSON_AddStringToObject(file,"command",list[i].command);
        if (list[i].djb_program_name) cJSON_AddStringToObject(file,"djb_program_name",list[i].djb_program_name);
        if (list[i].alias) cJSON_AddStringToObject(file,"alias",list[i].alias);
        if (list[i].query) cJSON_AddStringToObject(file,"query",list[i].query);
        cJSON_AddStringToObject(file,"ignore_binaries",list[i].filter_binary ? "yes" : "no");
        if (list[i].age_str) cJSON_AddStringToObject(file,"age",list[i].age_str);
        if (list[i].exclude) cJSON_AddStringToObject(file,"exclude",list[i].exclude);
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
    _getLocalfilesListJSON(logff, localfiles, 0);

    if (globs) {
        unsigned int i = 0;
        while (globs[i].gfiles) {
            _getLocalfilesListJSON(globs[i].gfiles, localfiles, 1);
            i++;
        }
    }

    if (cJSON_GetArraySize(localfiles) > 0) {
        cJSON_AddItemToObject(root,"localfile",localfiles);
    } else {
        cJSON_free(localfiles);
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
        if (logsk[i].mode == IPPROTO_UDP) {
            cJSON_AddStringToObject(target,"mode","udp");
        } else {
            cJSON_AddStringToObject(target,"mode","tcp");
        }
        if (logsk[i].prefix) cJSON_AddStringToObject(target,"prefix",logsk[i].prefix);

        cJSON_AddItemToArray(targets, target);
    }

    if (cJSON_GetArraySize(targets) > 0) {
        cJSON_AddItemToObject(root,"target",targets);
    } else {
        cJSON_free(targets);
    }

    return root;
}

cJSON *getLogcollectorOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *logcollector = cJSON_CreateObject();
    cJSON *files = cJSON_CreateObject();
    cJSON *reload = cJSON_CreateObject();

    cJSON_AddStringToObject(logcollector, "remote_commands", log_config.accept_remote ? "enabled" : "disabled");
    cJSON_AddNumberToObject(logcollector, "sock_fail_time", sock_fail_time);
    cJSON_AddNumberToObject(logcollector, "queue_size", log_config.queue_size);
    cJSON_AddNumberToObject(logcollector, "sample_log_length", log_config.sample_log_length);

    /* Files block */
    cJSON_AddNumberToObject(files, "loop_timeout", log_config.loop_timeout);
    cJSON_AddNumberToObject(files, "open_attempts", log_config.open_attempts);
    cJSON_AddNumberToObject(files, "vcheck", log_config.vcheck_files);
    cJSON_AddNumberToObject(files, "max_lines", log_config.max_lines);
    cJSON_AddNumberToObject(files, "max_files", log_config.max_files);
    cJSON_AddNumberToObject(files, "input_threads", log_config.input_threads);
#ifndef WIN32
    cJSON_AddNumberToObject(files, "rlimit_nofile", log_config.rlimit_nofile);
#endif
    cJSON_AddNumberToObject(files, "exclude_interval", log_config.exclude_files_interval);

    cJSON_AddItemToObject(logcollector, "files", files);

    /* Reload block */
    cJSON_AddStringToObject(reload, "force", log_config.force_reload ? "enabled" : "disabled");
    cJSON_AddNumberToObject(reload, "interval", log_config.reload_interval);
    cJSON_AddNumberToObject(reload, "delay", log_config.reload_delay);

    cJSON_AddItemToObject(logcollector, "reload", reload);

    cJSON_AddNumberToObject(logcollector, "thread_stack_size", log_config.thread_stack_size);
#ifndef WIN32
    cJSON_AddNumberToObject(logcollector, "log_level", log_config.log_level);
#endif

    cJSON_AddItemToObject(root, "logcollector", logcollector);

    return root;
}
