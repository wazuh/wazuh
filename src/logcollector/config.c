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
#include "logcollector.h"
#include "list_op.h"

/* To string size of max-size option */
#define OFFSET_SIZE 11

int accept_remote;
int lc_debug_level;
#ifndef WIN32
rlim_t nofile;
#endif

void _getLocalfilesListJSON(logreader *list, cJSON *array, const char *gpath);

/* Read the config file (the localfiles) */
int LogCollectorConfig(const char *cfgfile)
{
    int modules = 0;
    logreader_config log_config;

    modules |= CLOCALFILE;
    modules |= CLGCSOCKET;

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
    free_excluded_files_interval = getDefine_Int("logcollector", "exclude_files_interval", 1, 172800);
    state_interval = getDefine_Int("logcollector", "state_interval", 0, 3600);

    /* Current and total files counter */
    total_files = 0;
    current_files = 0;

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
#else
    if (maximum_files > WIN32_MAX_FILES) {
        /* Limit files on Windows as file descriptors are shared */
        maximum_files = WIN32_MAX_FILES;
        mdebug1("The maximum number of files to monitor cannot exceed %d in Windows, so it will be limited.", WIN32_MAX_FILES);
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

void _getLocalfilesListJSON(logreader* reader, cJSON* array, const char *gpath)
{
    cJSON* file = cJSON_CreateObject();

    if (gpath)
        cJSON_AddStringToObject(file, "file", gpath);
    else if (reader->ffile)
       cJSON_AddStringToObject(file, "file", reader->ffile);
    else if (reader->file)
        cJSON_AddStringToObject(file, "file", reader->file);
    if (reader->channel_str != NULL)
        cJSON_AddStringToObject(file, "channel", reader->channel_str);
    if (reader->logformat)
        cJSON_AddStringToObject(file, "logformat", reader->logformat);
    if (reader->command)
        cJSON_AddStringToObject(file, "command", reader->command);
    if (reader->djb_program_name)
        cJSON_AddStringToObject(file, "djb_program_name", reader->djb_program_name);
    if (reader->alias)
        cJSON_AddStringToObject(file, "alias", reader->alias);
    if (reader->query != NULL)
    {
        cJSON* query = cJSON_CreateObject();
        if (*reader->query != '\0')
        {
            cJSON_AddStringToObject(query, "value", reader->query);
        }
        if (reader->query_level != NULL)
        {
            cJSON_AddStringToObject(query, "level", reader->query_level);
        }
        if (reader->query_type > 0)
        {
            cJSON* type = cJSON_CreateArray();
            if (reader->query_type & MACOS_LOG_TYPE_LOG)
            {
                cJSON_AddItemToArray(type, cJSON_CreateString(MACOS_LOG_TYPE_LOG_STR));
            }
            if (reader->query_type & MACOS_LOG_TYPE_ACTIVITY)
            {
                cJSON_AddItemToArray(type, cJSON_CreateString(MACOS_LOG_TYPE_ACTIVITY_STR));
            }
            if (reader->query_type & MACOS_LOG_TYPE_TRACE)
            {
                cJSON_AddItemToArray(type, cJSON_CreateString(MACOS_LOG_TYPE_TRACE_STR));
            }
            cJSON_AddItemToObject(query, "type", type);
        }
        cJSON_AddItemToObject(file, "query", query);
    }
    // Invalid configuration for journal logs
    if (reader->journal_log == NULL)
    {
        cJSON_AddStringToObject(file, "ignore_binaries", reader->filter_binary ? "yes" : "no");
    }

    if (reader->age_str)
        cJSON_AddStringToObject(file, "age", reader->age_str);
    if (reader->exclude)
        cJSON_AddStringToObject(file, "exclude", reader->exclude);

    if (reader->logformat != NULL && strcmp(reader->logformat, EVENTLOG) != 0 && strcmp(reader->logformat, "command") != 0 &&
        strcmp(reader->logformat, "full_command") != 0)
    {

        if (reader->future == 1)
        {
            cJSON_AddStringToObject(file, "only-future-events", "yes");
        }
        else
        {
            char offset[OFFSET_SIZE] = {0};
            sprintf(offset, "%ld", reader->diff_max_size);
            cJSON_AddStringToObject(file, "only-future-events", "no");
            cJSON_AddStringToObject(file, "max-size", offset);
        }
    }

    if (reader->target && *reader->target)
    {
        cJSON* target = cJSON_CreateArray();
        for (int i = 0; reader->target[i]; i++)
        {
            cJSON_AddItemToArray(target, cJSON_CreateString(reader->target[i]));
        }
        cJSON_AddItemToObject(file, "target", target);
    }
    if (reader->out_format && *reader->out_format)
    {
        cJSON* outformat = cJSON_CreateArray();
        for (int i = 0; reader->out_format[i] && reader->out_format[i]->format; i++)
        {
            cJSON* item = cJSON_CreateObject();
            if (reader->out_format[i]->target)
                cJSON_AddStringToObject(item, "target", reader->out_format[i]->target);
            else
                cJSON_AddStringToObject(item, "target", "all");
            cJSON_AddStringToObject(item, "format", reader->out_format[i]->format);
            cJSON_AddItemToArray(outformat, item);
        }
        cJSON_AddItemToObject(file, "out_format", outformat);
    }
    if (reader->duplicated)
        cJSON_AddNumberToObject(file, "duplicate", reader->duplicated);
    if (reader->labels && reader->labels[0].key)
    {
        cJSON* label = cJSON_CreateObject();
        for (int i = 0; reader->labels[i].key; i++)
        {
            cJSON_AddStringToObject(label, reader->labels[i].key, reader->labels[i].value);
        }
        cJSON_AddItemToObject(file, "labels", label);
    }
    if (reader->ign && reader->logformat != NULL &&
        (strcmp(reader->logformat, "command") == 0 || strcmp(reader->logformat, "full_command") == 0))
        cJSON_AddNumberToObject(file, "frequency", reader->ign);
    if (reader->reconnect_time && reader->logformat != NULL && strcmp(reader->logformat, "eventchannel") == 0)
        cJSON_AddNumberToObject(file, "reconnect_time", reader->reconnect_time);
    if (reader->multiline)
    {
        cJSON* multiline = cJSON_CreateObject();
        cJSON_AddStringToObject(multiline, "match", multiline_attr_match_str(reader->multiline->match_type));
        cJSON_AddStringToObject(multiline, "replace", multiline_attr_replace_str(reader->multiline->replace_type));
        cJSON_AddStringToObject(multiline, "regex", w_expression_get_regex_pattern(reader->multiline->regex));
        cJSON_AddNumberToObject(multiline, "timeout", reader->multiline->timeout);
        cJSON_AddItemToObject(file, "multiline_regex", multiline);
    }
    if (reader->journal_log != NULL && reader->journal_log->filters != NULL)
    {

        cJSON* filters = w_journal_filter_list_as_json(reader->journal_log->filters);
        if (filters != NULL)
        {
            cJSON_AddItemToObject(file, "filters", filters);
        }

        cJSON_AddBoolToObject(file, "filters_disabled", reader->journal_log->disable_filters);
    }
    if (reader->regex_ignore != NULL)
    {
        OSListNode* node_it;
        w_expression_t* exp_it;
        cJSON* ignore_array = cJSON_CreateArray();

        OSList_foreach(node_it, reader->regex_ignore)
        {
            exp_it = node_it->data;
            cJSON* ignore_object = cJSON_CreateObject();

            cJSON_AddStringToObject(ignore_object, "value", w_expression_get_regex_pattern(exp_it));
            cJSON_AddStringToObject(ignore_object, "type", w_expression_get_regex_type(exp_it));

            cJSON_AddItemToArray(ignore_array, ignore_object);
        }

        if (cJSON_GetArraySize(ignore_array) > 0)
        {
            cJSON_AddItemToObject(file, "ignore", ignore_array);
        }
        else
        {
            cJSON_free(ignore_array);
        }
    }
    if (reader->regex_restrict != NULL)
    {
        OSListNode* node_it;
        w_expression_t* exp_it;
        cJSON* restrict_array = cJSON_CreateArray();

        OSList_foreach(node_it, reader->regex_restrict)
        {
            exp_it = node_it->data;
            cJSON* restrict_object = cJSON_CreateObject();

            cJSON_AddStringToObject(restrict_object, "value", w_expression_get_regex_pattern(exp_it));
            cJSON_AddStringToObject(restrict_object, "type", w_expression_get_regex_type(exp_it));

            cJSON_AddItemToArray(restrict_array, restrict_object);
        }

        if (cJSON_GetArraySize(restrict_array) > 0)
        {
            cJSON_AddItemToObject(file, "restrict", restrict_array);
        }
        else
        {
            cJSON_free(restrict_array);
        }
    }

    cJSON_AddItemToArray(array, file);
}

cJSON *getLocalfileConfig(void) {

    if (!logff) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();

    cJSON *localfiles = cJSON_CreateArray();

    for (int i = 0; logff[i].target; i++) {
        _getLocalfilesListJSON(&logff[i], localfiles, NULL);
    }

    if (globs) {
        for (int i = 0; globs[i].gfiles; i++) {
            if (globs[i].gfiles) {
                _getLocalfilesListJSON(globs[i].gfiles, localfiles, globs[i].gpath);
            }
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
    cJSON *sockets = cJSON_CreateArray();
    int i;

    for (i=0;logsk[i].name;i++) {
        cJSON *socket = cJSON_CreateObject();

        cJSON_AddStringToObject(socket,"name",logsk[i].name);
        cJSON_AddStringToObject(socket,"location",logsk[i].location);
        if (logsk[i].mode == IPPROTO_UDP) {
            cJSON_AddStringToObject(socket,"mode","udp");
        } else {
            cJSON_AddStringToObject(socket,"mode","tcp");
        }
        if (logsk[i].prefix) cJSON_AddStringToObject(socket,"prefix",logsk[i].prefix);

        cJSON_AddItemToArray(sockets, socket);
    }

    if (cJSON_GetArraySize(sockets) > 0) {
        cJSON_AddItemToObject(root,"socket",sockets);
    } else {
        cJSON_free(sockets);
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
    cJSON_AddNumberToObject(logcollector, "exclude_files_interval", free_excluded_files_interval);
    cJSON_AddNumberToObject(logcollector, "state_interval", state_interval);

#ifndef WIN32
    cJSON_AddNumberToObject(logcollector,"rlimit_nofile",nofile);
#endif

    cJSON_AddItemToObject(internals,"logcollector",logcollector);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
