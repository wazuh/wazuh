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
#include "localfile-config.h"
#include "config.h"

int maximum_files;
int current_files;
int total_files;

int Read_Localfile(XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    unsigned int pl = 0;
    unsigned int gl = 0;
    unsigned int i = 0;

    /* XML Definitions */
    const char *xml_localfile_location = "location";
    const char *xml_localfile_command = "command";
    const char *xml_localfile_logformat = "log_format";
    const char *xml_localfile_frequency = "frequency";
    const char *xml_localfile_alias = "alias";
    const char *xml_localfile_future = "only-future-events";
    const char *xml_localfile_query = "query";
    const char *xml_localfile_label = "label";
    const char *xml_localfile_target = "target";
    const char *xml_localfile_outformat = "out_format";
    const char *xml_localfile_reconnect_time = "reconnect_time";
    const char *xml_localfile_age = "age";
    const char *xml_localfile_exclude = "exclude";
    const char *xml_localfile_binaries = "ignore_binaries";

    logreader *logf;
    logreader_config *log_config;
    size_t labels_z=0;
    label_flags_t flags;

    log_config = (logreader_config *)d1;

    if (maximum_files && current_files >= maximum_files) {
        mwarn(FILE_LIMIT, maximum_files);
        return 0;
    }

    /* If config is not set, create it */
    if (!log_config->config) {
        os_calloc(2, sizeof(logreader), log_config->config);
        logf = log_config->config;
        memset(logf, 0, 2 * sizeof(logreader));
    } else {
        logf = log_config->config;
        while (logf[pl].file != NULL) {
            pl++;
        }

        /* Allocate more memory */
        os_realloc(logf, (pl + 2)*sizeof(logreader), log_config->config);
        logf = log_config->config;
        memset(logf + pl + 1, 0, sizeof(logreader));
    }

    if (!log_config->globs) {
        os_calloc(1, sizeof(logreader_glob), log_config->globs);
    } else {
        while (log_config->globs[gl].gpath) {
             gl++;
         }
    }
    memset(log_config->globs + gl, 0, sizeof(logreader_glob));
    memset(logf + pl, 0, sizeof(logreader));

    logf[pl].ign = 360;
    logf[pl].exists = 1;
    logf[pl].future = 1;
    logf[pl].reconnect_time = DEFAULT_EVENTCHANNEL_REC_TIME;

    /* Search for entries related to files */
    i = 0;
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_localfile_future) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logf[pl].future = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logf[pl].future = 0;
            } else {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_localfile_query) == 0) {
            os_strdup(node[i]->content, logf[pl].query);
        } else if (strcmp(node[i]->element, xml_localfile_target) == 0) {
            // Count number of targets
            int count, n;
            count = 1;
            for (n=0; node[i]->content[n]; n++) {
                if(node[i]->content[n] == ',') {
                    count ++;
                }
            }
            logf[pl].target = OS_StrBreak(',', node[i]->content, count);
            char * tmp;
            if(logf[pl].target) {
                for (n=0; n<count; n++) {
                    os_strdup(w_strtrim(logf[pl].target[n]), tmp);
                    free(logf[pl].target[n]);
                    logf[pl].target[n] = tmp;
                }
            }
        } else if (strcmp(node[i]->element, xml_localfile_outformat) == 0) {
            char * target = NULL;
            int j, n;

            // Get attribute

            for (j = 0; node[i]->attributes && node[i]->attributes[j]; ++j) {
                if (strcmp(node[i]->attributes[j], xml_localfile_target) == 0) {
                    target = node[i]->values[j];
                } else {
                    mwarn("Invalid attribute '%s' for <%s>", node[i]->attributes[j], xml_localfile_outformat);
                }
            }

            for (n = 0; logf[pl].out_format && logf[pl].out_format[n]; ++n);

            os_realloc(logf[pl].out_format, (n + 2) * sizeof(outformat *), logf[pl].out_format);
            os_malloc(sizeof(outformat), logf[pl].out_format[n]);
            logf[pl].out_format[n]->target = target ? strdup(target) : NULL;
            os_strdup(node[i]->content, logf[pl].out_format[n]->format);
            logf[pl].out_format[n + 1] = NULL;
        } else if (strcmp(node[i]->element, xml_localfile_reconnect_time) == 0) {
            char *c;
            int time = strtoul(node[i]->content, &c, 0);
            if(time) {
                switch (c[0]) {
                case 'w':
                    time *= 604800;
                    break;
                case 'd':
                    time *= 86400;
                    break;
                case 'h':
                    time *= 3600;
                    break;
                case 'm':
                    time *= 60;
                    break;
                case 's':
                    break;
                default:
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
            if(time < 1 ||  time == INT_MAX){
                mwarn("Invalid reconnection time value. Changed to %d seconds.", DEFAULT_EVENTCHANNEL_REC_TIME);
                time = DEFAULT_EVENTCHANNEL_REC_TIME;
            }
            logf[pl].reconnect_time = time;
        } else if (strcmp(node[i]->element, xml_localfile_label) == 0) {
            flags.hidden = flags.system = 0;
            char *key_value = 0;
            int j;
            for (j = 0; node[i]->attributes && node[i]->attributes[j]; j++) {
                if (strcmp(node[i]->attributes[j], "key") == 0) {
                    if (strlen(node[i]->values[j]) > 0) {
                        if (node[i]->values[j][0] == '_'){
                            mwarn("Labels starting with \"_\"  are reserved for internal use. Skipping label '%s'.", node[i]->values[j]);
                            flags.system = 1;
                        }
                        key_value = node[i]->values[j];
                    } else {
                        merror("Label with empty key.");
                        return (OS_INVALID);
                    }
                }
            }

            // Skip labels with "_"
            if (flags.system == 1)
                continue;

            if (!key_value) {
                merror("Expected 'key' attribute for label.");
                return (OS_INVALID);
            }

            logf[pl].labels = labels_add(logf[pl].labels, &labels_z, key_value, node[i]->content, flags, 1);
        } else if (strcmp(node[i]->element, xml_localfile_command) == 0) {
            /* We don't accept remote commands from the manager - just in case */
            if (log_config->agent_cfg == 1 && log_config->accept_remote == 0) {
                merror("Remote commands are not accepted from the manager. "
                       "Ignoring it on the agent.conf");

                logf[pl].file = NULL;
                logf[pl].ffile = NULL;
                logf[pl].command = NULL;
                logf[pl].alias = NULL;
                logf[pl].logformat = NULL;
                logf[pl].fp = NULL;
                labels_free(logf[pl].labels);
                return 0;
            }

            os_strdup(node[i]->content, logf[pl].file);
            logf[pl].command = logf[pl].file;
        } else if (strcmp(node[i]->element, xml_localfile_frequency) == 0) {

            if(strcmp(node[i]->content,  "hourly") == 0)
            {
                logf[pl].ign = 3600;
            }
            else if(strcmp(node[i]->content,  "daily") == 0)
            {
                logf[pl].ign = 86400;
            }
            else
            {

                if (!OS_StrIsNum(node[i]->content)) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }

                logf[pl].ign = atoi(node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_localfile_location) == 0) {
#ifdef WIN32
            /* Expand variables on Windows */
            if (strchr(node[i]->content, '%')) {
                int expandreturn = 0;
                char newfile[OS_MAXSTR + 1];

                newfile[OS_MAXSTR] = '\0';
                expandreturn = ExpandEnvironmentStrings(node[i]->content,
                                                        newfile, OS_MAXSTR);

                if ((expandreturn > 0) && (expandreturn < OS_MAXSTR)) {
                    free(node[i]->content);

                    os_strdup(newfile, node[i]->content);
                }
            }
#endif
            os_strdup(node[i]->content, logf[pl].file);
        } else if (strcasecmp(node[i]->element, xml_localfile_logformat) == 0) {
            os_strdup(node[i]->content, logf[pl].logformat);

            if (strcmp(logf[pl].logformat, "syslog") == 0) {
            } else if (strcmp(logf[pl].logformat, "generic") == 0) {
            } else if (strcmp(logf[pl].logformat, "json") == 0) {
            } else if (strcmp(logf[pl].logformat, "snort-full") == 0) {
            } else if (strcmp(logf[pl].logformat, "snort-fast") == 0) {
            } else if (strcmp(logf[pl].logformat, "apache") == 0) {
            } else if (strcmp(logf[pl].logformat, "iis") == 0) {
            } else if (strcmp(logf[pl].logformat, "squid") == 0) {
            } else if (strcmp(logf[pl].logformat, "nmapg") == 0) {
            } else if (strcmp(logf[pl].logformat, "mysql_log") == 0) {
            } else if (strcmp(logf[pl].logformat, "ossecalert") == 0) {
            } else if (strcmp(logf[pl].logformat, "mssql_log") == 0) {
            } else if (strcmp(logf[pl].logformat, "postgresql_log") == 0) {
            } else if (strcmp(logf[pl].logformat, "djb-multilog") == 0) {
            } else if (strcmp(logf[pl].logformat, "syslog-pipe") == 0) {
            } else if (strcmp(logf[pl].logformat, "command") == 0) {
            } else if (strcmp(logf[pl].logformat, "full_command") == 0) {
            } else if (strcmp(logf[pl].logformat, "audit") == 0) {
            } else if (strncmp(logf[pl].logformat, "multi-line", 10) == 0) {

                char *p_lf = logf[pl].logformat;
                p_lf += 10;

                while (p_lf[0] == ' ') {
                    p_lf++;
                }

                if (*p_lf != ':') {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
                p_lf++;

                char *end;

                if (logf[pl].linecount = strtol(p_lf, &end, 10), end == p_lf || logf[pl].linecount < 1 ) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }

            } else if (strcmp(logf[pl].logformat, EVENTLOG) == 0) {
            } else if (strcmp(logf[pl].logformat, EVENTCHANNEL) == 0) {
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_localfile_exclude) == 0) {
            if (logf[pl].exclude) {
                os_free(logf[pl].exclude);
            }
            os_strdup(node[i]->content, logf[pl].exclude);
        } else if (strcasecmp(node[i]->element, xml_localfile_alias) == 0) {
            os_strdup(node[i]->content, logf[pl].alias);
        } else if (!strcmp(node[i]->element, xml_localfile_age)) {
            char *endptr;
            logf[pl].age  = strtoul(node[i]->content, &endptr, 0);

            if (logf[pl].age == 0 || logf[pl].age == UINT_MAX) {
                merror("Invalid age for localfile");
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'w':
                logf[pl].age *= 604800;
                break;
            case 'd':
                logf[pl].age *= 86400;
                break;
            case 'h':
                logf[pl].age *= 3600;
                break;
            case 'm':
                logf[pl].age *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid age for localfile");
                return OS_INVALID;
            }

            if(logf[pl].age_str){
                os_free(logf[pl].age_str);
            }

            os_strdup(node[i]->content,logf[pl].age_str);

        } else if (strcasecmp(node[i]->element, xml_localfile_binaries) == 0) {

            if(strcmp(node[i]->content,"yes") == 0) {
               logf[pl].filter_binary = 1;
            }
            else if (strcmp(node[i]->content,"no") == 0) {
                logf[pl].filter_binary = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        i++;
    }

    if (logf[pl].target == NULL) {
        os_calloc(2, sizeof(char*), logf[pl].target);
        os_strdup("agent", logf[pl].target[0]);
    }

    /* Missing file */
    if (logf[pl].file == NULL) {
        merror(MISS_FILE);
        os_strdup("", logf[pl].file);
        return (OS_INVALID);
    }

    /* Missing log format */
    if (!logf[pl].logformat) {
        merror(MISS_LOG_FORMAT);
        return (OS_INVALID);
    }

        /* Verify a valid event log config */
    if (strcmp(logf[pl].logformat, EVENTLOG) == 0) {
        if ((strcmp(logf[pl].file, "Application") != 0) &&
                (strcmp(logf[pl].file, "System") != 0) &&
                (strcmp(logf[pl].file, "Security") != 0)) {
            /* Invalid event log */
            minfo(NSTD_EVTLOG, logf[pl].file);
            return (0);
        }
    }

    if ((strcmp(logf[pl].logformat, "command") == 0) ||
            (strcmp(logf[pl].logformat, "full_command") == 0)) {
        if (!logf[pl].command) {
            merror("Missing 'command' argument. "
                   "This option will be ignored.");
        }
        total_files++;
    } else {
        current_files++;
    }

    /* Deploy glob entries */
    if (!logf[pl].command) {
#ifdef WIN32
        if (strchr(logf[pl].file, '*') ||
            strchr(logf[pl].file, '?')) {

            WIN32_FIND_DATA ffd;
            HANDLE hFind = INVALID_HANDLE_VALUE;

            hFind = FindFirstFile(logf[pl].file, &ffd);

            if (INVALID_HANDLE_VALUE == hFind) {
                minfo(GLOB_ERROR_WIN, logf[pl].file);
            }

            os_realloc(log_config->globs, (gl + 2)*sizeof(logreader_glob), log_config->globs);
            os_strdup(logf[pl].file, log_config->globs[gl].gpath);
            memset(&log_config->globs[gl + 1], 0, sizeof(logreader_glob));
            os_calloc(1, sizeof(logreader), log_config->globs[gl].gfiles);
            memcpy(log_config->globs[gl].gfiles, &logf[pl], sizeof(logreader));
            log_config->globs[gl].gfiles->file = NULL;

            /* Wildcard exclusion, check for date */
            if (logf[pl].exclude && strchr(logf[pl].exclude, '%')) {

                time_t l_time = time(0);
                char excluded_path_date[PATH_MAX] = {0};
                size_t ret;
                struct tm tm_result = { .tm_sec = 0 };

                localtime_r(&l_time, &tm_result);
                ret = strftime(excluded_path_date, PATH_MAX, logf[pl].exclude, &tm_result);
                if (ret != 0) {
                    os_strdup(excluded_path_date, log_config->globs[gl].exclude_path);
                }
            }
            else if (logf[pl].exclude) {
                os_strdup(logf[pl].exclude, log_config->globs[gl].exclude_path);
            }

            if (Remove_Localfile(&logf, pl, 0, 0,NULL)) {
                merror(REM_ERROR, logf[pl].file);
                FindClose(hFind);
                return (OS_INVALID);
            }
            log_config->config = logf;
            FindClose(hFind);
            return 0;
#else
        if (strchr(logf[pl].file, '*') ||
            strchr(logf[pl].file, '?') ||
            strchr(logf[pl].file, '[')) {
            glob_t g;
            int err;

            if (err = glob(logf[pl].file, 0, NULL, &g), err && err != GLOB_NOMATCH) {
                merror(GLOB_ERROR, logf[pl].file);
            } else {
                os_realloc(log_config->globs, (gl + 2)*sizeof(logreader_glob), log_config->globs);
                os_strdup(logf[pl].file, log_config->globs[gl].gpath);
                memset(&log_config->globs[gl + 1], 0, sizeof(logreader_glob));
                os_calloc(1, sizeof(logreader), log_config->globs[gl].gfiles);
                memcpy(log_config->globs[gl].gfiles, &logf[pl], sizeof(logreader));
                log_config->globs[gl].gfiles->file = NULL;
            }

            /* Wildcard exclusion, check for date */
            if (logf[pl].exclude && strchr(logf[pl].exclude, '%')) {

                time_t l_time = time(0);
                struct tm tm_result = { .tm_sec = 0 };
                char excluded_path_date[PATH_MAX] = {0};
                size_t ret;

                localtime_r(&l_time, &tm_result);
                ret = strftime(excluded_path_date, PATH_MAX, logf[pl].exclude, &tm_result);
                if (ret != 0) {
                    os_strdup(excluded_path_date, log_config->globs[gl].exclude_path);
                }
            }
            else if (logf[pl].exclude) {
                os_strdup(logf[pl].exclude, log_config->globs[gl].exclude_path);
            }

            globfree(&g);
            if (Remove_Localfile(&logf, pl, 0, 0,NULL)) {
                merror(REM_ERROR, logf[pl].file);
                return (OS_INVALID);
            }
            log_config->config = logf;

            return 0;
#endif
        } else if (strchr(logf[pl].file, '%')) {
            /* We need the format file (based on date) */
            time_t l_time = time(0);
            struct tm tm_result = { .tm_sec = 0 };
            char lfile[OS_FLSIZE + 1];
            size_t ret;

            localtime_r(&l_time, &tm_result);
            lfile[OS_FLSIZE] = '\0';
            ret = strftime(lfile, OS_FLSIZE, logf[pl].file, &tm_result);
            if (ret != 0) {
                os_strdup(logf[pl].file, logf[pl].ffile);
            }

            /* Wildcard exclusion */
            if (logf[pl].exclude) {
                os_strdup(logf[pl].exclude, log_config->globs[gl].exclude_path);
            }
        }
    }

    return (0);
}

int Test_Localfile(const char * path){
    int fail = 0;
    logreader_config test_localfile = { .agent_cfg = 0 };

    if (ReadConfig(CAGENT_CONFIG | CLOCALFILE | CSOCKET, path, &test_localfile, NULL) < 0) {
        merror(RCONFIG_ERROR,"Localfile", path);
        fail = 1;
    }

    Free_Localfile(&test_localfile);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Localfile(logreader_config * config){
    int i, j;

    if (config) {
        if (config->config) {
            for (i = 0; config->config[i].file; i++) {
                Free_Logreader(&config->config[i]);
            }

            free(config->config);
        }

        if (config->socket_list) {
            for (i = 0; config->socket_list[i].name; i++) {
                free(config->socket_list[i].name);
                free(config->socket_list[i].location);
                free(config->socket_list[i].prefix);
            }

            free(config->socket_list);
        }

        if (config->globs) {
            for (i = 0; config->globs[i].gpath; i++) {
                if (config->globs[i].gfiles->file) {
                    Free_Logreader(config->globs[i].gfiles);
                    for (j = 1; config->globs[i].gfiles[j].file; j++) {
                        free(config->globs[i].gfiles[j].file);
                    }
                }
                free(config->globs[i].gfiles);
            }

            free(config->globs);
        }
    }
}

void Free_Logreader(logreader * logf) {
    int i;

    if (logf) {
        free(logf->ffile);
        free(logf->file);
        free(logf->logformat);
        free(logf->djb_program_name);
        free(logf->alias);
        free(logf->query);
        free(logf->exclude);

        if (logf->target) {
            for (i = 0; logf->target[i]; i++) {
                free(logf->target[i]);
            }

            free(logf->target);
        }

        free(logf->log_target);

        labels_free(logf->labels);

        if (logf->fp) {
            fclose(logf->fp);
        }

        if (logf->out_format) {
            for (i = 0; logf->out_format[i]; ++i) {
                free(logf->out_format[i]->target);
                free(logf->out_format[i]->format);
                free(logf->out_format[i]);
            }

            free(logf->out_format);
        }
    }
}

int Remove_Localfile(logreader **logf, int i, int gl, int fr, logreader_glob *globf) {
    if (*logf) {
        int size = 0;
        int x;
        while ((*logf)[size].file || (!gl && (*logf)[size].logformat)) {
            size++;
        }
        if (i < size) {
            if (fr) {
                Free_Logreader(&(*logf)[i]);
            } else {
                free((*logf)[i].file);
                if((*logf)[i].fp) {
                    fclose((*logf)[i].fp);
                }
            #ifdef WIN32
                if ((*logf)[i].h && (*logf)[i].h != INVALID_HANDLE_VALUE) {
                    CloseHandle((*logf)[i].h);
                }
            #endif
            }

            for (x = i; x < size; x++) {
                memcpy(&(*logf)[x], &(*logf)[x + 1], sizeof(logreader));
            }

            if (!size)
                size = 1;
            os_realloc(*logf, size*sizeof(logreader), *logf);

            if(gl && globf) {
                (*globf).num_files--;
            }

            current_files--;
            return 0;
        }
    }
    return (OS_INVALID);
}
