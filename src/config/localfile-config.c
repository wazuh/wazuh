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
#include "localfile-config.h"
#include "config.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

int maximum_files;
int current_files;
int total_files;

/**
 * @brief gets the type filter from the type attribute
 * @param content type attribute string
 * @return returns the configuration flags: activity, trace and/or log
 */
STATIC int w_logcollector_get_macos_log_type(const char * content);

/**
 * @brief Check the regex type configured in localfile, the allowed types are osmatch, osregex and pcre2
 * @param node Current configuration node being edited
 * @param element Configuration element tag name
 * @return Returns the variable associated with the specified regex type
 */
w_exp_type_t w_check_regex_type(xml_node * node, const char * element);

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
    const char *xml_localfile_max_size_attr = "max-size";
    const char *xml_localfile_query = "query";
    const char *xml_localfile_query_type_attr = "type";
    const char *xml_localfile_query_level_attr = "level";
    const char *xml_localfile_label = "label";
    const char *xml_localfile_target = "target";
    const char *xml_localfile_outformat = "out_format";
    const char *xml_localfile_reconnect_time = "reconnect_time";
    const char *xml_localfile_age = "age";
    const char *xml_localfile_exclude = "exclude";
    const char *xml_localfile_binaries = "ignore_binaries";
    const char *xml_localfile_ignore = "ignore";
    const char *xml_localfile_restrict = "restrict";
    const char *xml_localfile_multiline_regex =  "multiline_regex";
    const char *xml_localfile_filter = "filter";

    logreader *logf;
    logreader_config *log_config;
    size_t labels_z=0;
    label_flags_t flags;
    w_exp_type_t regex_type;

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

    logf[pl].ign = DEFAULT_FREQUENCY_SECS;
    logf[pl].exists = 1;
    logf[pl].future = 1;
    logf[pl].reconnect_time = DEFAULT_EVENTCHANNEL_REC_TIME;
    logf[pl].regex_ignore = NULL;
    logf[pl].regex_restrict = NULL;

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
            logf[pl].diff_max_size = DIFF_DEFAULT_SIZE;
            if (node[i]->attributes) {
                for (int j = 0; node[i]->attributes[j]; j++) {
                    if (strcmp(node[i]->attributes[j], xml_localfile_max_size_attr) == 0) {
                        long long value = w_validate_bytes(node[i]->values[j]);
                        if (value == -1 || value > DIFF_MAX_SIZE) {
                            mwarn(LOGCOLLECTOR_INV_VALUE_DEFAULT, node[i]->values[j], \
                                  xml_localfile_max_size_attr, xml_localfile_future);

                            continue;
                        }
                        logf[pl].diff_max_size = (long) value;
                    } else {
                        mwarn(XML_INVATTR, node[i]->attributes[j], node[i]->element);
                    }
                }
            }
            if (strcmp(node[i]->content, "yes") == 0) {
                logf[pl].future = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logf[pl].future = 0;
            } else {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_localfile_query) == 0) {
            const char * type_attr = w_get_attr_val_by_name(node[i], xml_localfile_query_type_attr);
            if (type_attr) {
                logf[pl].query_type = w_logcollector_get_macos_log_type(type_attr);
            }

            const char * level_attr = w_get_attr_val_by_name(node[i], xml_localfile_query_level_attr);
            if (level_attr) {
                if ((strcmp(level_attr, MACOS_LOG_LEVEL_DEFAULT_STR) != 0) &&
                    (strcmp(level_attr, MACOS_LOG_LEVEL_INFO_STR) != 0) &&
                    (strcmp(level_attr, MACOS_LOG_LEVEL_DEBUG_STR) != 0)) {
                    /* Invalid level query */
                    mwarn(LOGCOLLECTOR_INV_VALUE_IGNORE, level_attr,
                        xml_localfile_query_level_attr, xml_localfile_query);
                } else {
                    os_strdup(level_attr, logf[pl].query_level);
                }
            }
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
            if (is_network_path(node[i]->content)) {
                merror("Network drives not allowed.");

                logf[pl].file = NULL;
                logf[pl].ffile = NULL;
                logf[pl].command = NULL;
                logf[pl].alias = NULL;
                logf[pl].logformat = NULL;
                logf[pl].fp = NULL;
                labels_free(logf[pl].labels);
                return 0;
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
            } else if (strcmp(logf[pl].logformat, MULTI_LINE_REGEX) == 0) {
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
            } else if (strcmp(logf[pl].logformat, MACOS) == 0) {
#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
                os_calloc(1, sizeof(w_macos_log_config_t), logf[pl].macos_log);
                w_calloc_expression_t(&logf[pl].macos_log->log_start_regex, EXP_TYPE_OSREGEX);
                if (!w_expression_compile(logf[pl].macos_log->log_start_regex, MACOS_LOG_START_REGEX, 0)) {
                    merror(LOGCOLLECTOR_MACOS_LOG_IREGEX_ERROR);
                    w_free_expression_t(&logf[pl].macos_log->log_start_regex);
                    os_free(logf[pl].macos_log);
                    return (OS_INVALID);
                }
#endif
            } else if (strcmp(logf[pl].logformat, JOURNALD_LOG) == 0) {
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_localfile_multiline_regex) == 0) {

            if (strlen(node[i]->content) == 0) {
                mwarn("Empty tag '%s' is ignored", xml_localfile_multiline_regex);
            } else if (logf[pl].multiline == NULL) {
                os_calloc(1, sizeof(w_multiline_config_t), logf[pl].multiline);
                w_calloc_expression_t(&logf[pl].multiline->regex, EXP_TYPE_PCRE2);

                if (!w_expression_compile(logf[pl].multiline->regex, node[i]->content, 0)) {
                    merror(LOCALFILE_REGEX, node[i]->content);
                    w_free_expression_t(&logf[pl].multiline->regex);
                    os_free(logf[pl].multiline);
                    return (OS_INVALID);
                }

                logf[pl].multiline->match_type = w_get_attr_match(node[i]);
                logf[pl].multiline->replace_type = w_get_attr_replace(node[i]);
                logf[pl].multiline->timeout = w_get_attr_timeout(node[i]);

            } else {
                mwarn("Duplicate tag '%s' is ignored", xml_localfile_multiline_regex);
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
        } else if (strcasecmp(node[i]->element, xml_localfile_ignore) == 0) {
            regex_type = EXP_TYPE_PCRE2;
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0]) {
                if (!strcmp(node[i]->attributes[0], "type")) {
                    regex_type = w_check_regex_type(node[i], xml_localfile_ignore);
                } else {
                    merror(LF_LOG_REGEX, xml_localfile_ignore, node[i]->content);
                    return (OS_INVALID);
                }
            }

            if (logf[pl].regex_ignore == NULL) {
                logf[pl].regex_ignore = OSList_Create();
                if (logf[pl].regex_ignore == NULL) {
                    merror(MEM_ERROR, errno, strerror(errno));
                    return (OS_INVALID);
                }
                OSList_SetFreeDataPointer(logf[pl].regex_ignore, (void (*)(void *))w_free_expression);
            }
            w_expression_t * expression_ignore;

            w_calloc_expression_t(&expression_ignore, regex_type);

            if (!w_expression_compile(expression_ignore, node[i]->content, 0)) {
                merror(LF_LOG_REGEX, "ignore", node[i]->content);
                w_free_expression_t(&expression_ignore);
                return (OS_INVALID);
            }
            OSList_InsertData(logf[pl].regex_ignore, NULL, expression_ignore);

        } else if (strcasecmp(node[i]->element, xml_localfile_restrict) == 0) {
            regex_type = EXP_TYPE_PCRE2;
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0]) {
                if (!strcmp(node[i]->attributes[0], "type")) {
                    regex_type = w_check_regex_type(node[i], xml_localfile_restrict);
                } else {
                    merror(LF_LOG_REGEX, xml_localfile_restrict, node[i]->content);
                    return (OS_INVALID);
                }
            }

            if (logf[pl].regex_restrict == NULL) {
                logf[pl].regex_restrict = OSList_Create();
                if (logf[pl].regex_restrict == NULL) {
                    merror(MEM_ERROR, errno, strerror(errno));
                    return (OS_INVALID);
                }
                OSList_SetFreeDataPointer(logf[pl].regex_restrict, (void (*)(void *))w_free_expression);
            }
            w_expression_t * expression_restrict;

            w_calloc_expression_t(&expression_restrict, regex_type);

            if (!w_expression_compile(expression_restrict, node[i]->content, 0)) {
                merror(LF_LOG_REGEX, "restrict", node[i]->content);
                w_free_expression_t(&expression_restrict);
                return (OS_INVALID);
            }
            OSList_InsertData(logf[pl].regex_restrict, NULL, expression_restrict);
        } else if (strcasecmp(node[i]->element, xml_localfile_filter) == 0) {
            if (init_w_journal_log_config_t(&(logf[pl].journal_log))) {
                os_calloc(2, sizeof(w_journal_filter_t *), logf[pl].journal_log->filters);
            }
            // Use always the same filter for all the conditions (First filter)
            if (!journald_add_condition_to_filter(node[i], &(logf[pl].journal_log->filters[0]))) {
                mwarn(LOGCOLLECTOR_JOURNAL_CONFG_FAIL_FILTER);
                w_clean_logreader(&logf[pl]);
                return (0);
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

    /* Missing log format */
    if (logf[pl].logformat == NULL) {
        merror(MISS_LOG_FORMAT);
        return (OS_INVALID);
    }

    /* Missing file */
    if (logf[pl].file == NULL) {
        if (strcmp(logf[pl].logformat, MACOS) == 0) {
            mwarn(LOGCOLLECTOR_MISSING_LOCATION_MACOS);
            // Neceesary to check duplicated blocks
            os_strdup(MACOS, logf[pl].file);
        } else if (strcmp(logf[pl].logformat, JOURNALD_LOG) == 0) {
            mwarn(LOGCOLLECTOR_JOURNAL_CONFG_MISSING_LOC, JOURNALD_LOG);
            os_strdup(JOURNALD_LOG, logf[pl].file);
        } else {
            merror(MISS_FILE);
            os_strdup("", logf[pl].file);
            return (OS_INVALID);
        }
    }

    /* Verify journald log config*/
    if (strcmp(logf[pl].logformat, JOURNALD_LOG) == 0) {

        init_w_journal_log_config_t(&(logf[pl].journal_log));

        /* Verify journald log config*/
        if (strcmp(logf[pl].file, JOURNALD_LOG) != 0) {
            /* Invalid macos log configuration */
            mwarn(LOGCOLLECTOR_JOURNAL_CONFG_INVALID_LOC, logf[pl].file, JOURNALD_LOG);
            os_free(logf[pl].file);
            w_strdup(JOURNALD_LOG, logf[pl].file);
        }

        if (logf[pl].reconnect_time != DEFAULT_EVENTCHANNEL_REC_TIME) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_reconnect_time);
        }
        if (logf[pl].age != 0) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_age);
        }
        if (logf[pl].filter_binary != 0) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_binaries);
        }
        if (logf[pl].exclude != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_exclude);
        }
        if (logf[pl].multiline != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_multiline_regex);
        }
        if (logf[pl].labels != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_label);
        }
        if (logf[pl].ign != DEFAULT_FREQUENCY_SECS) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_frequency);
        }
        if (logf[pl].alias != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_alias);
        }
        if (logf[pl].regex_ignore != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_ignore);
        }
        if (logf[pl].regex_restrict != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, JOURNALD_LOG, xml_localfile_restrict);
        }

    } else if (logf[pl].journal_log != NULL) {
        /* Only log format journald support journald log config */
        mwarn(LOGCOLLECTOR_JOURNAL_CONFG_NOT_JOURNAL_FILTER, logf[pl].logformat);
        w_journal_log_config_free(&(logf[pl].journal_log));
    }

    /* Verify macos log config*/
    if (strcmp(logf[pl].logformat, MACOS) == 0) {

        if (strcmp(logf[pl].file, MACOS) != 0) {
            /* Invalid macos log configuration */
            mwarn(LOGCOLLECTOR_INV_MACOS, logf[pl].file);
            os_free(logf[pl].file);
            // Neceesary to check duplicated blocks
            w_strdup(MACOS, logf[pl].file);
        }

        if (logf[pl].reconnect_time != DEFAULT_EVENTCHANNEL_REC_TIME) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_reconnect_time);
        }
        if (logf[pl].age != 0) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_age);
        }
        if (logf[pl].filter_binary != 0) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_binaries);
        }
        if (logf[pl].exclude != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_exclude);
        }
        if (logf[pl].multiline != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_multiline_regex);
        }
        if (logf[pl].labels != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_label);
        }
        if (logf[pl].ign != DEFAULT_FREQUENCY_SECS) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_frequency);
        }
        if (logf[pl].alias != NULL) {
            mwarn(LOGCOLLECTOR_OPTION_IGNORED, MACOS, xml_localfile_alias);
        }
    }
    /* Verify Multiline Regex Config */
    if (strcmp(logf[pl].logformat, MULTI_LINE_REGEX) == 0) {

        if (logf[pl].multiline == NULL) {
            /* Multiline_regex must be configured */
            merror(MISS_MULT_REGEX);
            return (OS_INVALID);

        } else if (logf[pl].age && logf[pl].age <= logf[pl].multiline->timeout) {
            /* Avoid dismissing an incomplete multiline log */
            mwarn(LOGCOLLECTOR_MULTILINE_AGE_TIMEOUT);
            logf[pl].age = 0;
            os_free(logf[pl].age_str);
        }

    } else if (logf[pl].multiline) {
        /* Only log format multi-line-regex support multiline_regex */
        mwarn(LOGCOLLECTOR_MULTILINE_SUPPORT, logf[pl].logformat);
        w_free_expression_t(&logf[pl].multiline->regex);
        os_free(logf[pl].multiline);
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

            os_realloc(log_config->globs, (gl + 2)*sizeof(logreader_glob), log_config->globs);
            os_strdup(logf[pl].file, log_config->globs[gl].gpath);
            memset(&log_config->globs[gl + 1], 0, sizeof(logreader_glob));
            os_calloc(1, sizeof(logreader), log_config->globs[gl].gfiles);
            memcpy(log_config->globs[gl].gfiles, &logf[pl], sizeof(logreader));
            logf[pl].multiline = NULL; // Prevent freeing the multiline config in Remove_Localfile
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
                return (OS_INVALID);
            }
            log_config->config = logf;
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
                logf[pl].multiline = NULL; // Prevent freeing the multiline config in Remove_Localfile
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

    /* post processing stage */
    // Merge multi configurations of journald log
    if (logf[pl].journal_log != NULL) {
        bool res = w_logreader_journald_merge(&(log_config->config), pl);
        if (res) {
            minfo("Merge journald log configurations");
        }
    }

    return (0);
}

int Test_Localfile(const char * path){
    int fail = 0;
    logreader_config test_localfile = { .agent_cfg = 0 };

    if (ReadConfig(CAGENT_CONFIG | CLOCALFILE | CLGCSOCKET, path, &test_localfile, NULL) < 0) {
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

void w_clean_logreader(logreader * logf) {

    if (logf != NULL) {
        Free_Logreader(logf);
        memset(logf, 0, sizeof(logreader));
    }
}

void Free_Logreader(logreader * logf) {
    int i;

    if (logf) {
        os_free(logf->ffile);
        os_free(logf->file);
        os_free(logf->logformat);
        w_multiline_log_config_free(&(logf->multiline));
        w_macos_log_config_free(&(logf->macos_log));
        w_journal_log_config_free(&(logf->journal_log));
        os_free(logf->djb_program_name);
        os_free(logf->channel_str);
        os_free(logf->alias);
        os_free(logf->query);
        os_free(logf->exclude);
        os_free(logf->query_level);

        if (logf->regex_ignore) {
            OSList_Destroy(logf->regex_ignore);
            logf->regex_ignore = NULL;
        }
        if (logf->regex_restrict) {
            OSList_Destroy(logf->regex_restrict);
            logf->regex_restrict = NULL;
        }

        if (logf->target) {
            for (i = 0; logf->target[i]; i++) {
                free(logf->target[i]);
            }

            free(logf->target);
        }

        os_free(logf->log_target);

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
                // If is a glob entry and multiline is set, we need to free the multiline config
                w_multiline_log_config_free(&(*logf)[i].multiline);
                if((*logf)[i].fp) {
                    fclose((*logf)[i].fp);
                }
            #ifdef WIN32
                if ((*logf)[i].h && (*logf)[i].h != INVALID_HANDLE_VALUE) {
                    CloseHandle((*logf)[i].h);
                }
                pthread_mutex_destroy(&(*logf)[i].mutex);
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

w_multiline_match_type_t w_get_attr_match(xml_node * node) {

    const char * xml_attr_name = "match";

    /* default value */
    w_multiline_match_type_t retval = ML_MATCH_START;
    const char * str_match = w_get_attr_val_by_name(node, xml_attr_name);

    if (str_match == NULL) {
        return retval;
    }

    if (strcasecmp(str_match, multiline_attr_match_str(ML_MATCH_START)) == 0) {
        retval = ML_MATCH_START;
    } else if (strcasecmp(str_match, multiline_attr_match_str(ML_MATCH_ALL)) == 0) {
        retval = ML_MATCH_ALL;
    } else if (strcasecmp(str_match, multiline_attr_match_str(ML_MATCH_END)) == 0) {
        retval = ML_MATCH_END;
    } else {
        mwarn(LOGCOLLECTOR_INV_VALUE_DEFAULT, str_match, xml_attr_name, "multiline_regex");
    }

    return retval;
}

w_multiline_replace_type_t w_get_attr_replace(xml_node * node) {

    const char * xml_attr_name = "replace";

    /* default value */
    w_multiline_replace_type_t retval = ML_REPLACE_NO_REPLACE;
    const char * str_replace = w_get_attr_val_by_name(node, xml_attr_name);

    if (str_replace == NULL) {
        return retval;
    }

    if (strcasecmp(str_replace, multiline_attr_replace_str(ML_REPLACE_NO_REPLACE)) == 0) {
        retval = ML_REPLACE_NO_REPLACE;
    } else if (strcasecmp(str_replace, multiline_attr_replace_str(ML_REPLACE_WSPACE)) == 0) {
        retval = ML_REPLACE_WSPACE;
    } else if (strcasecmp(str_replace, multiline_attr_replace_str(ML_REPLACE_TAB)) == 0) {
        retval = ML_REPLACE_TAB;
    } else if (strcasecmp(str_replace, multiline_attr_replace_str(ML_REPLACE_NONE)) == 0) {
        retval = ML_REPLACE_NONE;
    } else {
        mwarn(LOGCOLLECTOR_INV_VALUE_DEFAULT, str_replace, xml_attr_name, "multiline_regex");
    }

    return retval;
}

unsigned int w_get_attr_timeout(xml_node * node) {

    const char * xml_attr_name = "timeout";

    /* default value: 1 seg */
    unsigned int retval = MULTI_LINE_REGEX_TIMEOUT;
    const char * str_timeout = w_get_attr_val_by_name(node, xml_attr_name);
    char * endptr = NULL;

    if (str_timeout == NULL) {
        return retval;
    }

    retval = strtoul(str_timeout, &endptr, 0);
    if (*endptr != '\0' || retval == 0 || retval > MULTI_LINE_REGEX_MAX_TIMEOUT) {
        mwarn(LOGCOLLECTOR_INV_VALUE_DEFAULT, str_timeout, xml_attr_name, "multiline_regex");
        retval = MULTI_LINE_REGEX_TIMEOUT;
    }

    return retval;
}

const char * multiline_attr_replace_str(w_multiline_replace_type_t replace_type) {
    const char * const replace_str[ML_REPLACE_MAX] = {"no-replace", "none", "wspace", "tab"};
    return replace_str[replace_type];
}

const char * multiline_attr_match_str(w_multiline_match_type_t match_type) {
    const char * const match_str[ML_MATCH_MAX] = {"start", "all", "end"};
    return match_str[match_type];
}

void w_multiline_log_config_free(w_multiline_config_t ** config) {
    if (config == NULL || *config == NULL) {
        return;
    }

    if ((*config)->ctxt) {
        os_free((*config)->ctxt->buffer);
        os_free((*config)->ctxt);
    }
    w_free_expression_t(&((*config)->regex));
    os_free((*config));
}

void w_macos_log_config_free(w_macos_log_config_t ** macos_log) {

    if (macos_log == NULL || *macos_log == NULL) {
        return;
    }

    w_free_expression_t(&((*macos_log)->log_start_regex));
    if ((*macos_log)->processes.stream.wfd != NULL) {
        wpclose((*macos_log)->processes.stream.wfd);
    }
    if ((*macos_log)->processes.show.wfd != NULL) {
        wpclose((*macos_log)->processes.show.wfd);
    }
    os_free((*macos_log)->current_settings);
    os_free(*macos_log);
}

w_multiline_config_t* w_multiline_log_config_clone(w_multiline_config_t* config)
{
    if (config == NULL)
    {
        return NULL;
    }

    w_multiline_config_t* new_config = NULL;
    os_calloc(1, sizeof(w_multiline_config_t), new_config);

    new_config->match_type = config->match_type;
    new_config->replace_type = config->replace_type;
    new_config->timeout = config->timeout;

    w_calloc_expression_t(&(new_config->regex), config->regex->exp_type);
    if (!w_expression_compile(new_config->regex, w_expression_get_regex_pattern(config->regex), 0))
    {
        merror_exit("Failed to clone multiline regex"); // Should never happen
    }

    // No clone the context
    new_config->ctxt = NULL;

    return new_config;
}

STATIC int w_logcollector_get_macos_log_type(const char * content) {

    const size_t MAX_ARRAY_SIZE = 64;
    const char * XML_LOCALFILE_QUERY_TYPE_ATTR = "type";
    const char * XML_LOCALFILE_QUERY = "query";
    size_t current = 0;
    int retval = 0;

    char ** type_arr = OS_StrBreak(',', content, MAX_ARRAY_SIZE);

    if (type_arr) {
        while (type_arr[current]) {
            char * config_str = &(type_arr[current])[strspn(type_arr[current], " ")];
            int num_words = w_word_counter(config_str);

            if (num_words == 1) {
                config_str[strcspn(config_str, " ")] = '\0';
            }

            if (strcasecmp(config_str, MACOS_LOG_TYPE_ACTIVITY_STR) == 0) {
                retval |= MACOS_LOG_TYPE_ACTIVITY;
            } else if (strcasecmp(config_str, MACOS_LOG_TYPE_LOG_STR) == 0) {
                retval |= MACOS_LOG_TYPE_LOG;
            } else if (strcasecmp(config_str, MACOS_LOG_TYPE_TRACE_STR) == 0) {
                retval |= MACOS_LOG_TYPE_TRACE;
            } else if (strcasecmp(config_str, "") != 0) {
                mwarn(LOGCOLLECTOR_INV_VALUE_IGNORE, config_str, XML_LOCALFILE_QUERY_TYPE_ATTR, XML_LOCALFILE_QUERY);
            }

            os_free(type_arr[current]);
            current++;
        }

        os_free(type_arr);
    }

    return retval;
}

w_exp_type_t w_check_regex_type(xml_node * node, const char * element) {

    if (node->values[0]) {
        if (strcasecmp(node->values[0], OSREGEX_STR) == 0) {
            return EXP_TYPE_OSREGEX;
        } else if (strcasecmp(node->values[0], OSMATCH_STR) == 0) {
            return EXP_TYPE_OSMATCH;
        } else if (strcasecmp(node->values[0], PCRE2_STR) == 0) {
            return EXP_TYPE_PCRE2;
        }
    }
    mwarn(LOGCOLLECTOR_DEFAULT_REGEX_TYPE, element, node->content);

    return EXP_TYPE_PCRE2;
}

bool init_w_journal_log_config_t(w_journal_log_config_t ** config) {
    if (config == NULL || *config != NULL) {
        return false;
    }

    os_calloc(1, sizeof(w_journal_log_config_t), *config);
    return true;
}

void w_journal_log_config_free(w_journal_log_config_t ** config) {
    if (config == NULL || *config == NULL) {
        return;
    }

    w_journal_filters_list_free((*config)->filters);
    os_free(*config);
}

bool journald_add_condition_to_filter(xml_node * node, w_journal_filter_t ** filter) {
    if (node == NULL || filter == NULL) {
        return false;
    }

    const char * field = w_get_attr_val_by_name(node, "field");
    char * expression = node->content;
    bool ignore_if_missing = false;

    if (field == NULL || *field == '\0') {
        mwarn(LOGCOLLECTOR_JOURNAL_CONFG_EMPTY_FILTER_FIELD);
        return false;
    }
    if (expression == NULL || *expression == '\0') {
        mwarn(LOGCOLLECTOR_JOURNAL_CONFG_EMPTY_FILTER_EXPR);
        return false;
    }

    const char * ignore_if_missing_str = w_get_attr_val_by_name(node, "ignore_if_missing");
    if (ignore_if_missing_str != NULL) {
        if (strcasecmp(ignore_if_missing_str, "yes") == 0) {
            ignore_if_missing = true;
        } else if (strcasecmp(ignore_if_missing_str, "no") != 0) {
            mwarn(LOGCOLLECTOR_INV_VALUE_DEFAULT, ignore_if_missing_str, "ignore_if_missing", "journal");
        }
    }

    if (w_journal_filter_add_condition(filter, field, expression, ignore_if_missing) != 0) {
        mwarn(LOGCOLLECTOR_JOURNAL_CONFG_FILTER_EXP_FAIL, expression, field);
        return false;
    }

    return true;
}

/**
 * @brief Free the unit filter and all its resources
 *
 * The unit pointer is invalid after the call.
 * @param unit Journal filter unit
 */
STATIC void free_unit_filter(_w_journal_filter_unit_t * unit) {
    if (unit == NULL) {
        return;
    }

    os_free(unit->field);
    w_free_expression_t(&(unit->exp));
    os_free(unit);
}

/**
 * @brief Create the filter unit
 * The caller is responsible for freeing the returned unit.
 *
 * @param field The field to filter
 * @param expression The expression to match
 * @param ignore_if_missing Ignore if the field is missing
 * @return The filter unit or NULL if an error occurred (compiling the expression)
 */
STATIC _w_journal_filter_unit_t * create_unit_filter(const char * field, char * expression, bool ignore_if_missing) {
    if (field == NULL || expression == NULL) {
        return NULL;
    }

    _w_journal_filter_unit_t * unit;
    os_calloc(1, sizeof(_w_journal_filter_unit_t), unit);

    w_calloc_expression_t(&(unit->exp), EXP_TYPE_PCRE2);

    if (!w_expression_compile(unit->exp, expression, 0)) {
        free_unit_filter(unit);
        return NULL;
    }

    unit->field = strdup(field);
    unit->ignore_if_missing = ignore_if_missing;

    return unit;
}

void w_journal_filter_free(w_journal_filter_t * ptr_filter) {
    if (ptr_filter == NULL) {
        return;
    }

    if (ptr_filter->units != NULL) {
        for (size_t i = 0; ptr_filter->units[i] != NULL; i++) {
            free_unit_filter(ptr_filter->units[i]);
        }

        os_free(ptr_filter->units);
    }

    os_free(ptr_filter);
}

int w_journal_filter_add_condition(w_journal_filter_t ** ptr_filter, const char * field, char * expression,
                                   bool ignore_if_missing) {
    if (field == NULL || expression == NULL || ptr_filter == NULL) {
        return -1;
    }

    // Crete the unit filter
    _w_journal_filter_unit_t * unit = create_unit_filter(field, expression, ignore_if_missing);
    if (unit == NULL) {
        return -1;
    }

    // If the filter does not exist, create it
    if (*ptr_filter == NULL) {
        os_calloc(1, sizeof(w_journal_filter_t), *ptr_filter);
    }
    w_journal_filter_t * filter = *ptr_filter;

    // Allocate memory for the new unit
    os_realloc(filter->units, (filter->units_size + 2) * sizeof(_w_journal_filter_unit_t *), filter->units);

    // Add the new unit
    filter->units[filter->units_size] = unit;
    filter->units_size++;
    filter->units[filter->units_size] = NULL;

    return 0;
}

bool w_journal_add_filter_to_list(w_journal_filters_list_t * list, w_journal_filter_t * filter) {
    if (list == NULL || filter == NULL) {
        return false;
    }

    // Allocate memory for the new filter
    if (*list == NULL) {
        os_calloc(1, sizeof(w_journal_filter_t *), *list);
    }

    // Determine the size of the list
    size_t size = 0;
    while ((*list)[size] != NULL) {
        size++;
    }

    // Allocate memory for the new filter
    os_realloc(*list, (size + 2) * sizeof(w_journal_filter_t *), *list);

    // Add the new filter
    (*list)[size] = filter;
    (*list)[size + 1] = NULL;

    return true;
}

/**
 * @brief Get the unit filter as JSON object
 *
 * @param unit Unit filter
 * @return STATIC*
 */
STATIC cJSON * unit_filter_as_json(_w_journal_filter_unit_t * unit) {

    if (unit == NULL || unit->field == NULL || unit->exp == NULL || unit->exp->exp_type != EXP_TYPE_PCRE2) {
        return NULL;
    }

    cJSON * json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "field", unit->field);
    cJSON_AddStringToObject(json, "expression", unit->exp->pcre2->raw_pattern);
    cJSON_AddBoolToObject(json, "ignore_if_missing", unit->ignore_if_missing);

    return json;
}

/**
 * @brief Get the filter as a JSON Object
 *
 * @param filter Filter
 * @return cJSON* JSON Object with the filter
 */
STATIC cJSON * filter_as_json(w_journal_filter_t * filter) {
    if (filter == NULL || filter->units == NULL) {
        return NULL;
    }

    cJSON * json = cJSON_CreateArray();
    if (json == NULL) {
        return NULL;
    }

    for (size_t i = 0; filter->units[i] != NULL; i++) {
        cJSON * unit = unit_filter_as_json(filter->units[i]);
        if (unit == NULL) {
            cJSON_Delete(json);
            return NULL;
        }

        cJSON_AddItemToArray(json, unit);
    }

    return json;
}

/**
 * @brief Get the filter as a JSON Array
 *
 * @param filter_lst Filters list
 * @return cJSON* JSON Array with the filters
 */
cJSON * w_journal_filter_list_as_json(w_journal_filters_list_t filter_lst) {
    if (filter_lst == NULL) {
        return NULL;
    }

    cJSON * json = cJSON_CreateArray();
    if (json == NULL) {
        return NULL;
    }

    for (size_t i = 0; filter_lst[i] != NULL; i++) {
        cJSON * filter = filter_as_json(filter_lst[i]);
        if (filter == NULL) {
            cJSON_Delete(json);
            return NULL;
        }

        cJSON_AddItemToArray(json, filter);
    }

    return json;

}

void w_journal_filters_list_free(w_journal_filters_list_t list) {
    if (list == NULL) {
        return;
    }

    for (size_t i = 0; list[i] != NULL; i++) {
        w_journal_filter_free(list[i]);
    }

    os_free(list);
}

bool w_logreader_journald_merge(logreader ** logf_ptr, size_t src_index) {
    if (logf_ptr == NULL || *logf_ptr == NULL || src_index == 0) {
        return false;
    }

    logreader * logr = *logf_ptr;

    /* Check if src_index is in range and if it is a journald log reader */
    size_t i = 0;
    for (; logr[i].file != NULL; i++) {
        if (i == src_index) {
            break;
        }
    }
    if (logr[i].journal_log == NULL) {
        return false;
    }

    /* Search the first journald log reader, destination */
    bool dst_found = false;
    size_t dst_index = 0;
    for (dst_index = 0; logr[dst_index].file != NULL && dst_index < src_index; dst_index++) {
        if (logr[dst_index].journal_log != NULL) {
            dst_found = true;
            break;
        }
    }

    if (!dst_found) {
        return false;
    }

    /* Merge the filters */
    bool src_has_filters = logr[src_index].journal_log->filters != NULL
                           && logr[src_index].journal_log->filters[0] != NULL;
    bool dst_has_filters = logr[dst_index].journal_log->filters != NULL
                           && logr[dst_index].journal_log->filters[0] != NULL;

    // Disable filter is already disabled or if any don't have filters
    if (!src_has_filters || !dst_has_filters) {
        logr[dst_index].journal_log->disable_filters = true;
        mwarn(LOGCOLLECTOR_JOURNAL_CONFG_DISABLE_FILTER);
    }

    // Move the filters from the src_index to the dst_index
    if (src_has_filters) {
        w_journal_add_filter_to_list(&(logr[dst_index].journal_log->filters), logr[src_index].journal_log->filters[0]);
        logr[src_index].journal_log->filters[0] = NULL; // Prevent the filter from being freed
    }

    // Replace the only future event with last configuration
    logr[dst_index].future = logr[src_index].future;

    // Move the target with the last configuration
    if (logr[dst_index].target) {
        for (i = 0; logr[dst_index].target[i]; i++) {
            os_free(logr[dst_index].target[i]);
        }
        os_free(logr[dst_index].target);
    }
    logr[dst_index].target = logr[src_index].target;
    logr[src_index].target = NULL;

    /* Remove the src_index log reader */
    Remove_Localfile(logf_ptr, (int) src_index, 0, true, NULL);

    return true;
}
