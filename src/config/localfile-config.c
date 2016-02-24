/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "localfile-config.h"
#include "config.h"


int Read_Localfile(XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    unsigned int pl = 0;
    unsigned int i = 0;
    unsigned int glob_set = 0;
#ifndef WIN32
    int glob_offset = 0;
#endif

    /* XML Definitions */
    const char *xml_localfile_location = "location";
    const char *xml_localfile_command = "command";
    const char *xml_localfile_logformat = "log_format";
    const char *xml_localfile_frequency = "frequency";
    const char *xml_localfile_alias = "alias";
    const char *xml_localfile_future = "only-future-events";
    const char *xml_localfile_query = "query";

    logreader *logf;
    logreader_config *log_config;

    log_config = (logreader_config *)d1;

    /* If config is not set, create it */
    if (!log_config->config) {
        os_calloc(2, sizeof(logreader), log_config->config);
        logf = log_config->config;
        logf[0].file = NULL;
        logf[0].command = NULL;
        logf[0].alias = NULL;
        logf[0].logformat = NULL;
        logf[0].future = 0;
        logf[0].query = NULL;
        logf[1].file = NULL;
        logf[1].command = NULL;
        logf[1].alias = NULL;
        logf[1].logformat = NULL;
        logf[1].future = 0;
        logf[1].query = NULL;
    } else {
        logf = log_config->config;
        while (logf[pl].file != NULL) {
            pl++;
        }

        /* Allocate more memory */
        os_realloc(logf, (pl + 2)*sizeof(logreader), log_config->config);
        logf = log_config->config;
        logf[pl + 1].file = NULL;
        logf[pl + 1].command = NULL;
        logf[pl + 1].alias = NULL;
        logf[pl + 1].logformat = NULL;
        logf[pl + 1].future = 0;
        logf[pl + 1].query = NULL;
    }

    logf[pl].file = NULL;
    logf[pl].command = NULL;
    logf[pl].alias = NULL;
    logf[pl].logformat = NULL;
    logf[pl].future = 0;
    logf[pl].query = NULL;
    logf[pl].fp = NULL;
    logf[pl].ffile = NULL;
    logf[pl].djb_program_name = NULL;
    logf[pl].ign = 360;


    /* Search for entries related to files */
    i = 0;
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, __local_name, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_localfile_future) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logf[pl].future = 1;
            }
        } else if (strcmp(node[i]->element, xml_localfile_query) == 0) {
            os_strdup(node[i]->content, logf[pl].query);
        } else if (strcmp(node[i]->element, xml_localfile_command) == 0) {
            /* We don't accept remote commands from the manager - just in case */
            if (log_config->agent_cfg == 1 && log_config->accept_remote == 0) {
                merror("%s: Remote commands are not accepted from the manager. "
                       "Ignoring it on the agent.conf", __local_name);

                logf[pl].file = NULL;
                logf[pl].ffile = NULL;
                logf[pl].command = NULL;
                logf[pl].alias = NULL;
                logf[pl].logformat = NULL;
                logf[pl].fp = NULL;
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, logf[pl].file);
            logf[pl].command = logf[pl].file;
        } else if (strcmp(node[i]->element, xml_localfile_frequency) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            logf[pl].ign = atoi(node[i]->content);
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

            /* This is a glob*
             * We will call this file multiple times until
             * there is no one else available.
             */
#ifndef WIN32 /* No windows support for glob */
            if (strchr(node[i]->content, '*') ||
                    strchr(node[i]->content, '?') ||
                    strchr(node[i]->content, '[')) {
                glob_t g;

                /* Setting to the first entry of the glob */
                if (glob_set == 0) {
                    glob_set = pl + 1;
                }

                if (glob(node[i]->content, 0, NULL, &g) != 0) {
                    merror(GLOB_ERROR, __local_name, node[i]->content);
                    os_strdup(node[i]->content, logf[pl].file);
                    i++;
                    continue;
                }

                /* Check for the last entry */
                if ((g.gl_pathv[glob_offset]) == NULL) {
                    /* Check when nothing is found */
                    if (glob_offset == 0) {
                        merror(GLOB_NFOUND, __local_name, node[i]->content);
                        return (OS_INVALID);
                    }
                    i++;
                    continue;
                }


                while(g.gl_pathv[glob_offset] != NULL)
                {
                    /* Check for strftime on globs too */
                    if (strchr(g.gl_pathv[glob_offset], '%')) {
                        struct tm *p;
                        time_t l_time = time(0);
                        char lfile[OS_FLSIZE + 1];
                        size_t ret;

                        p = localtime(&l_time);

                        lfile[OS_FLSIZE] = '\0';
                        ret = strftime(lfile, OS_FLSIZE, g.gl_pathv[glob_offset], p);
                        if (ret == 0) {
                            merror(PARSE_ERROR, __local_name, g.gl_pathv[glob_offset]);
                            return (OS_INVALID);
                        }

                        os_strdup(g.gl_pathv[glob_offset], logf[pl].ffile);
                        os_strdup(g.gl_pathv[glob_offset], logf[pl].file);
                    } else {
                        os_strdup(g.gl_pathv[glob_offset], logf[pl].file);
                    }

                    glob_offset++;

                    /* Now we need to create another file entry */
                    pl++;
                    os_realloc(logf, (pl +2)*sizeof(logreader), log_config->config);
                    logf = log_config->config;

                    logf[pl].file = NULL;
                    logf[pl].alias = NULL;
                    logf[pl].logformat = NULL;
                    logf[pl].fp = NULL;
                    logf[pl].ffile = NULL;

                    logf[pl +1].file = NULL;
                    logf[pl +1].alias = NULL;
                    logf[pl +1].logformat = NULL;
                }


                globfree(&g);
            } else if (strchr(node[i]->content, '%'))
            #else
            if (strchr(node[i]->content, '%'))
            #endif /* WIN32 */

            /* We need the format file (based on date) */
            {
                struct tm *p;
                time_t l_time = time(0);
                char lfile[OS_FLSIZE + 1];
                size_t ret;

                p = localtime(&l_time);

                lfile[OS_FLSIZE] = '\0';
                ret = strftime(lfile, OS_FLSIZE, node[i]->content, p);
                if (ret != 0) {
                    os_strdup(node[i]->content, logf[pl].ffile);
                }

                os_strdup(node[i]->content, logf[pl].file);
            }

            /* Normal file */
            else {
                os_strdup(node[i]->content, logf[pl].file);
            }
        }

        /* Get log format */
        else if (strcasecmp(node[i]->element, xml_localfile_logformat) == 0) {
            os_strdup(node[i]->content, logf[pl].logformat);

            if (strcmp(logf[pl].logformat, "syslog") == 0) {
            } else if (strcmp(logf[pl].logformat, "generic") == 0) {
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
            } else if (strncmp(logf[pl].logformat, "multi-line", 10) == 0) {
                int x = 0;
                logf[pl].logformat += 10;

                while (logf[pl].logformat[0] == ' ') {
                    logf[pl].logformat++;
                }

                if (logf[pl].logformat[0] != ':') {
                    merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
                logf[pl].logformat++;

                while (*logf[pl].logformat == ' ') {
                    logf[pl].logformat++;
                }

                while (logf[pl].logformat[x] >= '0' && logf[pl].logformat[x] <= '9') {
                    x++;
                }

                while (logf[pl].logformat[x] == ' ') {
                    x++;
                }

                if (logf[pl].logformat[x] != '\0') {
                    merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            } else if (strcmp(logf[pl].logformat, EVENTLOG) == 0) {
            } else if (strcmp(logf[pl].logformat, EVENTCHANNEL) == 0) {
            } else {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_localfile_alias) == 0) {
            os_strdup(node[i]->content, logf[pl].alias);
        } else {
            merror(XML_INVELEM, __local_name, node[i]->element);
            return (OS_INVALID);
        }

        i++;
    }

    /* Validate glob entries */
    if (glob_set) {
        char *format;

        /* Get log format */
        if (logf[pl].logformat) {
            format = logf[pl].logformat;
        } else if (logf[glob_set - 1].logformat) {
            format = logf[glob_set - 1].logformat;
        } else {
            merror(MISS_LOG_FORMAT, __local_name);
            return (OS_INVALID);
        }

        /* The last entry is always null on glob */
        pl--;

        /* Set format for all entries */
        for (i = (glob_set - 1); i <= pl; i++) {
            /* Every entry must be valid */
            if (!logf[i].file) {
                merror(MISS_FILE, __local_name);
                return (OS_INVALID);
            }

            if (logf[i].logformat == NULL) {
                logf[i].logformat = format;
            }

        }
    }

    /* Missing log format */
    if (!logf[pl].logformat) {
        merror(MISS_LOG_FORMAT, __local_name);
        return (OS_INVALID);
    }

    /* Missing file */
    if (!logf[pl].file) {
        merror(MISS_FILE, __local_name);
        return (OS_INVALID);
    }

    /* Verify a valid event log config */
    if (strcmp(logf[pl].logformat, EVENTLOG) == 0) {
        if ((strcmp(logf[pl].file, "Application") != 0) &&
                (strcmp(logf[pl].file, "System") != 0) &&
                (strcmp(logf[pl].file, "Security") != 0)) {
            /* Invalid event log */
            merror(NSTD_EVTLOG, __local_name, logf[pl].file);
            return (0);
        }
    }

    if ((strcmp(logf[pl].logformat, "command") == 0) ||
            (strcmp(logf[pl].logformat, "full_command") == 0)) {
        if (!logf[pl].command) {
            merror("%s: ERROR: Missing 'command' argument. "
                   "This option will be ignored.", __local_name);
        }
    }

    return (0);
}

