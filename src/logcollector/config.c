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


/* Read the config file (the localfiles) */
int LogCollectorConfig(const char *cfgfile)
{
    int modules = 0;
    logreader_config log_config;

    modules |= CLOCALFILE;
    modules |= CSOCKET;

    log_config.config = NULL;
    log_config.socket_list = NULL;
    log_config.agent_cfg = 0;
    log_config.accept_remote = getDefine_Int("logcollector", "remote_commands", 0, 1);

    /* Get loop timeout */
    loop_timeout = getDefine_Int("logcollector", "loop_timeout", 1, 120);
    open_file_attempts = getDefine_Int("logcollector", "open_attempts", 2, 998);
    vcheck_files = getDefine_Int("logcollector", "vcheck_files", 0, 1024);
    maximum_lines = getDefine_Int("logcollector", "max_lines", 0, 1000000);

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
    logsk = log_config.socket_list;

    // List readed sockets
    unsigned int sk;
    for (sk=0; logsk && logsk[sk].name; sk++) {
        mdebug1("Socket '%s' (%s) added. Location: %s", logsk[sk].name, logsk[sk].mode == UDP_PROTO ? "udp" : "tcp", logsk[sk].location);
    }

    // Check sockets
    if (logff) {
        int i, j, k;
        for (i=0;logff[i].file;i++) {
            for (j=0;logff[i].target[j];j++) {
                if (strcmp(logff[i].target[j], "agent") == 0) {
                    logff[i].target_socket[j] = &default_agent;
                    continue;
                }
                int found = -1;
                for (k=0;logsk && logsk[k].name;k++) {
                    found = strcmp(logsk[k].name, logff[i].target[j]);
                    if (found == 0) {
                        break;
                    }
                }
                if (found != 0) {
                    merror_exit("Socket '%s' for '%s' is not defined.", logff[i].target[j], logff[i].file);
                } else {
                    logff[i].target_socket[j] = &logsk[k];
                }
            }
        }
    }

    /* Remove duplicate entries */
    int i, r, count_localfiles = 0;
    for (i = 0;; i++) {
        if (logff[i].file == NULL) {
            break;
        }
        for (r = 0; r < i; r++) {
            if (logff[r].file && strcmp(logff[i].file, logff[r].file) == 0) {
                mwarn("Duplicated log file given: '%s'.", logff[i].file);
                logff[r].duplicated = 1;
                count_localfiles--;
                break;
            }
        }
        count_localfiles++;
    }
    mdebug1("Added %i valid 'localfile' entries.", count_localfiles);

    return (1);
}
