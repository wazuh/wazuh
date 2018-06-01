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

    log_config.config = NULL;
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

    return (1);
}
