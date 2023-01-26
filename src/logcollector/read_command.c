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


/* Read Output of commands */
void *read_command(logreader *lf, int *rc, int drop_it) {
    size_t cmd_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    FILE *cmd_output;
    int lines = 0;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    mdebug2("Running command '%s'", lf->command);

    cmd_output = popen(lf->command, "r");
    if (!cmd_output) {
        merror("Unable to execute command: '%s'.",
               lf->command);

        lf->command = NULL;
        return (NULL);
    }

    snprintf(str, 256, "ossec: output: '%s': ",
             (NULL != lf->alias)
             ? lf->alias
             : lf->command);
    cmd_size = strlen(str);

    while (can_read() && fgets(str + cmd_size, OS_MAXSTR - OS_LOG_HEADER - 256, cmd_output) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

        /* Remove empty lines */
#ifdef WIN32
        if (str[0] == '\r' && str[1] == '\0') {
            continue;
        }
#endif
        if (str[0] == '\0') {
            continue;
        }

        /* Check ignore and restrict log regex, if configured. */
        if (check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, str)) {
            continue;
        }

        mdebug2("Reading command message: '%s'", str);

        /* Send message to queue */
        if (drop_it == 0) {
            w_msg_hash_queues_push(str, lf->alias ? lf->alias : lf->command, strlen(str) + 1, lf->log_target, LOCALFILE_MQ);
        }

        continue;
    }

    pclose(cmd_output);

    mdebug2("Read %d lines from command '%s'", lines, lf->command);
    return (NULL);
}
