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


/* Read Output of commands */
void *read_command(int pos, int *rc, int drop_it)
{
    size_t cmd_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    FILE *cmd_output;
    int lines = 0;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    mdebug2("Running command '%s'", logff[pos].command);

    cmd_output = popen(logff[pos].command, "r");
    if (!cmd_output) {
        merror("Unable to execute command: '%s'.",
               logff[pos].command);

        logff[pos].command = NULL;
        return (NULL);
    }

    snprintf(str, 256, "ossec: output: '%s': ",
             (NULL != logff[pos].alias)
             ? logff[pos].alias
             : logff[pos].command);
    cmd_size = strlen(str);

    while (fgets(str + cmd_size, OS_MAXSTR - OS_LOG_HEADER - 256, cmd_output) != NULL && (!maximum_lines || lines < maximum_lines)) {

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

        mdebug2("Reading command message: '%s'", str);

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSGtoSCK(logr_queue, str,
                        (NULL != logff[pos].alias) ? logff[pos].alias : logff[pos].command,
                        LOCALFILE_MQ, logff[pos].log_target) < 0) {
                merror(QUEUE_SEND);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    merror_exit(QUEUE_FATAL, DEFAULTQPATH);
                }
            }
        }

        continue;
    }

    pclose(cmd_output);

    mdebug2("Read %d lines from command '%s'", lines, logff[pos].command);
    return (NULL);
}
