/* Copyright (C) 2010 Trend Micro Inc.
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
void *read_fullcommand(int pos, int *rc, int drop_it)
{
    size_t n = 0;
    size_t cmd_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char strfinal[OS_MAXSTR + 1];
    FILE *cmd_output;

    str[OS_MAXSTR] = '\0';
    strfinal[OS_MAXSTR] = '\0';
    *rc = 0;

    debug2("%s: DEBUG: Running full command '%s'", ARGV0, logff[pos].command);

    cmd_output = popen(logff[pos].command, "r");
    if (!cmd_output) {
        merror("%s: ERROR: Unable to execute command: '%s'.",
               ARGV0, logff[pos].command);

        logff[pos].command = NULL;
        return (NULL);
    }

    snprintf(str, 256, "ossec: output: '%s':\n",
             (NULL != logff[pos].alias)
             ? logff[pos].alias
             : logff[pos].command);
    cmd_size = strlen(str);

    n = fread(str + cmd_size, 1, OS_MAXSTR - OS_LOG_HEADER - 256, cmd_output);
    if (n > 0) {
        str[cmd_size + n] = '\0';

        /* Get the last occurence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

        debug2("%s: DEBUG: Reading command message: '%s'", ARGV0, str);

        /* Remove empty lines */
        n = 0;
        p = str;
        while (*p != '\0') {
            if (p[0] == '\r') {
                p++;
                continue;
            }

            if (p[0] == '\n' && p[1] == '\n') {
                p++;
            }
            strfinal[n] = *p;
            n++;
            p++;
        }
        strfinal[n] = '\0';

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSG(logr_queue, strfinal,
                        (NULL != logff[pos].alias) ? logff[pos].alias : logff[pos].command,
                        LOCALFILE_MQ) < 0) {
                merror(QUEUE_SEND, ARGV0);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }
    }

    pclose(cmd_output);

    return (NULL);
}

