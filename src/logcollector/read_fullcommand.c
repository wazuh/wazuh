/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
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
void *read_fullcommand(logreader *lf, int *rc, int drop_it) {
   size_t n = 0;
    size_t cmd_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char strfinal[OS_MAXSTR + 1];
    FILE *cmd_output;

    str[OS_MAXSTR] = '\0';
    strfinal[OS_MAXSTR] = '\0';
    *rc = 0;

    mdebug2("Running full command '%s'", lf->command);

    cmd_output = popen(lf->command, "r");
    if (!cmd_output) {
        merror("Unable to execute command: '%s'.",
               lf->command);

        lf->command = NULL;
        return (NULL);
    }

    snprintf(str, 256, "ossec: output: '%s':\n",
             (NULL != lf->alias)
             ? lf->alias
             : lf->command);
    cmd_size = strlen(str);

    n = fread(str + cmd_size, 1, OS_MAXSTR - OS_LOG_HEADER - 256, cmd_output);
    if (n > 0) {
        str[cmd_size + n] = '\0';

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

        mdebug2("Reading command message: '%s'", str);

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
            w_msg_hash_queues_push(strfinal, lf->alias ? lf->alias : lf->command, strlen(strfinal) + 1, lf->log_target, LOCALFILE_MQ);
        }
    }

    pclose(cmd_output);

    return (NULL);
}
