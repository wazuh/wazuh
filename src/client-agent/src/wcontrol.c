/* Agent control command dispatcher (Windows)
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include <shared.h>
#include "agentd.h"

size_t control_dispatch(char *command, char **output) {
    char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))) {
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "restart") == 0) {
        mdebug1("Restarting Wazuh agent service via control.");
        os_stop_service();
        os_start_service();
        os_strdup("ok ", *output);
        return strlen(*output);

    } else if (strcmp(rcv_comm, "reload") == 0) {
        mdebug1("Reloading Wazuh agent service via control.");
        os_stop_service();
        os_start_service();
        os_strdup("ok ", *output);
        return strlen(*output);

    } else {
        mdebug1("CONTROL: Unrecognized command '%s'.", rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

#endif /* WIN32 */
