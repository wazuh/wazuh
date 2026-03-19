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
    char *args = strchr(command, ' ');
    if (args) {
        *args = '\0';
        args++;
    }

    if (strcmp(command, "restart") == 0) {
        mdebug1("Restarting Wazuh agent service via control.");
        os_stop_service();
        os_start_service();
        os_strdup("ok ", *output);
        return strlen(*output);

    } else if (strcmp(command, "reload") == 0) {
        mdebug1("Reloading Wazuh agent service via control.");
        os_stop_service();
        os_start_service();
        os_strdup("ok ", *output);
        return strlen(*output);

    } else {
        mdebug1("CONTROL: Unrecognized command '%s'.", command);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

#endif /* WIN32 */
