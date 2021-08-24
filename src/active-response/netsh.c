/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "active_responses.h"

#define RULE_NAME "WAZUH ACTIVE RESPONSE BLOCKED IP"

int main (int argc, char **argv) {
    (void)argc;
    int action = OS_INVALID;
    cJSON *input_json = NULL;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get srcip
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (action == ADD_COMMAND) {
        char **keys = NULL;
        int action2 = OS_INVALID;

        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);

        os_free(keys);

        // If necessary, abort execution
        if (action2 != CONTINUE_COMMAND) {
            cJSON_Delete(input_json);

            if (action2 == ABORT_COMMAND) {
                write_debug_file(argv[0], "Aborted");
                return OS_SUCCESS;
            } else {
                return OS_INVALID;
            }
        }
    }

    if (action == ADD_COMMAND) {
        char cmd[OS_MAXSTR + 1];
		snprintf(cmd, OS_MAXSTR, "netsh advfirewall firewall add rule name=\"%s\" interface=any dir=in action=block remoteip=%s/32", RULE_NAME, srcip);
        system(cmd);
    } else {
        char cmd[OS_MAXSTR + 1];
		snprintf(cmd, OS_MAXSTR, "netsh advfirewall firewall delete rule name=\"%s\" remoteip=%s/32", RULE_NAME, srcip);
        system(cmd);
    }

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}

#endif
