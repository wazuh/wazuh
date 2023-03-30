/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "active_responses.h"
#include "dll_load_notify.h"

#define RULE_NAME "WAZUH ACTIVE RESPONSE BLOCKED IP"
#define NETSH "C:\\Windows\\System32\\netsh.exe"

int main (int argc, char **argv) {
    // This must be always the first instruction
    enable_dll_verification();

    (void)argc;
    char log_msg[OS_MAXSTR];
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

    char name[OS_MAXSTR -1];
    char remoteip[OS_MAXSTR -1];

    snprintf(name, OS_MAXSTR -1, "name=\"%s\"", RULE_NAME);
    snprintf(remoteip, OS_MAXSTR -1, "remoteip=%s/32", srcip);

    char *exec_args_add[11] = { NETSH, "advfirewall", "firewall", "add", "rule", name, "interface=any", "dir=in", "action=block", remoteip, NULL };
    char *exec_args_delete[8] = { NETSH, "advfirewall", "firewall", "delete", "rule", name, remoteip, NULL };

    wfd_t *wfd = wpopenv(NETSH, (action == ADD_COMMAND) ? exec_args_add : exec_args_delete, W_BIND_STDERR);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: '%s', rule: '%s'", (action == ADD_COMMAND) ? "ADD" : "DELETE", RULE_NAME);
        write_debug_file(argv[0], log_msg);
    }
    else {
        wpclose(wfd);
    }

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}

#endif
