/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "active_responses.h"

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
	char *action = NULL;
	cJSON *input_json = NULL;
	int ret = OS_SUCCESS;

    write_debug_file(argv[0] , "Starting");

    memset(input, '\0', BUFFERSIZE);
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0] , input);

	input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(argv[0], "Invalid input format");
        return OS_INVALID;
    }

    action = get_command(input_json);
    if (!action) {
        write_debug_file(argv[0], "Cannot read 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file(argv[0], "Invalid value of 'command'");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

	if (strcmp("add", action) == 0) {
#ifndef WIN32
	    char log_msg[LOGSIZE];
		char *exec_cmd[3] = { DEFAULTDIR "/bin/wazuh-control", "restart", NULL};

		if (isChroot()) {
			strcpy(exec_cmd[0], "/bin/wazuh-control");
		}

		if (execv(exec_cmd[0], exec_cmd) < 0) {
            memset(log_msg, '\0', LOGSIZE);
			snprintf(log_msg, LOGSIZE-1 , "Error executing '%s': %s", *exec_cmd, strerror(errno));
			write_debug_file(argv[0], log_msg);
			ret = OS_INVALID;
		}
#else
        char cmd[OS_MAXSTR + 1];

		snprintf(cmd, OS_MAXSTR, "net stop Wazuh");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "net start Wazuh");
        system(cmd);
#endif
	}

	cJSON_Delete(input_json);
	os_free(action);

    return ret;
}
