/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#ifndef WIN32
#define LOG_FILE "/logs/active-responses.log"
#else
#define LOG_FILE "active-response\\active-responses.log"
#endif

#define BUFFERSIZE 4096
#define LOGSIZE 5120
#define PATHSIZE 512

void write_debug_file(const char *msg);

int main (void) {
    char input[BUFFERSIZE];
	char log_msg[LOGSIZE];
	char *action = NULL;
	cJSON *input_json = NULL;
	cJSON *command_json = NULL;
	const char *json_err;
	int ret = OS_SUCCESS;

	write_debug_file("Executing 'restart-ossec' program");

	// Reading input
    input[BUFFERSIZE-1] = '\0';
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file("Cannot read input from stdin");
        return OS_INVALID;
    }

	log_msg[LOGSIZE-1] = '\0';
	snprintf(log_msg, LOGSIZE-1 , "Input received: %s", input);
	write_debug_file(log_msg);

	// Parsing Input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        write_debug_file("Cannot parse input to json");
        return OS_INVALID;
    }

	// Detecting command
    command_json = cJSON_GetObjectItem(input_json, "command");
    if (command_json && (command_json->type == cJSON_String)) {
        os_strdup(command_json->valuestring, action);
    } else {
        write_debug_file("Invalid 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

	if (strcmp("add", action) == 0) {
#ifndef WIN32
		char *exec_cmd[3] = { DEFAULTDIR "/bin/wazuh-control", "restart", NULL};

		if (isChroot()) {
			strcpy(exec_cmd[0], "/bin/wazuh-control");
		}

		if (execv(exec_cmd[0], exec_cmd) < 0) {
			log_msg[LOGSIZE-1] = '\0';
			snprintf(log_msg, LOGSIZE-1 , "Error executing '%s': %s", *exec_cmd, strerror(errno));
			write_debug_file(log_msg);
			ret = OS_INVALID;
		}
#else
        char cmd[OS_MAXSTR + 1];

		snprintf(cmd, OS_MAXSTR, "net stop Wazuh");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "net start Wazuh");
        system(cmd);
#endif
	} else if (strcmp("delete", action) != 0) {
        write_debug_file("Invalid value of 'command'");
        ret = OS_INVALID;
    }

	cJSON_Delete(input_json);
	os_free(action);

    return ret;
}

void write_debug_file(const char *msg) {
    char path[PATHSIZE];
    char *timestamp = w_get_timestamp(time(NULL));

#ifndef WIN32
    snprintf(path, PATHSIZE, "%s%s", isChroot() ? "" : DEFAULTDIR, LOG_FILE);
#else
    snprintf(path, PATHSIZE, "%s", LOG_FILE);
#endif

    FILE *ar_log_file = fopen(path, "a");

    fprintf(ar_log_file, "%s: %s\n", timestamp, msg);
    fclose(ar_log_file);
}
