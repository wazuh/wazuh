/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define ROUTE "route"

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

#ifndef WIN32
    struct utsname uname_buffer;
    wfd_t *wfd = NULL;

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        if (action == ADD_COMMAND) {
            char *exec_cmd1[5] = { NULL, NULL, NULL, NULL, NULL };

            const char *arg1[5] = { ROUTE, "add", srcip, "reject", NULL };
            memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

            wfd = wpopenv(ROUTE, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[5] = { NULL, NULL, NULL, NULL, NULL };

            const char *arg1[5] = { ROUTE, "del", srcip, "reject", NULL };
            memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

            wfd = wpopenv(ROUTE, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        if (action == ADD_COMMAND) {
            char *exec_cmd1[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };

            const char *arg1[7] = { ROUTE, "-q", "add", srcip, "127.0.0.1", "-blackhole", NULL };
            memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

            wfd = wpopenv(ROUTE, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };

            const char *arg1[7] = { ROUTE, "-q", "delete", srcip, "127.0.0.1", "-blackhole", NULL };
            memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

            wfd = wpopenv(ROUTE, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else {
        write_debug_file(argv[0], "Invalid system");
    }
#else
    if (action == ADD_COMMAND) {
        const char *regex = ".*Default Gateway.*[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*";
        const char *tmp_file = "default-gateway.txt";
        char *gateway = NULL;

        char cmd[OS_MAXSTR + 1];
        snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\ipconfig.exe | %%WINDIR%%\\system32\\findstr.exe /R /C:\"%s\" > %s", regex, tmp_file);
        system(cmd);

        FILE *fp = fopen(tmp_file, "r");
        if(fp != NULL) {
            char output_buf[OS_MAXSTR];
            while (fgets(output_buf, OS_MAXSTR, fp)) {
                char *ptr = strchr(output_buf, ':');
                if (ptr != NULL) {
                    os_free(gateway);
                    os_strdup(ptr+1, gateway);
                }
            }
            fclose(fp);
        }
        remove(tmp_file);

        if (gateway) {
            snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\route.exe -p ADD %s MASK 255.255.255.255 %s", srcip, gateway);
            system(cmd);
            os_free(gateway);
        } else {
            write_debug_file(argv[0], "Couldn't get default gateway");
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
    } else {
        char cmd[OS_MAXSTR + 1];
		snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\route.exe DELETE %s", srcip);
        system(cmd);
    }
#endif

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}
