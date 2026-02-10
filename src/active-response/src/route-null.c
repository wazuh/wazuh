/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"
#include "dll_load_notify.h"

int main (int argc, char **argv) {
#ifdef WIN32
    // This must be always the first instruction
    enable_dll_verification();
#endif

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
    char *route_path = NULL;
    char log_msg[OS_MAXSTR];

    if (get_binary_path("route", &route_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", route_path);
        write_debug_file(argv[0], log_msg);
    }

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        os_free(route_path);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        if (action == ADD_COMMAND) {
            char *exec_cmd1[5] = { route_path, "add", (char *)srcip, "reject", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[5] = { route_path, "del", (char *)srcip, "reject", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        if (action == ADD_COMMAND) {
            char *exec_cmd1[7] = { route_path, "-q", "add", (char *)srcip, "127.0.0.1", "-blackhole", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[7] = { route_path, "-q", "delete", (char *)srcip, "127.0.0.1", "-blackhole", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else {
        write_debug_file(argv[0], "Invalid system");
    }
    os_free(route_path);
#else
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;

    if (get_binary_path("route.exe", &route_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", route_path);
        write_debug_file(argv[0], log_msg);
    }

    if (action == ADD_COMMAND) {
        const char *regex = ".*Default Gateway.*[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*";
        const char *tmp_file = "default-gateway.txt";
        char gateway[IPSIZE + 1] = {0};

        char cmd[OS_MAXSTR + 1];
        snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\ipconfig.exe | %%WINDIR%%\\system32\\findstr.exe /R /C:\"%s\" > %s", regex, tmp_file);
        system(cmd);

        FILE *fp = wfopen(tmp_file, "r");
        if(fp != NULL) {
            char output_buf[OS_MAXSTR];
            while (fgets(output_buf, OS_MAXSTR, fp)) {
                char *ptr = strchr(output_buf, ':');
                if (ptr != NULL) {
                    snprintf(gateway, sizeof(gateway), "%s", ptr + 2);
                }
            }
            fclose(fp);
        }
        remove(tmp_file);

        if (gateway[0]) {
            char *exec_args_add[8] = { route_path, "-p", "ADD", (char *)srcip, "MASK", "255.255.255.255", gateway, NULL };

            wfd_t *wfd = wpopenv(route_path, exec_args_add, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run %s, action: 'ADD'", route_path);
                write_debug_file(argv[0], log_msg);
            }
            else {
                wpclose(wfd);
            }
        } else {
            write_debug_file(argv[0], "Couldn't get default gateway");
            cJSON_Delete(input_json);
            os_free(route_path);
            return OS_INVALID;
        }
    } else {
        char *exec_args_delete[4] = { route_path, "DELETE", (char *)srcip, NULL };

        wfd_t *wfd = wpopenv(route_path, exec_args_delete, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to run %s, action: 'DELETE'", route_path);
            write_debug_file(argv[0], log_msg);
        }
        else {
            wpclose(wfd);
        }
    }
    os_free(route_path);
#endif

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}
