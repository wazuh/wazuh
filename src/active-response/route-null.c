/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

int main (int argc, char **argv) {
    (void)argc;
    char *srcip;
    char *action;
    char input[BUFFERSIZE];
    cJSON *input_json = NULL;

#ifndef WIN32
    char *home_path = w_homedir(argv[0]);

    /* Trim absolute path to get Wazuh's installation directory */
    home_path = w_strtok_r_str_delim("/active-response", &home_path);

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
    os_free(home_path);
#endif

    write_debug_file(argv[0], "Starting");

    memset(input, '\0', BUFFERSIZE);
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0], input);

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

    // Get srcip
    srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

#ifndef WIN32
    wfd_t *wfd = NULL;
    struct utsname uname_buffer;

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        if (!strcmp("add", action)) {
            char *cmd[5] = { "route", "add", srcip, "reject", NULL };
            if (wfd = wpopenv(*cmd, cmd, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *cmd[5] = { "route", "del", srcip, "reject", NULL };
            if (wfd = wpopenv(*cmd, cmd, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        if (!strcmp("add", action)) {
            char *cmd[7] = { "route", "-q", "add", srcip, "127.0.0.1", "-blackhole", NULL };
            if (wfd = wpopenv(*cmd, cmd, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *cmd[7] = { "route", "-q", "delete", srcip, "127.0.0.1", "-blackhole", NULL };
            if (wfd = wpopenv(*cmd, cmd, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else {
        write_debug_file(argv[0], "Invalid system");
    }
#else
    if (!strcmp("add", action)) {
        const char *regex = ".*Default Gateway.*[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*";
        const char *tmp_file = "default-gateway.txt";
        char *gateway = NULL;

        char cmd[OS_MAXSTR + 1];
        snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\ipconfig.exe | %%WINDIR%%\\system32\\findstr.exe /R /C:\"%s\" > %s", regex, tmp_file);
        system(cmd);

        FILE *fp = fopen(tmp_file, "r");
        if(fp != NULL) {
            char output_buf[BUFFERSIZE];
            while (fgets(output_buf, BUFFERSIZE, fp)) {
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
