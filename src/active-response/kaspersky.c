/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define PYTHON2             "/usr/bin/python"
#define PYTHON3             "/usr/bin/python3"
#define PATH_TO_KASPERSKY   DEFAULTDIR "/active-response/bin/kaspersky.py"

int main (int argc, char **argv) {

    char log_msg[LOGSIZE];
    struct stat file_status;

    write_debug_file(argv[0], "Starting");

    if (!stat(PYTHON2, &file_status)) {
        char exec_cmd[3] = {"python", PATH_TO_KASPERSKY, NULL};
        wfd_t *wfd = wpopenv(exec_cmd[0], exec_cmd, W_BIND_STDOUT);
        if (!wfd) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error executing '%s' : %s", exec_cmd, strerror(errno));
            write_debug_file(argv[0], log_msg);
            return OS_INVALID;
        }
        wpclose(wfd);

    }
    if (!stat(PYTHON3, &file_status)) {
        char exec_cmd[3] = {"python3", PATH_TO_KASPERSKY, NULL};
        wfd_t *wfd = wpopenv(exec_cmd[0], exec_cmd, W_BIND_STDOUT);
        if (!wfd) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error executing '%s' : %s", exec_cmd, strerror(errno));
            write_debug_file(argv[0], log_msg);
            return OS_INVALID;
        }
        wpclose(wfd);
    }
    write_debug_file(argv[0], "Ended");

    return OS_SUCCESS;
}
