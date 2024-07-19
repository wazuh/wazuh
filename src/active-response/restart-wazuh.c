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

    action = setup_and_check_message(argv, NULL);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

#ifndef WIN32
    char log_msg[OS_MAXSTR];
    char *exec_cmd[3] = { "bin/wazuh-control", "restart", NULL };

    wfd_t *wfd = wpopenv(*exec_cmd, exec_cmd, W_BIND_STDERR);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s': %s", *exec_cmd, strerror(errno));
        write_debug_file(argv[0], log_msg);
        return OS_INVALID;
    }

    while (waitpid(-1, NULL, 0) > 0);

    wpclose(wfd);
#else
    char cmd[OS_MAXSTR + 1];

    snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\net.exe stop Wazuh");
    system(cmd);

    snprintf(cmd, OS_MAXSTR, "%%WINDIR%%\\system32\\net.exe start Wazuh");
    system(cmd);
#endif

    write_debug_file(argv[0], "Ended");

    return OS_SUCCESS;
}
