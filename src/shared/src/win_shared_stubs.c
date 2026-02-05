/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Stub implementations for Windows shared library
 * These functions are referenced by libwazuh.a but not actually
 * called by simple utilities like active-response programs.
 * They are only called by the full agent code.
 */

#ifdef WIN32

#include <stddef.h>

/* Stub for WinSetError - only called on agent service errors */
void WinSetError() {
    /* No-op for utilities that don't run as a service */
}

/* Stub for get_agent_ip_legacy_win32 - only used by full agent */
char* get_agent_ip_legacy_win32() {
    return NULL;
}

/* Stub for SendMSG - only used by full agent communication */
int SendMSG(int socket, const char* msg, const char* locmsg, char loc) {
    (void)socket;
    (void)msg;
    (void)locmsg;
    (void)loc;
    return -1;
}

/* Stub for syscom_dispatch - only used by syscheck module */
size_t syscom_dispatch(char * command, size_t length, char ** output) {
    (void)command;
    (void)length;
    (void)output;
    return 0;
}

#endif
