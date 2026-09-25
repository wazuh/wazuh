/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Stubs for wazuh-agent-auth.exe, in the spirit of win_stubs.c.
 *
 * The tool links the configuration parser, which references the module readers, which reference
 * the agent's event queue and syscheck's command dispatcher. On Windows those live in
 * win_utils.c beside local_start() -- the function that starts the entire agent -- so satisfying
 * them from there would pull syscheck, logcollector and every module into a command that enrolls
 * and exits. None of that code runs here: wazuh-agent-auth writes files and returns.
 */

#ifdef WIN32

#include "shared.h"

/* The agent's queue does not exist in this process. Reported as "not sent" rather than silently
 * accepted, so a future caller that does reach here fails visibly. */
int SendMSG(__attribute__((unused)) int queue, __attribute__((unused)) const char *message,
            __attribute__((unused)) const char *locmsg, __attribute__((unused)) char loc) {
    return -1;
}

int SendMSGPredicated(__attribute__((unused)) int queue, __attribute__((unused)) const char *message,
                      __attribute__((unused)) const char *locmsg, __attribute__((unused)) char loc,
                      __attribute__((unused)) bool (*fn_ptr)()) {
    return -1;
}

/* The agent's own Windows implementations of these are no-ops that report success; there is no
 * queue to open on this platform either way. */
int StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type,
            __attribute__((unused)) short int n_tries) {
    return 0;
}

int StartMQPredicated(__attribute__((unused)) const char *path, __attribute__((unused)) short int type,
                      __attribute__((unused)) short int n_tries,
                      __attribute__((unused)) bool (*fn_ptr)()) {
    return 0;
}

int MQReconnectPredicated(__attribute__((unused)) const char *path,
                          __attribute__((unused)) bool (fn_ptr)()) {
    return 0;
}

/* agent_report.c's report_dispatch() fans out to every module's command dispatcher. Three of
 * them resolve from libraries this executable already links; these two live in logcollector and
 * execd, which it does not, and linking either to satisfy a call that never happens would pull a
 * whole subsystem into a command that enrolls and exits. 0 is what report_dispatch() itself
 * returns for a target it does not know. */
size_t lccom_dispatch(__attribute__((unused)) char *command, __attribute__((unused)) char **output) {
    return 0;
}

size_t wcom_dispatch(__attribute__((unused)) char *command, __attribute__((unused)) char **output) {
    return 0;
}

/* syscheck is not running in this process, so there is no state for a command to query. */
size_t syscom_dispatch(__attribute__((unused)) char *command, __attribute__((unused)) size_t command_len,
                       __attribute__((unused)) char **output) {
    return 0;
}

/* Read by getAgentInternalOptions(), which shares an object file with ClientConf() and is never
 * called here. Defined by win_utils.c in the agent itself. */
int win_debug_level;

#endif /* WIN32 */
