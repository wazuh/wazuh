/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef EXEC_H
#define EXEC_H

#include "eventinfo.h"
#include "active-response.h"

/* Max time in seconds waiting for the active response queue reader to drain the queue */
#define EXEC_SEND_TIMEOUT_S 1

void OS_Exec(int *execq, int *arq, int *sock, const Eventinfo *lf, const active_response *ar);
void getActiveResponseInString(const Eventinfo *lf,
                               const active_response *ar,
                               const char *ip,
                               const char *user,
                               char *filename,
                               char *extra_args,
                               char *temp_msg);
void get_exec_msg(const active_response *ar, char *agent_id, const char *temp_msg, char *exec_msg);
void send_exec_msg(int *socket, const char *queue_path, const char *exec_msg);
int connect_exec_queue(const char *queue_path);

#endif /* EXEC_H */
