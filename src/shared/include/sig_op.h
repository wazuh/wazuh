/* Copyright (C) Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle signal manipulation */

#ifndef SIG_H
#define SIG_H

#include <stdbool.h>

/* True once HandleSIG() has taken a termination signal. The daemon is then inside exit(), and its
 * other threads keep running until the process is gone; a peer daemon stopped in the same pass
 * (wazuh-server.sh signals every daemon before waiting for any) is expected to vanish under them
 * in that window, so a failure to reach it is part of the shutdown, not a fault to report. Only
 * raised by HandleSIG(): daemons with a handler of their own (StartSIG2) carry their own flag. The
 * flag is a lock-free atomic, so the handler's store and the readers in other threads are ordered
 * without a lock; it is kept behind these two calls because this header also reaches C++ units. */
bool w_shutdown_requested(void);
void w_shutdown_requested_set(bool value);

void HandleSIG(int sig) __attribute__((noreturn));
void HandleSIGPIPE(int sig);
void HandleExit();

/* Start signal manipulation */
void StartSIG(const char *process_name) __attribute__((nonnull));

/* Start signal manipulation -- function as an argument */
void StartSIG2(const char *process_name, void (*func)(int)) __attribute__((nonnull));

#endif /* SIG_H */
