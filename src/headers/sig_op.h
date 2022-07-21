/* Copyright (C) 2015, Wazuh Inc.
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

void HandleSIG(int sig) __attribute__((noreturn));
void HandleSIGPIPE(int sig);
void HandleExit();

/* Start signal manipulation */
void StartSIG(const char *process_name) __attribute__((nonnull));

/* Start signal manipulation -- function as an argument */
void StartSIG2(const char *process_name, void (*func)(int)) __attribute__((nonnull));

#endif /* SIG_H */
