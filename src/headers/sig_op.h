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

void HandleSIG(int sig);
void HandleSIGPIPE(int sig);
void HandleExit();

/* Start signal manipulation */
void StartSIG(const char *process_name) __attribute__((nonnull));

/* Start signal manipulation -- function as an argument */
void StartSIG2(const char *process_name, void (*func)(int)) __attribute__((nonnull));

/* Make HandleSIG() only signal a thread that ends the process outside signal context.
 * Call it after StartSIG() and after goDaemon(): threads don't survive its fork. */
void StartSIGShutdownThread();

/* Callback run by the shutdown thread before the process ends. The atexit handlers are skipped on that path, so it must cover their work. */
void SetSIGShutdownFunc(void (*func)(void));

#endif /* SIG_H */
