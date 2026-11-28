/*
 * Wazuh Module Manager - shutdown sequence
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_SHUTDOWN_H
#define WM_SHUTDOWN_H

/*
 * modulesd's shutdown runs on the main thread, never in the signal handler: wm_handler() only
 * raises wm_shutdown_requested and wakes the main thread through a self-pipe. Defined in main.c (not static: the unit
 * tests include main.c and call them).
 */

/* Blocks until a shutdown signal has been received and returns its number, once; later signals only raise the flag. */
int wm_wait_shutdown_signal(void);

/* The whole sequence: grace, beginShutdown(T0+25 s), every module's stop() in list order, joins until T0+28 s, the
 * runtime's shutdown() and exit(EXIT_SUCCESS). Returns only for an unknown signal (logged). */
void wm_shutdown_run(int signum);

/* Waits for the startup gate; when it reports a shutdown request, runs the shutdown sequence instead of starting. */
void wm_after_startup_gate(void);

#endif /* WM_SHUTDOWN_H */
