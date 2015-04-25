/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _OS_WIN__H
#define _OS_WIN__H

/* Install the OSSEC-HIDS agent service */
int InstallService(char *path);

/* Uninstall the OSSEC-HIDS agent service */
int UninstallService();

/* Check if the OSSEC-HIDS agent service is running
 * Returns 1 on success (running) or 0 if not running
 */
int CheckServiceRunning();

/* Start OSSEC-HIDS service */
int os_start_service();

/* Stop OSSEC-HIDS service */
int os_stop_service();

/* Start the process from the services */
int os_WinMain(int argc, char **argv);

/* Locally start the process (after the services initialization) */
int local_start();

#endif
