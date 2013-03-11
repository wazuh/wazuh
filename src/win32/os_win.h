/* @(#) $Id: ./src/win32/os_win.h, 2011/09/08 dcid Exp $
 */

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


/** int InstallService(char *path)
 * Install the OSSEC HIDS agent service.
 */
int InstallService(char *path);


/** int UninstallService()
 * Uninstall the OSSEC HIDS agent service.
 */
int UninstallService();


/** int QueryService():
 * Checks if service is running.
 * Return 1 on success (running) or 0 if not.
 */
int CheckServiceRunning();


/* os_start_service: Starts ossec service */
int os_start_service();


/* os_stop_service: Stops ossec service */
int os_stop_service();


/** int os_WinMain(int argc, char **argv)
 * Starts the process from the services.
 */
int os_WinMain(int argc, char **argv);


/** int local_start();
 * Locally starts the process (after the services initialization).
 */
int local_start();

#endif
/* EOF */
