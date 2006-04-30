/*    $OSSEC, os_win.h, v0.1, 2006/04/03, Daniel B. Cid$    */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
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
