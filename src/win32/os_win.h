/*    $OSSEC, os_win.h, v0.1, 2006/04/03, Daniel B. Cid$    */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



/** int InstallService()
 * Install the OSSEC HIDS agent service.
 */
int InstallService(int argc, char **argv); 


/** int UninstallService()
 * Uninstall the OSSEC HIDS agent service.
 */
int UninstallService(); 


/* EOF */
