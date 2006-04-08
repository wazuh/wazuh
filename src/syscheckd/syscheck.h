/*   $OSSEC, syscheck.h, v0.1, 2005/07/29, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       

#ifndef __SYSCHECK_H

#define __SYSCHECK_H

#include "config/syscheck-config.h"

config syscheck;

/** Prototypes **/

/* run_check: checks the integrity of the files against the
 * saved database
 */
void run_check();

/* start_daemon: Runs run_check periodically.
 */
void start_daemon();

#endif

/* EOF */
