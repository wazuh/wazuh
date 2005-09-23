/*      $OSSEC, sig_op.h, v0.2, 2004/08/03, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to handle signal manipulation
 */

#ifndef __SIG_H

#define __SIG_H

void HandleSIG();
void HandleSIGPIPE();

/* Start signal manipulation */
void StartSIG(char *process_name);

#endif
