/*   $OSSEC, ar.h, v0.1, 2005/11/06, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Active response shared headers */

#ifndef __AR_H

#define __AR_H


/* Recepient agents */
#define ALL_AGENTS      0000001
#define REMOTE_AGENT    0000002
#define SPECIFIC_AGENT  0000004
#define AS_ONLY         0000010

#define ALL_AGENTS_C     'A'
#define REMOTE_AGENT_C   'R'
#define SPECIFIC_AGENT_C 'S'
#define NONE_C           'N'


/* AR  Queues to use */
#define REMOTE_AR       00001
#define LOCAL_AR        00002


/* Expected values */
#define SRCIP       0000004
#define DSTIP       0000002
#define USERNAME    0000001


#endif

/* EOF */
