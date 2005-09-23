/*   $OSSEC, agentd.h, v0.1, 2005/01/30, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


#ifndef __LOGCLIENT_H

#define __LOGCLIENT_H

typedef struct _agent
{
	char *port;
	char *rip; /* remote (server) ip */
}agent;


/** Prototypes **/

/* Client configuration */
int ClientConf(char *cfgfile,agent *logr);


#endif
