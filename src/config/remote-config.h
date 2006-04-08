/*   $OSSEC, remote-config.h, v0.3, 2005/02/09, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __CLOGREMOTE_H

#define __CLOGREMOTE_H

#define SYSLOG_CONN 1   
#define SECURE_CONN 2

#include "shared.h"

/* socklen_t header */
typedef struct _remoted
{
    int *port;
    int *conn;

	char **allowips;
	char **denyips;

    int m_queue;
    int sock;
    socklen_t peer_size; 
}remoted;

#endif
