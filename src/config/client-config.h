/*   $OSSEC, client-config.h, v0.2, 2005/11/09, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __CAGENTD_H

#define __CAGENTD_H

/* Configuration structure */
typedef struct _agent
{
    char *port;
    int m_queue;
    int sock;
    int execdq;
    int rip_id;
    char *lip;
    char **rip; /* remote (server) ip */
    int notify_time;
    int max_time_reconnect_try;
    char *profile;
}agent;


#endif


/* EOF */
