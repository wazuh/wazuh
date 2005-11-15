/*   $OSSEC, agentd.h, v0.2, 2005/11/09, Daniel B. Cid$   */

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


#ifndef __AGENTD_H

#define __AGENTD_H

/* Configuration structure */
typedef struct _agent
{
	char *port;
	char *rip; /* remote (server) ip */
    int m_queue;
    int sock;
    int execdq;
}agent;



/*** Function Prototypes ***/

/* Client configuration */
int ClientConf(char *cfgfile);

/* Agentd init function */
void AgentdStart(char *dir, int uid, int gid);

/* Event Forwarder */
void *EventForward(void *none);

/* Receiver thread */
void *receiver_thread(void *none);

/* Notifier thread */
void *notify_thread(void *none);



/*** Global variables ***/

/* Global variables. Only modified
 * during startup. Shared by all
 * threads and functions
 */

#include <pthread.h>
#include "shared.h"
#include "sec.h"

keystruct keys;
agent *logr;

pthread_mutex_t receiver_mutex;
pthread_mutex_t forwarder_mutex;
pthread_mutex_t notify_mutex;
pthread_cond_t  receiver_cond;
pthread_cond_t  forwarder_cond;
pthread_cond_t  notify_cond;

int available_receiver;
int available_forwarder;

#endif



/* EOF */
