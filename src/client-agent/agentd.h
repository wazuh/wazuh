/* @(#) $Id$ */

/* Copyright (C) 2005,2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


#ifndef __AGENTD_H

#define __AGENTD_H

#include "config/config.h"
#include "config/client-config.h"


/*** Function Prototypes ***/

/* Client configuration */
int ClientConf(char *cfgfile);

/* Agentd init function */
void AgentdStart(char *dir, int uid, int gid, char *user, char *group);

/* Event Forwarder */
void *EventForward(void *none);

/* Receiver thread */
void *receiver_thread(void *none);

/* Notifier thread */
void *notify_thread(void *none);

/* intcheck_file: 
 * Sends integrity checking information about a file to the server.
 */
int intcheck_file(char *file_name, char *dir);

/* Sends message to server */
int send_msg(int agentid, char *msg);

/* Extract the shared files */
char *getsharedfiles();

/* Connects to server */
void start_agent(int is_startup);

/* notify server */
void run_notify();


/*** Global variables ***/

/* Global variables. Only modified
 * during startup. Shared by all
 * threads and functions
 */

#ifndef WIN32
#include <pthread.h>
#endif
#include "shared.h"
#include "sec.h"

keystore keys;
agent *logr;


/* Not for windows */
#ifndef WIN32
pthread_mutex_t receiver_mutex;
pthread_mutex_t forwarder_mutex;
pthread_cond_t  receiver_cond;
pthread_cond_t  forwarder_cond;
#endif


int available_server;
int available_receiver;
int available_forwarder;

#endif



/* EOF */
