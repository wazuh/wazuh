/* @(#) $Id: ./src/client-agent/agentd.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

#include "config/config.h"
#include "config/client-config.h"


/*** Function Prototypes ***/

/* Client configuration */
int ClientConf(char *cfgfile);

/* Agentd init function */
void AgentdStart(char *dir, int uid, int gid, char *user, char *group);

/* Event Forwarder */
void *EventForward();

/* Receiver messages */
void *receive_msg();

/* Receiver messages for Windows */
void *receiver_thread(void *none);

/* intcheck_file:
 * Sends integrity checking information about a file to the server.
 */
int intcheck_file(char *file_name, char *dir);

/* Sends message to server */
int send_msg(int agentid, char *msg);

/* Extract the shared files */
char *getsharedfiles();

/* Initializes handshake to server */
void start_agent(int is_startup);

/* Connects to the server. */
int connect_server(int initial_id);

/* notify server */
void run_notify();


/*** Global variables ***/

/* Global variables. Only modified
 * during startup.
 */

#include "shared.h"
#include "sec.h"

int available_server;
int run_foreground;
keystore keys;
agent *agt;


#endif
/* EOF */
