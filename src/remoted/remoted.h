/*   $OSSEC, remoted.h, v0.3, 2005/02/09, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __LOGREMOTE_H

#define __LOGREMOTE_H

#ifndef ARGV0
#define ARGV0 "ossec-remoted"
#endif

#define SYSLOG_CONN 1   
#define SECURE_CONN 2

#include "shared.h"
#include "sec.h"

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


/*** Function prototypes ***/

/* Read remoted config */
int RemotedConfig(char *cfgfile, remoted *logr);

/* Handle Remote connections */
void HandleRemote(int position, int uid); 

/* Handle Syslog */
void HandleSyslog(int position);

/* Handle Secure connections */
void HandleSecure(int position);

/* Forward active response events */
void *AR_Forward(void *arg);

/* Initialize the manager */
void manager_init();

/* Wait for messages from the agent to analyze */
void *wait_for_msgs(void *none);

/* Save control messages */
void save_controlmsg(int agentid, char *msg);



/*** Global variables ***/

keystruct keys;
remoted logr;

#endif
