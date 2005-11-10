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

#define MGR_PORT    1514

/* socklen_t header */
#include <sys/types.h>
#include <sys/socket.h>
typedef struct _remoted
{
	char **port;
	char **group;
	char **conn;
	char **allowips;
	char **denyips;

    int m_queue;
    int sock;
    socklen_t peer_size; 
}remoted;


int BindConf(char *cfgfile, remoted *logr);
void *AR_Forward(void *arg);

/* Shared keys */
#include "headers/sec.h"

keystruct keys;
remoted logr;

#endif
