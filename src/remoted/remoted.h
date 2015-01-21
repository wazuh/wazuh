/* Copyright (C) 2009 Trend Micro Inc.
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

#include "config/remote-config.h"
#include "sec.h"

/** Function prototypes **/

/* Read remoted config */
int RemotedConfig(const char *cfgfile, remoted *cfg);

/* Handle Remote connections */
void HandleRemote(int position, int uid) __attribute__((noreturn));

/* Handle Syslog */
void HandleSyslog(void) __attribute__((noreturn));

/* Handle Syslog TCP */
void HandleSyslogTCP(void) __attribute__((noreturn));

/* Handle Secure connections */
void HandleSecure(void) __attribute__((noreturn));

/* Forward active response events */
void *AR_Forward(void *arg);

/* Initialize the manager */
void manager_init(int isUpdate);

/* Wait for messages from the agent to analyze */
void *wait_for_msgs(void *none);

/* Save control messages */
void save_controlmsg(unsigned int agentid, char *msg);

/* Send message to agent */
int send_msg(unsigned int agentid, const char *msg);

/* Initializing send_msg */
void send_msg_init(void);

int check_keyupdate(void);

void key_lock(void);

void key_unlock(void);

void keyupdate_init(void);

/** Global variables **/

extern keystore keys;
extern remoted logr;

#endif /* __LOGREMOTE_H */
