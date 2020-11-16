/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MQ_H
#define MQ_H

#include "config/localfile-config.h"

/* Default queues */
#define LOCALFILE_MQ    '1'
#define SYSLOG_MQ       '2'
#define HOSTINFO_MQ     '3'
#define SECURE_MQ       '4'
#define DBSYNC_MQ       '5'
#define SYSCHECK_MQ     '8'
#define ROOTCHECK_MQ    '9'
#define SCA_MQ          'p'
#define UPGRADE_MQ      'u'

/* Queues for additional log types */
#define MYSQL_MQ         'a'
#define POSTGRESQL_MQ    'b'
#define AUTH_MQ          'c'
#define SYSCOLLECTOR_MQ  'd'
#define CISCAT_MQ        'e'
#define WIN_EVT_MQ       'f'

#define INFINITE_OPENQ_ATTEMPTS 0

extern int sock_fail_time;
/**
 *  Starts a Message Queue.
 *  @param key path where the message queue will be created
 *  @param type WRITE||READ
 *  @param n_attempts Number of attempts to connect to the queue (0 to attempt until a successful conection).
 *  @return
 *  UNIX -> OS_INVALID if queue failed to start
 *  UNIX -> int(rc) file descriptor of initialized queue
 *  WIN32 -> 0
 */
int StartMQ(const char *key, short int type, short int n_attempts) __attribute__((nonnull));

/**
 * Sends a message string through a message queue
 * @param queue file descriptor of the queue where the message will be sent (UNIX)
 * @param message string containing the message
 * @param locmsg path to the queue file
 * @param loc  queue location (WIN32)
 * @return
 * UNIX -> 0 if file descriptor is still available
 * UNIX -> -1 if there is an error in the socket. The socket will be closed before returning (StartMQ should be called to restore queue)
 * WIN32 -> 0
 * Notes: (UNIX) If the socket is busy when trying to send a message a DEBUG2 message will be loggeed but the return code will be 0
 */

int SendMSG(int queue, const char *message, const char *locmsg, char loc) __attribute__((nonnull));

/**
 * Sends a message to a socket. If the socket has not been created yet it will be created based on
 * the target information. If a message fails to be sent the method will not try to send it again until *sock_fail_time* has passed
 * @param queue file descriptor of the queue where the error message will be sent (UNIX)
 * @param message string containing the message that will be sent
 * @param locmsg path to the queue file
 * @param loc  queue location (WIN32)
 * @param target logtarget ptr with the socket information
 * @return
 * UNIX -> -1 invalid protocol or cannot create socket
 * UNIX ->  0 message was sent or discarded
 * WIN32 -> -1 invalid target
 * WIN32 -> 0 valid target
 * Notes: (UNIX) If the message is not sent because the socket is busy, the return code will be 0
 */
int SendMSGtoSCK(int queue, const char *message, const char *locmsg, char loc, logtarget * target) __attribute__((nonnull (2, 3, 5)));

void mq_log_builder_init();

int mq_log_builder_update();

#endif /* MQ_H */
