/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLOGREMOTE_H
#define CLOGREMOTE_H

#define SYSLOG_CONN 1
#define SECURE_CONN 2

#include "shared.h"

/* socklen_t header */
typedef struct _remoted {
    int *proto;
    int *port;
    int *conn;
    int *ipv6;

    char **lip;
    os_ip **allowips;
    os_ip **denyips;

    int m_queue;
    int sock;
    int position;
    socklen_t peer_size;
    long queue_size;

    int recv_counter_flush;
    int comp_average_printout;
    int verify_msg_id;
    int pass_empty_keyfile;
    int sender_pool;
    int request_pool;
    int request_timeout;
    int response_timeout;
    int request_rto_sec;
    int request_rto_msec;
    int max_attempts;
    int shared_reload;
    int rlimit_nofile;
    int recv_timeout;
    int send_timeout;
    int nocmerged;
    int keyupdate_interval;
    int worker_pool;
    int state_interval;
    int guess_agent_group;
    int group_data_flush;
    unsigned receive_chunk;
    int buffer_relax;
    int tcp_keepidle;
    int tcp_keepintvl;
    int tcp_keepcnt;
    int log_level;
    int thread_stack_size;
} remoted;

#endif /* CLOGREMOTE_H */
