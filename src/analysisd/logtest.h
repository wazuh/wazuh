/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "decoders/decoder.h"
#include "eventinfo.h"
#include "../headers/pthreads_op.h"
#include "../headers/defs.h"
#include "../headers/validate_op.h"
#include "../os_net/os_net.h"


/**
 * @brief A sessionLogtest instance represents a client.
*/
typedef struct sessionLogtest {

    int token;
    time_t last_connection;

    RuleNode *rulelist;
    OSDecoderNode *decoderlist_forpname;
    OSDecoderNode *decoderlist_nopname;
    ListNode *cdblistnode;
    ListRule *cdblistrule;
    EventList *eventlist;

} sessionLogtest;

/**
 * @brief List of client actives.
 */
OSHash *all_sessions;

/**
 * @brief Mutex to prevent race condition in accept syscall.
 */
pthread_mutex_t logtest_mutex;


/**
 * @brief Initialize Wazuh Logtest. Initialize the listener and creat threads.
 * Then, call function wazuh_logtest_init.
 */
void *w_logtest_init();


/**
 * @brief Main function of Wazuh Logtest module. Listen and treat conexions with clients.
 * @param connection The listener where clients connect
 */
void *w_logtest_main(int * connection);

/**
 * @brief Create resources necessaries to service client
 * @param fd File descriptor which represents the client
 */
void w_logtest_initialize_session(int token);

/**
 * @brief Process client's request
 * @param fd File descriptor which represents the client
 */
void w_logtest_process_log(int token);

/**
 * @brief Free resources after client close connection
 * @param fd File descriptor which represents the client
 */
void w_logtest_remove_session(int token);

/**
 * @brief Check all sessions. If session is created and the client has been offline
 * for more than 15 minutes, remove it.
 */
void w_logtest_check_active_sessions();
