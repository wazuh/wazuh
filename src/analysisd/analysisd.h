/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOGAUDIT_H
#define LOGAUDIT_H

#include <sys/types.h>

#include "decoders/decoder.h"
#include "rules.h"
#include "eventinfo.h"
#include "logtest.h"

/* Time structures */
extern int today;
extern int thishour;
extern int prev_year;
extern char prev_month[4];

extern int __crt_hour;
extern int __crt_wday;

extern struct timespec c_timespec; /* Current time of event. Used everywhere */
#define c_time c_timespec.tv_sec

/* Local host name */
extern char __shost[512];

extern OSDecoderInfo *NULL_Decoder;
extern rlim_t nofile;
extern int sys_debug_level;
extern OSDecoderInfo *fim_decoder;

/**
 * @brief Structure to save all CDB lists.
 */
extern ListNode *os_analysisd_cdblists;

/**
 * @brief Structure to save rules wich depends on a CDB list.
 */
extern ListRule *os_analysisd_cdbrules;

/* Archives writer queue */
extern w_queue_t * writer_queue;

/* Alerts log writer queue */
extern w_queue_t * writer_queue_log;

/* Statistical log writer queue */
extern w_queue_t * writer_queue_log_statistical;

/* Firewall log writer queue */
extern w_queue_t * writer_queue_log_firewall;

/* Decode syscheck input queue */
extern w_queue_t * decode_queue_syscheck_input;

/* Decode syscollector input queue */
extern w_queue_t * decode_queue_syscollector_input;

/* Decode rootcheck input queue */
extern w_queue_t * decode_queue_rootcheck_input;

/* Decode policy monitoring input queue */
extern w_queue_t * decode_queue_sca_input;

/* Decode hostinfo input queue */
extern w_queue_t * decode_queue_hostinfo_input;

/* Decode event input queue */
extern w_queue_t * decode_queue_event_input;

/* Decode pending event output */
extern w_queue_t * decode_queue_event_output;

/* Decode windows event input queue */
extern w_queue_t * decode_queue_winevt_input;

/* Database synchronization input queue */
extern w_queue_t * dispatch_dbsync_input;

/* Upgrade module decoder  */
extern w_queue_t * upgrade_module_input;

/**
 * @brief Initialize queues
 *
 * Queues: decoded event, log writer, database synchronization message and archives writer
 */
void w_init_queues();

#define WAZUH_SERVER    "wazuh-server"
#define MAX_DECODER_ORDER_SIZE  1024

extern OSHash *fim_agentinfo;
extern int num_rule_matching_threads;

#define FIM_MAX_WAZUH_DB_ATTEMPS 5
#define SYS_MAX_WAZUH_DB_ATTEMPS 5
#define PM_MAX_WAZUH_DB_ATTEMPS 5

/**
 * @brief mutex for any condition passed as an argument
 * @return none
 * */
#define w_guard_mutex_variable(mutex, AnyVariable)              \
    w_mutex_lock(&mutex);                                       \
    (void)(AnyVariable);                                        \
    w_mutex_unlock(&mutex)


time_t w_get_current_time(void);

 /**
  * @brief Try reload the ruleset
  *
  * This function will try to reload the ruleset, Re reading the ruleset config
  * from ossec.conf, getting the new files of decoders, rules, cdb list and
  * cleaning the old ruleset.
  *
  * @param list_msg [output] List of messages to be logged (error, warning and info messages)
  * @return false if the ruleset was reloaded successfully, true otherwise
  */
 bool w_hotreload_reload(OSList* list_msg);

#endif /* LOGAUDIT_H */
