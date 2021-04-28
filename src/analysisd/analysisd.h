/* Copyright (C) 2015-2021, Wazuh Inc.
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
extern time_t current_time;

/**
 * @brief Structure to save all CDB lists.
 */
extern ListNode *os_analysisd_cdblists;

/**
 * @brief Structure to save rules wich depends on a CDB list.
 */
extern ListRule *os_analysisd_cdbrules;

/**
 * @brief Listen to analysisd socket for new requests
 */
void * asyscom_main(__attribute__((unused)) void * arg) ;

/**
 * @brief Check that request is to get a configuration
 * @param command message received from api
 * @param output the configuration to send
 * @return the size of the string "output" containing the configuration
 */
size_t asyscom_dispatch(char * command, char ** output);

/**
 * @brief Process the message received to send the configuration requested
 * @param section contains the name of configuration requested
 * @param output the configuration to send
 * @return the size of the string "output" containing the configuration
 */
size_t asyscom_getconfig(const char * section, char ** output);


#define WM_ANALYSISD_LOGTAG ARGV0 "" // Tag for log messages

/**
 * @brief Get the number of elements divided by the size of queues
 * 
 * Values are save in state's variables
 */
void w_get_queues_size();

/**
 * @brief Obtains analysisd's queues sizes
 * 
 * Values are save in state's variables
 */
void w_get_initial_queues_size();

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

#endif /* LOGAUDIT_H */
