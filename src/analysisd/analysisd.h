/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _LOGAUDIT__H
#define _LOGAUDIT__H

#include <sys/types.h>

#include "decoders/decoder.h"
#include "rules.h"
#include "eventinfo.h"

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
extern OSDecoderNode *osdecodernode_forpname;
extern OSDecoderNode *osdecodernode_nopname;
extern RuleNode *rulenode;
extern rlim_t nofile;
extern int sys_debug_level;
extern OSDecoderInfo *fim_decoder;
extern EventList *last_events_list;
extern time_t current_time;

// Com request thread dispatcher
void * asyscom_main(__attribute__((unused)) void * arg) ;
size_t asyscom_dispatch(char * command, char ** output);
size_t asyscom_getconfig(const char * section, char ** output);

#define WM_ANALYSISD_LOGTAG ARGV0 "" // Tag for log messages

typedef struct cpu_info {
    char *cpu_name;
    int cpu_cores;
    double cpu_MHz;
} cpu_info;

/* CPU info */
cpu_info *get_cpu_info();
cpu_info *get_cpu_info_bsd();
cpu_info *get_cpu_info_linux();

void w_get_queues_size();
void w_get_initial_queues_size();
void w_init_queues();

#define OSSEC_SERVER    "ossec-server"
#define MAX_DECODER_ORDER_SIZE  1024

OSHash *fim_agentinfo;
extern int num_rule_matching_threads;

#define FIM_MAX_WAZUH_DB_ATTEMPS 5
#define SYS_MAX_WAZUH_DB_ATTEMPS 5

#endif /* _LOGAUDIT__H */
