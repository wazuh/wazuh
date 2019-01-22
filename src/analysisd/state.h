/*
 * Queue (abstract data type)
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 22, 2018
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STATE_A__H
#define _STATE_A__H

extern unsigned int s_events_syscheck_decoded;
extern unsigned int s_events_syscollector_decoded;
extern unsigned int s_events_rootcheck_decoded;
extern unsigned int s_events_hostinfo_decoded;
extern unsigned int s_events_decoded;
extern unsigned int s_events_processed;
extern unsigned int s_events_dropped;
extern volatile unsigned int s_events_received;
extern unsigned int s_alerts_written; 
extern unsigned int s_firewall_written;
extern unsigned int s_fts_written;

extern float s_syscheck_queue;
extern float s_syscollector_queue;
extern float s_rootcheck_queue;
extern float s_hostinfo_queue;
extern float s_event_queue;
extern float s_process_event_queue;
extern float s_winevt_queue;

extern unsigned int s_syscheck_queue_size;
extern unsigned int s_syscollector_queue_size;
extern unsigned int s_rootcheck_queue_size;
extern unsigned int s_hostinfo_queue_size;
extern unsigned int s_event_queue_size;
extern unsigned int s_process_event_queue_size;
extern unsigned int s_winevt_queue_size;

extern float s_writer_alerts_queue;
extern float s_writer_archives_queue;
extern float s_writer_firewall_queue;
extern float s_writer_statistical_queue;

extern unsigned int s_writer_alerts_queue_size;
extern unsigned int s_writer_archives_queue_size;
extern unsigned int s_writer_firewall_queue_size;
extern unsigned int s_writer_statistical_queue_size;

void * w_analysisd_state_main();
int w_analysisd_write_state();

void w_inc_syscheck_decoded_events();
void w_inc_syscollector_decoded_events();
void w_inc_rootcheck_decoded_events();
void w_inc_hostinfo_decoded_events();
void w_inc_decoded_events();
void w_inc_processed_events();
void w_inc_dropped_events();
void w_inc_alerts_written();
void w_inc_firewall_written();
void w_inc_fts_written();
void w_inc_winevt_decoded_events();
void w_reset_stats();

#endif /* _STATE_A__H */

