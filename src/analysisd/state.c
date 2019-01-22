/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "analysisd.h"
#include "state.h"

unsigned int s_events_syscheck_decoded = 0;
unsigned int s_events_syscollector_decoded  = 0;
unsigned int s_events_rootcheck_decoded = 0;
unsigned int s_events_hostinfo_decoded  = 0;
unsigned int s_events_winevt_decoded = 0;
unsigned int s_events_decoded = 0;
unsigned int s_events_processed = 0;
unsigned int s_events_dropped = 0 ;
volatile unsigned int s_events_received = 0;
unsigned int s_alerts_written  = 0; 
unsigned int s_firewall_written = 0;
unsigned int s_fts_written = 0;

float s_syscheck_queue = 0;
float s_syscollector_queue = 0;
float s_rootcheck_queue = 0;
float s_hostinfo_queue = 0;
float s_winevt_queue = 0;
float s_event_queue = 0;
float s_process_event_queue = 0;

unsigned int s_syscheck_queue_size = 0;
unsigned int s_syscollector_queue_size = 0;
unsigned int s_rootcheck_queue_size = 0;
unsigned int s_hostinfo_queue_size = 0;
unsigned int s_winevt_queue_size = 0;
unsigned int s_event_queue_size = 0;
unsigned int s_process_event_queue_size = 0;

float s_writer_alerts_queue = 0;
float s_writer_archives_queue = 0;
float s_writer_firewall_queue = 0;
float s_writer_statistical_queue = 0;

unsigned int s_writer_alerts_queue_size = 0;
unsigned int s_writer_archives_queue_size = 0;
unsigned int s_writer_firewall_queue_size = 0;
unsigned int s_writer_statistical_queue_size = 0;

pthread_mutex_t s_syscheck_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_syscollector_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_rootcheck_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_hostinfo_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_winevt_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_event_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_process_event_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_event_dropped_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_alerts_written_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_firewall_written_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_fts_written_mutex = PTHREAD_MUTEX_INITIALIZER;

static int interval;

void * w_analysisd_state_main(){
    interval = getDefine_Int("analysisd", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    mdebug1("State file updating thread started.");

    while (1) {
        w_analysisd_write_state();
        sleep(interval);
    }

    return NULL;
}

int w_analysisd_write_state(){
    FILE * fp;
    char path[PATH_MAX + 1];
    char path_temp[PATH_MAX + 1];

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

    snprintf(path, sizeof(path), "%s" OS_PIDFILE "/%s.state", isChroot() ? "" : DEFAULTDIR, __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = fopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        return -1;
    }

    w_get_queues_size();

    fprintf(fp,
        "# State file for %s\n"
        "\n"
        "# Total events decoded\n"
        "total_events_decoded='%u'\n"
        "\n"
        "# Syscheck events decoded\n"
        "syscheck_events_decoded='%u'\n"
        "syscheck_edps='%u'\n"
        "\n"
        "# Syscollector events decoded\n"
        "syscollector_events_decoded='%u'\n"
        "syscollector_edps='%u'\n"
        "\n"
        "# Rootcheck events decoded\n"
        "rootcheck_events_decoded='%u'\n"
        "rootcheck_edps='%u'\n"
        "\n"
        "# Hostinfo events decoded\n"
        "hostinfo_events_decoded='%u'\n"
        "hostinfo_edps='%u'\n"
        "\n"
        "# Winevt events decoded\n"
        "winevt_events_decoded='%u'\n"
        "winevt_edps='%u'\n"
        "\n"
        "# Other events decoded\n"
        "other_events_decoded='%u'\n"
        "other_events_edps='%u'\n"
        "\n"
        "# Events processed (Rule matching)\n"
        "events_processed='%u'\n"
        "events_edps='%u'\n"
        "\n"
        "# Events received\n"
        "events_received='%u'\n"
        "\n"
        "# Events dropped\n"
        "events_dropped='%u'\n"
        "\n"
        "# Alerts written to disk\n"
        "alerts_written='%u'\n"
        "\n"
        "# Firewall alerts written to disk\n"
        "firewall_written='%u'\n"
        "\n"
        "# FTS alerts written to disk\n"
        "fts_written='%u'\n"
        "\n"
        "# Syscheck queue\n"
        "syscheck_queue_usage='%.2f'\n"
        "\n"
        "# Syscheck queue size\n"
        "syscheck_queue_size='%u'\n"
        "\n"
        "# Syscollector queue\n"
        "syscollector_queue_usage='%.2f'\n"
        "\n"
        "# Syscollector queue size\n"
        "syscollector_queue_size='%u'\n"
        "\n"
        "# Rootcheck queue\n"
        "rootcheck_queue_usage='%.2f'\n"
        "\n"
        "# Rootcheck queue size\n"
        "rootcheck_queue_size='%u'\n"
        "\n"
        "# Hostinfo queue\n"
        "hostinfo_queue_usage='%.2f'\n"
        "\n"
        "# Hostinfo queue size\n"
        "hostinfo_queue_size='%u'\n"
        "\n"
        "# Winevt queue\n"
        "winevt_queue_usage='%.2f'\n"
        "\n"
        "# Winevt queue size\n"
        "winevt_queue_size='%u'\n"
        "\n"
        "# Event queue\n"
        "event_queue_usage='%.2f'\n"
        "\n"
        "# Event queue size\n"
        "event_queue_size='%u'\n"
        "\n"
        "# Rule matching queue\n"
        "rule_matching_queue_usage='%.2f'\n"
        "\n"
        "# Rule matching queue size\n"
        "rule_matching_queue_size='%u'\n"
        "\n"
        "# Alerts log queue\n"
        "alerts_queue_usage='%.2f'\n"
        "\n"
        "# Alerts log queue size\n"
        "alerts_queue_size='%u'\n"
        "\n"
        "# Firewall log queue\n"
        "firewall_queue_usage='%.2f'\n"
        "\n"
        "# Firewall log queue size\n"
        "firewall_queue_size='%u'\n"
        "\n"
        "# Statistical log queue\n"
        "statistical_queue_usage='%.2f'\n"
        "\n"
        "# Statistical log queue size\n"
        "statistical_queue_size='%u'\n"
        "\n"
        "# Archives log queue\n"
        "archives_queue_usage='%.2f'\n"
        "\n"
        "# Archives log queue size\n"
        "archives_queue_size='%u'\n"
        "\n",
        __local_name, 
        s_events_decoded + s_events_syscheck_decoded + s_events_syscollector_decoded + s_events_rootcheck_decoded + s_events_hostinfo_decoded + s_events_winevt_decoded ,
        s_events_syscheck_decoded,
        s_events_syscheck_decoded / interval ,
        s_events_syscollector_decoded,
        s_events_syscollector_decoded / interval,
        s_events_rootcheck_decoded,
        s_events_rootcheck_decoded / interval,
        s_events_hostinfo_decoded,
        s_events_hostinfo_decoded / interval,
        s_events_winevt_decoded,
        s_events_winevt_decoded / interval,
        s_events_decoded,
        s_events_decoded / interval,
        s_events_processed,
        s_events_processed / interval,
        s_events_received,
        s_events_dropped,
        s_alerts_written,
        s_firewall_written,
        s_fts_written,
        s_syscheck_queue,
        s_syscheck_queue_size,
        s_syscollector_queue,
        s_syscollector_queue_size,
        s_rootcheck_queue,
        s_rootcheck_queue_size,
        s_hostinfo_queue,
        s_hostinfo_queue_size,
        s_winevt_queue,
        s_winevt_queue_size,
        s_event_queue,s_event_queue_size,
        s_process_event_queue,
        s_process_event_queue_size,
        s_writer_alerts_queue,
        s_writer_alerts_queue_size,
        s_writer_firewall_queue,
        s_writer_firewall_queue_size,
        s_writer_statistical_queue,
        s_writer_statistical_queue_size,
        s_writer_archives_queue,
        s_writer_archives_queue_size);
    fclose(fp);

    w_reset_stats();

    if (rename(path_temp, path) < 0) {
        merror("Renaming %s to %s: %s", path_temp, path, strerror(errno));
        if (unlink(path_temp) < 0) {
            merror("Deleting %s: %s", path_temp, strerror(errno));
        }
       return -1;
    }

   return 0;
}

void w_inc_syscheck_decoded_events(){
    w_mutex_lock(&s_syscheck_mutex);
    s_events_syscheck_decoded++;
    w_mutex_unlock(&s_syscheck_mutex);
}

void w_inc_syscollector_decoded_events(){
    w_mutex_lock(&s_syscollector_mutex);
    s_events_syscollector_decoded++;
    w_mutex_unlock(&s_syscollector_mutex);
}

void w_inc_rootcheck_decoded_events(){
    w_mutex_lock(&s_rootcheck_mutex);
    s_events_rootcheck_decoded++;
    w_mutex_unlock(&s_rootcheck_mutex);
}

void w_inc_hostinfo_decoded_events(){
    w_mutex_lock(&s_hostinfo_mutex);
    s_events_hostinfo_decoded++;
    w_mutex_unlock(&s_hostinfo_mutex);
}

void w_inc_winevt_decoded_events(){
    w_mutex_lock(&s_winevt_mutex);
    s_events_winevt_decoded++;
    w_mutex_unlock(&s_winevt_mutex);
}

void w_inc_decoded_events(){
    w_mutex_lock(&s_event_mutex);
    s_events_decoded++;
    w_mutex_unlock(&s_event_mutex);
}

void w_inc_processed_events(){
    w_mutex_lock(&s_process_event_mutex);
    s_events_processed++;
    w_mutex_unlock(&s_process_event_mutex);
}

void w_inc_dropped_events(){
    w_mutex_lock(&s_event_dropped_mutex);
    s_events_dropped++;
    w_mutex_unlock(&s_event_dropped_mutex);
}

void w_inc_alerts_written(){
    w_mutex_lock(&s_alerts_written_mutex);
    s_alerts_written++;
    w_mutex_unlock(&s_alerts_written_mutex);
}

void w_inc_firewall_written(){
    w_mutex_lock(&s_firewall_written_mutex);
    s_firewall_written++;
    w_mutex_unlock(&s_firewall_written_mutex);
}

void w_inc_fts_written(){
    w_mutex_lock(&s_fts_written_mutex);
    s_fts_written++;
    w_mutex_unlock(&s_fts_written_mutex);
}

void w_reset_stats(){
    w_mutex_lock(&s_syscheck_mutex);
    s_events_syscheck_decoded = 0;
    w_mutex_unlock(&s_syscheck_mutex);

    w_mutex_lock(&s_syscollector_mutex);
    s_events_syscollector_decoded = 0;
    w_mutex_unlock(&s_syscollector_mutex);

    w_mutex_lock(&s_rootcheck_mutex);
    s_events_rootcheck_decoded = 0;
    w_mutex_unlock(&s_rootcheck_mutex);

    w_mutex_lock(&s_hostinfo_mutex);
    s_events_hostinfo_decoded = 0;
    w_mutex_unlock(&s_hostinfo_mutex);

    w_mutex_lock(&s_winevt_mutex)
    s_events_winevt_decoded = 0;
    w_mutex_unlock(&s_winevt_mutex);

    w_mutex_lock(&s_event_mutex);
    s_events_decoded = 0;
    w_mutex_unlock(&s_event_mutex);

    w_mutex_lock(&s_process_event_mutex);
    s_events_processed = 0;
    w_mutex_unlock(&s_process_event_mutex);

    w_mutex_lock(&s_event_dropped_mutex);
    s_events_dropped = 0;
    w_mutex_unlock(&s_event_dropped_mutex);

    w_mutex_lock(&s_alerts_written_mutex);
    s_alerts_written = 0;
    w_mutex_unlock(&s_alerts_written_mutex);

    w_mutex_lock(&s_firewall_written_mutex);
    s_firewall_written = 0;
    w_mutex_unlock(&s_firewall_written_mutex);

    w_mutex_lock(&s_fts_written_mutex);
    s_fts_written = 0;
    w_mutex_unlock(&s_fts_written_mutex);

    s_events_received = 0;
}



