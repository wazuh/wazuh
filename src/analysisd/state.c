/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "state.h"
#include "analysisd.h"

unsigned int s_events_syscheck_decoded = 0;
unsigned int s_events_syscollector_decoded  = 0;
unsigned int s_events_rootcheck_decoded = 0;
unsigned int s_events_hostinfo_decoded  = 0;
unsigned int s_events_decoded = 0;
unsigned int s_events_processed = 0;
unsigned int s_events_dropped = 0 ;
unsigned int s_alerts_writed  = 0; 
unsigned int s_firewall_writed = 0;

unsigned int s_syscheck_queue = 0;
unsigned int s_syscollector_queue = 0;
unsigned int s_rootcheck_queue = 0;
unsigned int s_hostinfo_queue = 0;
unsigned int s_event_queue = 0;
unsigned int s_process_event_queue = 0;

unsigned int s_writer_alerts_queue = 0;
unsigned int s_writer_archives_queue = 0;
unsigned int s_writer_firewall_queue = 0;
unsigned int s_writer_statistical_queue = 0;

pthread_mutex_t s_syscheck_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_syscollector_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_rootcheck_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_hostinfo_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_event_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_process_event_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_event_dropped_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_alerts_writed_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t s_firewall_writed_mutex = PTHREAD_MUTEX_INITIALIZER;


void * w_analysisd_state_main(){
    int interval = getDefine_Int("analysisd", "state_interval", 0, 86400);

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

    //w_get_queues_size();

    fprintf(fp,
        "# State file for %s\n"
        "\n"
        "# Total events decoded\n"
        "events_decoded:'%u'\n"
        "\n"
        "# Syscheck events decoded\n"
        "syscheck_events_decoded:'%u'\n"
        "\n"
        "# Syscollector events decoded\n"
        "syscollector_events_decoded:'%u'\n"
        "\n"
        "# Rootcheck events decoded\n"
        "rootcheck_events_decoded:'%u'\n"
        "\n"
        "# Hostinfo events decoded\n"
        "hostinfo_events_decoded:'%u'\n"
        "\n"
        "# Other events decoded\n"
        "other_events_decoded:'%u'\n"
        "\n"
        "# Events processed - rule matching\n"
        "events_processed:'%u'\n"
        "\n"
        "# Events dropped\n"
        "events_dropped:'%u'\n"
        "\n"
        "# Alerts writed to disk\n"
        "alerts_writed:'%u'\n"
        "# Firewall alerts writed to disk\n"
        "firewall_writed:'%u'\n",
        __local_name, s_events_decoded + s_events_syscheck_decoded + s_events_syscollector_decoded + s_events_rootcheck_decoded + s_events_hostinfo_decoded ,s_events_syscheck_decoded, s_events_syscollector_decoded,s_events_rootcheck_decoded,s_events_hostinfo_decoded,s_events_decoded,s_events_processed,s_events_dropped, s_alerts_writed,s_firewall_writed);
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

void w_inc_alerts_writed(){
    w_mutex_lock(&s_alerts_writed_mutex);
    s_alerts_writed++;
    w_mutex_unlock(&s_alerts_writed_mutex);
}

void w_inc_firewall_writed(){
    w_mutex_lock(&s_firewall_writed_mutex);
    s_firewall_writed++;
    w_mutex_unlock(&s_firewall_writed_mutex);
}

void w_reset_stats(){
    w_mutex_lock(&s_syscheck_mutex);
    s_events_syscheck_decoded = 0;
    w_mutex_unlock(&s_syscheck_mutex);

    w_mutex_lock(&s_syscollector_mutex);
    s_events_syscheck_decoded = 0;
    w_mutex_unlock(&s_syscollector_mutex);

    w_mutex_lock(&s_rootcheck_mutex);
    s_events_rootcheck_decoded = 0;
    w_mutex_unlock(&s_rootcheck_mutex);

    w_mutex_lock(&s_hostinfo_mutex);
    s_events_hostinfo_decoded = 0;
    w_mutex_unlock(&s_hostinfo_mutex);

    w_mutex_lock(&s_event_mutex);
    s_events_decoded = 0;
    w_mutex_unlock(&s_event_mutex);

    w_mutex_lock(&s_process_event_mutex);
    s_events_processed = 0;
    w_mutex_unlock(&s_process_event_mutex);

    w_mutex_lock(&s_event_dropped_mutex);
    s_events_dropped = 0;
    w_mutex_unlock(&s_event_dropped_mutex);

    w_mutex_lock(&s_alerts_writed_mutex);
    s_alerts_writed = 0;
    w_mutex_unlock(&s_alerts_writed_mutex);

    w_mutex_lock(&s_firewall_writed_mutex);
    s_firewall_writed = 0;
    w_mutex_unlock(&s_firewall_writed_mutex);

}



