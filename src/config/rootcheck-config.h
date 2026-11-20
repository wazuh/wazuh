/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CROOTCHECK_H
#define CROOTCHECK_H

#include <stdio.h>
#include "../os_regex/os_regex.h"

#define RK_CONF_UNPARSED -2
#define RK_CONF_UNDEFINED -1

/* Bounds of rootcheck.max_pid */
#define RC_MAX_PID_DEFAULT 32768
#define RC_MAX_PID_MAX     4194304

typedef struct _rkconfig {
    const char *workdir;
    char *basedir;
    char *rootkit_files;
    char *rootkit_trojans;
    char **unixaudit;
    char **ignore;
    OSMatch **ignore_sregex;
    char *winaudit;
    char *winmalware;
    char *winapps;
    char **alert_msg;

    FILE *fp;
    int daemon;
    int notify; /* QUEUE or SYSLOG */
    int scanall;
    int readall;
    int disabled;
    short skip_nfs;
    int tsleep;
    int max_pid;    /* Highest PID checked by the Linux hidden process scan */

    int time;
    int queue;

    struct _checks {
        short rc_dev;
        short rc_files;
        short rc_if;
        short rc_pids;
        short rc_ports;
        short rc_sys;
        short rc_trojans;

#ifdef WIN32
        short rc_winaudit;
        short rc_winmalware;
        short rc_winapps;
#else
        short rc_unixaudit;
#endif

    } checks;

} rkconfig;

/* Frees the Rootcheck struct  */
void Free_Rootcheck(rkconfig * config);

#endif /* CROOTCHECK_H */
