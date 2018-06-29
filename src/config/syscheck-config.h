/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __SYSCHECKC_H
#define __SYSCHECKC_H

#define MAX_DIR_SIZE    64
#define MAX_DIR_ENTRY   128
#define SYSCHECK_WAIT   1

/* Checking options */
#define CHECK_MD5SUM        0000001
#define CHECK_PERM          0000002
#define CHECK_SIZE          0000004
#define CHECK_OWNER         0000010
#define CHECK_GROUP         0000020
#define CHECK_SHA1SUM       0000040
#define CHECK_REALTIME      0000100
#define CHECK_SEECHANGES    0000200
#define CHECK_MTIME         0000400
#define CHECK_INODE         0001000
#define CHECK_SHA256SUM     0002000
#define CHECK_WHODATA       0004000

#define ARCH_32BIT          0
#define ARCH_64BIT          1
#define ARCH_BOTH           2

#include <stdio.h>

#include "os_regex/os_regex.h"

#ifdef WIN32
typedef struct whodata_event_node whodata_event_node;
#endif

typedef struct _rtfim {
    int fd;
    OSHash *dirtb;
#ifdef WIN32
    HANDLE evt;
#endif
} rtfim;


typedef struct whodata_evt {
    char *user_id;
    char *user_name;
    char *group_id;  // Linux
    char *group_name;  // Linux
    char *process_name;
    char *path;
    char *audit_uid;  // Linux
    char *audit_name;  // Linux
    char *effective_uid;  // Linux
    char *effective_name;  // Linux
    int ppid;  // Linux
#ifndef WIN32
    unsigned int process_id;
#else
    unsigned __int64 process_id;
    unsigned int mask;
    int dir_position;
    char deleted;
    char force_notify;
    whodata_event_node *wnode;
#endif
} whodata_evt;

#ifdef WIN32

typedef struct whodata_event_node {
    struct whodata_event_node *next;
    struct whodata_event_node *previous;
    char *handle_id;
} whodata_event_node;

typedef struct whodata_event_list {
    whodata_event_node *nodes;
    whodata_event_node *first;
    whodata_event_node *last;
    size_t current_size;
    size_t max_size;
    size_t alert_threshold;
    size_t max_remove;
    char alerted;
} whodata_event_list;

typedef struct whodata {
    OSHash *fd;        // Open file descriptors
    int *ignore_rest;       // List of directories whose SACL will not be restored
} whodata;

typedef struct registry {
    char *entry;
    int arch;
} registry;

typedef struct registry_regex {
    OSMatch *regex;
    int arch;
} registry_regex;

#endif

typedef struct _config {
    unsigned int tsleep;            /* sleep for sometime for daemon to settle */
    int sleep_after;
    int rootcheck;                  /* set to 0 when rootcheck is disabled */
    int disabled;                   /* is syscheck disabled? */
    int scan_on_start;
    int realtime_count;
    short skip_nfs;
    int rt_delay;                   /* Delay before real-time dispatching (ms) */

    int time;                       /* frequency (secs) for syscheck to run */
    int queue;                      /* file descriptor of socket to write to queue */
    unsigned int restart_audit:1;   /* Allow Syscheck restart Auditd */
    unsigned int enable_whodata:1;  /* At less one directory configured with whodata */

    int *opts;                      /* attributes set in the <directories> tag element */

    char *remote_db;
    char *db;

    char *scan_day;                 /* run syscheck on this day */
    char *scan_time;                /* run syscheck at this time */

    char **ignore;                  /* list of files/dirs to ignore */
    OSMatch **ignore_regex;         /* regex of files/dirs to ignore */

    char **nodiff;                  /* list of files/dirs to never output diff */
    OSMatch **nodiff_regex;         /* regex of files/dirs to never output diff */

    char **dir;                     /* array of directories to be scanned */
    OSMatch **filerestrict;

    /* Windows only registry checking */
#ifdef WIN32
    registry *registry_ignore;                  /* list of registry entries to ignore */
    registry_regex *registry_ignore_regex;      /* regex of registry entries to ignore */
    registry *registry;                         /* array of registry entries to be scanned */
    FILE *reg_fp;
    int max_fd_win_rt;
    whodata wdata;
    whodata_event_list wlist;
#else
    int max_audit_entries;          /* Maximum entries for Audit (whodata) */
#endif

    OSHash *fp;

    rtfim *realtime;

    char *prefilter_cmd;

} syscheck_config;


int dump_syscheck_entry(syscheck_config *syscheck, const char *entry, int vals, int reg, const char *restrictfile) __attribute__((nonnull(1, 2)));

char *syscheck_opts2str(char *buf, int buflen, int opts);

/* Frees the Syscheck struct  */
void Free_Syscheck(syscheck_config * config);

#endif /* __SYSCHECKC_H */
