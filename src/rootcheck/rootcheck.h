/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ROOTCHECK_H
#define ROOTCHECK_H

#include "list_op.h"
#include "../config/rootcheck-config.h"
#include <cJSON.h>

#ifdef WIN32
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

extern rkconfig rootcheck;

/* Output types */
#define QUEUE       101
#define SYSLOG_RK   102

/* Maximum files to search on the whole system */
#define MAX_RK_SYS      512

/* rk_types */
#define ALERT_OK                0
#define ALERT_SYSTEM_ERR        1
#define ALERT_SYSTEM_CRIT       2
#define ALERT_ROOTKIT_FOUND     3
#define ALERT_POLICY_VIOLATION  4

#define ROOTCHECK           "rootcheck"

/* Default to 12 hours */
#define ROOTCHECK_WAIT          43200

/** Prototypes **/

/* Check if file is present on dir */
int isfile_ondir(const char *file, const char *dir);

int rk_check_file(char *file, char *pattern);

int rk_check_dir(const char *dir, const char *file, char *pattern);

/* Parse read config into JSON format */
cJSON *getRootcheckConfig(void);

/* Check if pattern is present on string */
int pt_matches(const char *str, char *pattern);

/* Check if the patterns is made up completely of negate matches */
int pt_check_negate(const char *pattern);

/* Check if a file exist (using stat, fopen and opendir) */
int is_file(char *file_name);

/* Check if an entry is in the registry */
int is_registry(char *entry_name, char *reg_option, char *reg_value);

/* Read cl configuration file */
int rkcl_get_entry(FILE *fp, const char *msg, OSList *p_list);

/* Normalize a string, removing white spaces and tabs
 * from the beginning and the end of it.
 */
char *normalize_string(char *str);

/* Check if regex is present on the file.
 * Similar to `strings file | grep -r regex`
 */
int os_string(char *file, char *regex);

/* Check for NTFS ADS (Windows only) */
int os_check_ads(const char *full_path);

/* Get list of processes */
OSList *os_get_process_list(void);

/* Check if a process is running */
int is_process(char *value, OSList *p_list);

/*  Delete the process list */
int del_plist(OSList *p_list);

/* Used to report messages */
int notify_rk(int rk_type, const char *msg);

/* Start the rootcheck externally */
int rootcheck_init(int test_config);

/* Connect Rootcheck queue */
void rootcheck_connect();

/* run_rk_check: checks the integrity of the files against the
 * saved database
 */
void run_rk_check(void);

/* Rootcheck thread */
#ifdef WIN32
DWORD WINAPI w_rootcheck_thread(__attribute__((unused)) void * args);
#else
void * w_rootcheck_thread(__attribute__((unused)) void * args);
#endif
/*** Plugins prototypes ***/
void check_rc_dev(const char *basedir);
void check_rc_sys(const char *basedir);
void check_rc_pids(void);

/* Verify if "pid" is in the proc directory */
int check_rc_readproc(int pid);

void check_rc_ports(void);
void check_open_ports(void);
void check_rc_if(void);

/*Checks if the path or file is user-ignored */
 int check_ignore(const char *path_to_ignore);

int Read_Rootcheck_Config(const char *cfgfile);

/* Global variables */
extern char **rk_sys_file;
extern char **rk_sys_name;
extern int rk_sys_count;

/* All the ports */
extern char total_ports_udp[65535 + 1];
extern char total_ports_tcp[65535 + 1];

/* Process struct */
typedef struct _Proc_Info {
    char *p_name;
    char *p_path;
} Proc_Info;

#endif /* ROOTCHECK_H */
