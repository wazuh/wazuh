/* @(#) $Id: ./src/rootcheck/rootcheck.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __ROOTCHECK_H
#define __ROOTCHECK_H

#include "config/rootcheck-config.h"
rkconfig rootcheck;


/* output types */
#define QUEUE   101
#define SYSLOG  102


/* Maximum files to search on the whole system */
#define MAX_RK_SYS      512


/* rk_types */
#define ALERT_OK                0
#define ALERT_SYSTEM_ERR        1
#define ALERT_SYSTEM_CRIT       2
#define ALERT_ROOTKIT_FOUND     3
#define ALERT_POLICY_VIOLATION  4

#define ROOTCHECK           "rootcheck"

/* Default to 10 hours */
#define ROOTCHECK_WAIT          72000




/** Prototypes **/

/* common isfile_ondir: Check if file is present on dir */
int isfile_ondir(char *file, char *dir);

/* int rk_check_file(char *value, char *pattern) */
int rk_check_file(char *file, char *pattern);

/* int rk_check_dir(char *dir, char *file, char *pattern) */
int rk_check_dir(char *dir, char *file, char *pattern);

/* pt_matches: Checks if pattern is present on string */
int pt_matches(char *str, char *pattern);

/* pt_check_negate: checks if the patterns is made up
 * completely of negate matches */
int pt_check_negate(char *pattern);

/* common is_file: Check if a file exist (using stat, fopen and opendir) */
int is_file(char *file_name);

/* win_common is_registry: Check if a entry is in the registry */
int is_registry(char *entry_name, char *reg_option, char *reg_value);

/* int rkcl_get_entry: Reads cl configuration file. */
int rkcl_get_entry(FILE *fp, char *msg, void *p_list);


/** char *normalize_string
 * Normalizes a string, removing white spaces and tabs
 * from the begining and the end of it.
 */
char *normalize_string(char *str);


/* Check if regex is present on the file.
 * Similar to `strings file | grep -r regex`
 */
int os_string(char *file, char *regex);

/* check for NTFS ADS (Windows only)
 */
int os_check_ads(char *full_path);

/* os_get_process_list: Get list of processes
 */
void *os_get_process_list();

/* is_process: Check is a process is running.
 */
int is_process(char *value, void *p_list);


/*  del_plist:. Deletes the process list
 */
int del_plist(void *p_list);


/* Used to report messages */
int notify_rk(int rk_type, char *msg);



/* rootcheck_init: Starts the rootcheck externally
 */
int rootcheck_init(int test_config);

/* run_rk_check: checks the integrity of the files against the
 * saved database
 */
void run_rk_check();

/* start_rk_daemon: Runs run_rk_check periodically.
 */
void start_rk_daemon();


/*** Plugins prototypes ***/
void check_rc_files(char *basedir, FILE *fp);

void check_rc_trojans(char *basedir, FILE *fp);

void check_rc_unixaudit(FILE *fp, void *p_list);

void check_rc_winaudit(FILE *fp, void *p_list);

void check_rc_winmalware(FILE *fp, void *p_list);

void check_rc_winapps(FILE *fp, void *p_list);

void check_rc_dev(char *basedir);

void check_rc_sys(char *basedir);

void check_rc_pids();

/* Verifies if "pid" is in the proc directory */
int check_rc_readproc(int pid);

void check_rc_ports();

void check_open_ports();

void check_rc_if();


/* Global vars */
char **rk_sys_file;
char **rk_sys_name;
int rk_sys_count;


/* All the ports */
char total_ports_udp[65535 +1];
char total_ports_tcp[65535 +1];


/* Process struct */
typedef struct _Proc_Info
{
    char *p_name;
    char *p_path;
}Proc_Info;


#endif

/* EOF */
