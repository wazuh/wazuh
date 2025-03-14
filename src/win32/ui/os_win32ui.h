/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN_32UI_H
#define WIN_32UI_H

#include <stdio.h>
#include <unistd.h>
#include <windows.h>
#include <winresrc.h>
#include <commctrl.h>

/* Default values */
#define CONFIG          "ossec.conf"
#define LASTCONFIG      "last-ossec.conf"
#define VERSION_FILE    "VERSION.json"
#define REVISION_FILE   "REVISION"
#define OSSECLOGS       "ossec.log"
#define HELPTXT         "help.txt"
#define SENDER_FILE     "rids\\sender_counter"
#define DEFDIR          "C:\\Program Files\\ossec-agent"

/* Status messages */
#define ST_RUNNING          "Running"
#define ST_RUNNING_RESTART  "Running (pending restart)"
#define ST_STOPPED          "Stopped"
#define ST_UNKNOWN          "Unknown"
#define ST_NOTSET           "0"
#define ST_MISSING_IMPORT   "Require import of authentication key.\r\n" \
                            "            - Not Running"
#define ST_MISSING_SERVER   "Require Manager IP address.\r\n" \
                            "            - Not Running"
#define ST_MISSING_ALL      "Require import of authentication key.\r\n" \
                            "            Missing Manager IP address.\r\n" \
                            "            - Not Running"

/* Pre-def fields */
#define FL_NOKEY        "<insert_auth_key_here>"
#define FL_NOSERVER     "<insert_server_ip_here>"
#define SERVER_IP_USED      1
#define SERVER_HOST_USED    2

/* Global ossec config structure */
typedef struct _ossec_config {
    unsigned short int server_type;
    unsigned short int admin_access;
    unsigned long int msg_sent;
    char *dir;
    char *config;
    char *key;
    char *server;

    char *agentid;
    char *agentname;
    char *agentip;

    char *version;
    char *revision;
    char *status;
} ossec_config;


/** Global variables **/

/* Configuration */
extern ossec_config config_inst;

/* Status bar */
extern HWND hStatus;

/* Ossec icon */
#define IDI_OSSECICON  201
#define UI_MANIFEST_ID 202

/* User input */
#define UI_SERVER_TEXT      1501
#define UI_SERVER_AUTH      1502
#define UI_SERVER_MSG       1503
#define UI_SERVER_TOP       1504
#define UI_SERVER_INFO      1505
#define UI_ID_CLOSE         1510

/* Menu values */
#define UI_MENU_MANAGE_STOP     1601
#define UI_MENU_MANAGE_START    1602
#define UI_MENU_MANAGE_STATUS   1603
#define UI_MENU_MANAGE_RESTART  1604
#define UI_MENU_MANAGE_EXIT     1605
#define UI_MENU_VIEW_LOGS       1606
#define UI_MENU_VIEW_CONFIG     1607
#define UI_MENU_HELP_HELP       1608
#define UI_MENU_HELP_ABOUT      1609
#define UI_MENU_NONE            1610

#define IDD_MAIN                1700
#define IDC_MAIN_STATUS         1701
#define IDC_ADD                 1702
#define IDC_CANCEL              1703
#define IDD_ABOUT               1704
#define IDC_STATIC -1

/** Prototypes **/

/* Generate server info */
int gen_server_info(HWND hwnd);

char *cat_file(char *file, FILE *fp2);

int is_file(char *file);

/* Reads ossec config */
int config_read(HWND hwnd);

/* Initializes the config */
void init_config();

/* Run command using cmd.exe */
int run_cmd(char *cmd, HWND hwnd);

/* Set OSSEC Server IP */
int set_ossec_server(char *ip, HWND hwnd);

/* Set OSSEC Auth Key */
int set_ossec_key(char *key, HWND hwnd);

/* Get OSSEC Server IP */
int get_ossec_server();


#endif
