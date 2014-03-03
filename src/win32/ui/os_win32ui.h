/* @(#) $Id: ./src/win32/ui/os_win32ui.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
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
#define NEWCONFIG       "new-ossec.conf"
#define LASTCONFIG      "last-ossec.conf"
#define VERSION_FILE    "VERSION.txt"
#define OSSECLOGS       "ossec.log"
#define HELPTXT         "help.txt"
#define AUTH_FILE       "client.keys"
#define SENDER_FILE     "rids\\sender_counter"
#define DEFDIR          "C:\\Program Files\\ossec-agent"


/* Status messages */
#define ST_RUNNING          "Running..."
#define ST_RUNNING_RESTART  "Running (pending restart)"
#define ST_STOPPED          "Stopped."
#define ST_UNKNOWN          "Unknown."
#define ST_NOTSET           "0"
#define ST_MISSING_IMPORT   "Require import of authentication key.\r\n" \
                            "            - Not Running..."
#define ST_MISSING_SERVER   "Require OSSEC Server IP address.\r\n" \
                            "            - Not Running..."
#define ST_MISSING_ALL      "Require import of authentication key.\r\n" \
                            "            Missing OSSEC Server IP address.\r\n" \
                            "            - Not Running..."



/* Pre-def fields */
#define FL_NOKEY        "<insert_auth_key_here>"
#define FL_NOSERVER     "<insert_server_ip_here>"
#define SERVER_IP_USED      1
#define SERVER_HOST_USED    2


/* Prototypes */
char *decode_base64(const char *src);
char *encode_base64(int size, char *src);


/* Global ossec config structure */
typedef struct _ossec_config
{
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
    char *install_date;
    char *status;
}ossec_config;


/** Global variables **/

/* Agent status */
char ui_server_info[2048 +1];

/* Configuration */
ossec_config config_inst;

/* Status bar */
HWND hStatus;



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

/* cat file */
char *cat_file(char *file, FILE *fp2);

/* is_file present */
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

/* EOF */
