/*   $OSSEC, global-config.h, v0.1, 2006/04/06, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

 

#ifndef _CCONFIG__H
#define _CCONFIG__H
#include "shared.h"


/* Configuration structure */
typedef struct __Config
{
    u_int8_t logall;
    u_int8_t stats;
    u_int8_t integrity;
    u_int8_t syscheck_auto_ignore;
    u_int8_t syscheck_alert_new;
    u_int8_t rootcheck;
    u_int8_t hostinfo;
    u_int8_t prelude;
    u_int8_t mailbylevel;
    u_int8_t logbylevel;
    
    /* Not currently used */
    u_int8_t keeplogdate;

    /* Mail alerting */
    short int mailnotify;
    
    /* For the active response */  
    int ar;
    
    /* For the correlation */
    int memorysize;
   
    /* List of files to ignore (syscheck) */ 
    char **syscheck_ignore;

    /* List of ips to never block */
    os_ip **white_list;

    /* List of hostnames to never block */
    OSMatch **hostname_white_list;

    /* List of rules */
    char **includes;

}_Config;


#endif
