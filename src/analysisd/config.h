/*   $OSSEC, config.h, v0.x, xxxx/xx/xx, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 

#ifndef _CONFIG__H

#define _CONFIG__H

#include "active-response.h"

/* Configuration structure */
typedef struct __Config
{
    int logall;
    int mailnotify;
    int ar;
    int local_ar;
    int remote_ar;
    int fts;
    int stats;
    int integrity;
    int memorysize; /* For stateful analysis */
    int keeplogdate;
    int accuracy;
    
    int mailbylevel;
    int logbylevel;

    char **syscheck_ignore;
    char **ar_ignore;
    
    int syscheck_threshold;
}_Config;


_Config Config;  /* Global Config structure */



#endif
