/*   $OSSEC, active-response.c, v0.1, 2005/10/28, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"

#include "shared.h"

#include "active-response.h"

#include "config.h"


/* Initiatiating active response */
void AS_Init()
{
    ar_commands = OSList_Create();
    active_responses = OSList_Create();

    if(!ar_commands || !active_responses)
    {
        ErrorExit(LIST_ERROR, ARGV0);
    }
    ar_flag = 0;
}

/* EOF */
