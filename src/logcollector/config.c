/*   $OSSEC, config.c, v0.3, 2005/08/23, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.3 (2005/08/23): Using the new OS_XML syntax and changing some usage 
 * v0.2 (2005/01/17)
 */
 

#include "shared.h" 

#include "logcollector.h"


/* LogCollectorConfig v0.3, 2005/03/03
 * Read the config file (the localfiles)
 * v0.3: Changed for the new OS_XML
 */
int LogCollectorConfig(char * cfgfile)
{
    int modules = 0;

    modules|= CLOCALFILE;

    log[0].file = NULL;

    if(ReadConfig(modules, cfgfile, log, NULL) < 0)
        return(OS_INVALID);

    return(1);


}

/* EOF */
