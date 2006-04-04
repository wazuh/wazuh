/*    $OSSEC, win_agent.c, v0.1, 2006/04/03, Daniel B. Cid$    */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifdef WIN32

#include "shared.h"

#ifndef ARGV0
#define ARGV0 ossec-agent
#endif


/** int WinAgent()
 * Main process of the windows agent
 */
int os_WinAgent()
{
}


/** main(int argc, char **argv)
 * ..
 */
int main(int argc, char **argv)
{
    
    OS_SetName(ARGV0);

    if(argc > 1)
    {
        if(strcmp(argv[1], "install-service") == 0)
        {
            /* Call install service */
        }
        if(strcmp(argv[1], "uninstall-service") == 0)
        {
            /* Call to uninstall */
        }
        else
        {
            merror("%s: Unknown option: %s", ARGV0, argv[1]);
        }
    }


    /* Read agent config */
    if((binds = ClientConf(DEFAULTCPATH)) == 0)
        ErrorExit(CLIENT_ERROR,ARGV0);

                    
                    
    /* Just start it */
}

#endif
/* EOF */
