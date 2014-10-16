/* @(#) $Id: ./src/util/verify-agent-conf.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "config/localfile-config.h"
#include "config/config.h"
#include "logcollector/logcollector.h"


#undef ARGV0
#define ARGV0 "verify-agent-conf"

static void helpmsg(void) __attribute__((noreturn));

/** help **/
static void helpmsg()
{
    printf("\nOSSEC HIDS %s: Verify agent.conf syntax for errors.\n", ARGV0);
    printf("Usage:  %s [-f <agent.conf file>]\n\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-f          Full file name and path to config file to be tested.\n");
    printf("\t            If this option is not specified the following default\n");
    printf("\t            will be used.\n");
    printf(" ");
    printf("\t            Validation is successful, if no errors are shown.\n");
    exit(1);
}


/* main: v0.3: 2005/04/04 */
int main(int argc, char **argv)
{
    const char* ar=AGENTCONFIG;
    int c=0;
    int modules = 0;
    logreader_config log_config;


    /* Setting the name */
    OS_SetName(ARGV0);


    /* printf ("Agrc [%d], Argv [%s]\n", argc, *argv); */

    /* user arguments */
    if(argc > 1)
    {
        while((c = getopt(argc, argv, "Vdhf:")) != -1)
        {
            switch(c){
                case 'V':
                    print_version();
                    break;
                case 'h':
                    helpmsg();
                    break;
                case 'd':
                    nowDebug();
                    break;
                case 'f':
                    if(!optarg)
                    {
                        merror("%s: -f needs an argument",ARGV0);
                        helpmsg();
                    }
                    ar = optarg;
                    break;
                default:
                    helpmsg();
                    break;
            }

        }
    }



    printf("\n%s: Verifying [%s].\n\n", ARGV0, ar);

    modules|= CLOCALFILE;
    modules|= CAGENT_CONFIG;
    log_config.config = NULL;
    if(ReadConfig(modules, ar, &log_config, NULL) < 0)
    {
        return(OS_INVALID);
    }

    return(0);


}

/* EOF */
