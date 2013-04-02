/* @(#) $Id: ./src/syscheckd/syscheck-baseline.c, 2011/09/08 dcid Exp $
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


#include "shared.h"
#include "syscheck.h"


/* Help information for syscheck-baseline.
 */
void sb_help(char *argv0)
{
    /* -s  sleep between files.
     * -c config
     * -D workdir (where ossec is installed to read internal_options.conf)
     * -o output_file
     * -i input_file (only used with compare)
     * -v (compare)
     */
}


/* void read_internal()
 * Reads syscheck internal options.
 */
void read_internal(no_stop)
{
    if(no_stop)
    {
        syscheck.tsleep = 0;
        syscheck.sleep_after = 9999;
    }
    else
    {
        syscheck.tsleep = getDefine_Int("syscheck","sleep",1,64);
        syscheck.sleep_after = getDefine_Int("syscheck","sleep_after",1,128);
    }
    return;
}




/* Unix main.
 */
int main(int argc, char **argv)
{
    int c,r,no_stop = 1;
    int test_config = 0;

    char *cfg = DEFAULTCPATH;
    char *input_f = NULL;
    char *output_f = NULL;


    /* Zeroing the structure */
    syscheck.workdir = NULL;


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "VtdshD:c:i:o:")) != -1)
    {
        switch(c)
        {
            case 'V':
                print_version();
                break;
            case 'h':
                sb_help(ARGV0);
                break;
            case 's':
                no_stop = 0;
                break;
            case 'd':
                nowDebug();
                break;
            case 'i':
                if(!optarg)
                    ErrorExit("%s: -i needs an argument",ARGV0);
                input_f = optarg;
                break;
            case 'o':
                if(!optarg)
                    ErrorExit("%s: -o needs an argument",ARGV0);
                output_f = optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                syscheck.workdir = optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help(ARGV0);
                break;
        }
    }


    /* Checking if the configuration is present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit(NO_CONFIG, ARGV0, cfg);


    /* Read syscheck config */
    if((r = Read_Syscheck_Config(cfg)) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }
    else if((r == 1) || (syscheck.disabled == 1))
    {
        syscheck.dir[0] = NULL;
        if(!test_config)
        {
            merror("%s: WARN: Syscheck disabled.", ARGV0);
        }
    }


    /* Reading internal options */
    read_internal(no_stop);


    /* Exit if testing config */
    if(test_config)
        exit(0);


    /* Setting default values */
    if(syscheck.workdir == NULL)
        syscheck.workdir = DEFAULTDIR;


    /* Creating a temporary fp */
    syscheck.db = (char *)calloc(1024,sizeof(char));
    if(syscheck.db == NULL)
        ErrorExit(MEM_ERROR,ARGV0);

    snprintf(syscheck.db,1023, output_f);


    /* Printing options */
    #ifdef WIN32
    r = 0;
    while(syscheck.registry[r] != NULL)
    {
        verbose("%s: INFO: Monitoring registry entry: '%s'.",
                ARGV0, syscheck.registry[r]);
        r++;
    }
    #endif

    r = 0;
    while(syscheck.dir[r] != NULL)
    {
        verbose("%s: INFO: Monitoring directory: '%s'.",
                ARGV0, syscheck.dir[r]);
        r++;
    }

    /* Start the signal handling */
    StartSIG(ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());


    /* Create local database */
    create_db(0);


    fflush(syscheck.fp);


    return(0);
}


/* EOF */
