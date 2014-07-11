/* @(#) $Id: ./src/monitord/report.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"



/* ossec-reportd - Runs manual reports. */
void report_help()
{
    printf("\nOSSEC HIDS %s: Generate reports (via stdin).\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h                  This help message.\n");
    printf("\t-f <filter> <value> Filter the results.\n");
    printf("\t-r <filter> <value> Show related entries.\n");
    printf("\t-n                  Creates a description for the report.\n");
    printf("\t-s                  Show the alert dump.\n");
    printf("\n");
    printf("\tFilters allowed: group, rule, level, location,\n");
    printf("\t                 user, srcip, filename\n");
    printf("\n");
    printf("Examples:\n");
    printf("\t-f group authentication_success (to filter on login success).\n");
    printf("\t-f level 10  (to filter on level >= 10).\n");
    printf("\t-f group authentication -r user srcip (to show the srcip for all users).\n");
    exit(1);
}



int main(int argc, char **argv)
{
    int c, test_config = 0;
    int uid=0,gid=0;
    char *dir  = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    // TODO: delete or implement
    char *cfg __attribute__((unused)) = DEFAULTCPATH;

    char *filter_by = NULL;
    char *filter_value = NULL;

    char *related_of = NULL;
    char *related_values = NULL;
    report_filter r_filter;


    /* Setting the name */
    OS_SetName(ARGV0);

    r_filter.group = NULL;
    r_filter.rule = NULL;
    r_filter.level = NULL;
    r_filter.location = NULL;
    r_filter.srcip = NULL;
    r_filter.user = NULL;
    r_filter.files = NULL;
    r_filter.show_alerts = 0;

    r_filter.related_group = 0;
    r_filter.related_rule = 0;
    r_filter.related_level = 0;
    r_filter.related_location = 0;
    r_filter.related_srcip = 0;
    r_filter.related_user = 0;
    r_filter.related_file = 0;

    r_filter.report_name = NULL;

    while((c = getopt(argc, argv, "Vdhstu:g:D:c:f:v:n:r:")) != -1)
    {
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                report_help();
                break;
            case 'd':
                nowDebug();
                break;
            case 'n':
                if(!optarg)
                    ErrorExit("%s: -n needs an argument",ARGV0);
                r_filter.report_name = optarg;
                break;
            case 'r':
                if(!optarg || !argv[optind])
                    ErrorExit("%s: -r needs two argument",ARGV0);
                related_of = optarg;
                related_values = argv[optind];

                if(os_report_configfilter(related_of, related_values,
                                          &r_filter, REPORT_RELATED) < 0)
                {
                    ErrorExit(CONFIG_ERROR, ARGV0, "user argument");
                }
                optind++;
                break;
            case 'f':
                if(!optarg)
                    ErrorExit("%s: -f needs two argument",ARGV0);
                filter_by = optarg;
                filter_value = argv[optind];

                if(os_report_configfilter(filter_by, filter_value,
                                          &r_filter, REPORT_FILTER) < 0)
                {
                    ErrorExit(CONFIG_ERROR, ARGV0, "user argument");
                }
                optind++;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 's':
                r_filter.show_alerts = 1;
                break;
            default:
                report_help();
                break;
        }

    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);



    /* Exit here if test config is set */
    if(test_config)
        exit(0);


    /* Privilege separation */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    nowChroot();



    /* Changing user */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    debug1(PRIVSEP_MSG,ARGV0,dir,user);



    /* Signal manipulation */
    StartSIG(ARGV0);



    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* the real stuff now */
    os_ReportdStart(&r_filter);
    exit(0);
}


/* EOF */
