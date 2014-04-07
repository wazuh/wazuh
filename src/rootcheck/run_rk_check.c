/* @(#) $Id: ./src/rootcheck/run_rk_check.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "rootcheck.h"


/* notify_rk
 * Report a problem.
 */
int notify_rk(int rk_type, char *msg)
{
    /* Non-queue notification */
    if(rootcheck.notify != QUEUE)
    {
        if(rk_type == ALERT_OK)
            printf("[OK]: %s\n", msg);
        else if(rk_type == ALERT_SYSTEM_ERR)
            printf("[ERR]: %s\n", msg);
        else if(rk_type == ALERT_POLICY_VIOLATION)
            printf("[INFO]: %s\n", msg);
        else
        {
            printf("[FAILED]: %s\n", msg);
        }

        printf("\n");
        return(0);
    }

    /* No need to alert on that to the server */
    if(rk_type <= ALERT_SYSTEM_ERR)
        return(0);

    #ifdef OSSECHIDS
    if(SendMSG(rootcheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);

        if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        if(SendMSG(rootcheck.queue,msg,ROOTCHECK,ROOTCHECK_MQ) < 0)
        {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }
    }
    #endif

    return(0);
}


/* start_rk_daemon
 * Start the rootkit daemon variables
 */
void start_rk_daemon()
{
    return;

    if(rootcheck.notify == QUEUE)
    {
    }
}


/* run_rk_check: v0.1
 * Execute the rootkit checks
 */
void run_rk_check()
{
    time_t time1;
    time_t time2;

    FILE *fp;
    OSList *plist;

    #ifndef WIN32
    /* Hard coding basedir */
    int i;
    char basedir[] = "/";

    /* Removing the last / from basedir */
    i = strlen(basedir);
    if(i > 0)
    {
        if(basedir[i-1] == '/')
        {
            basedir[i-1] = '\0';
        }
    }
    #else

    /* Basedir for Windows */
    char basedir[] = "C:\\";

    #endif


    /* Setting basedir */
    if(rootcheck.basedir == NULL)
    {
        rootcheck.basedir = basedir;
    }


    time1 = time(0);

    /*** Initial message ***/
    if(rootcheck.notify != QUEUE)
    {
        printf("\n");
        printf("** Starting Rootcheck v0.9 by Daniel B. Cid        **\n");
        printf("** http://www.ossec.net/en/about.html#dev-team     **\n");
        printf("** http://www.ossec.net/rootcheck/                 **\n\n");
        printf("Be patient, it may take a few minutes to complete...\n");
        printf("\n");
    }


    /* Cleaning the global variables */
    rk_sys_count = 0;
    rk_sys_file[rk_sys_count] = NULL;
    rk_sys_name[rk_sys_count] = NULL;



    /* Sending scan start message */
    notify_rk(ALERT_POLICY_VIOLATION, "Starting rootcheck scan.");
    if(rootcheck.notify == QUEUE)
    {
        merror("%s: INFO: Starting rootcheck scan.", ARGV0);
    }



    /***  First check, look for rootkits ***/
    /* Open rootkit_files and pass the pointer to check_rc_files */
    if (rootcheck.checks.rc_files)
    {
        if(!rootcheck.rootkit_files)
        {
            #ifndef WIN32
            merror("%s: No rootcheck_files file configured.", ARGV0);
            #endif
        }

        else
        {
            fp = fopen(rootcheck.rootkit_files, "r");
            if(!fp)
            {
                merror("%s: No rootcheck_files file: '%s'",ARGV0,
                        rootcheck.rootkit_files);
            }

            else
            {
                check_rc_files(rootcheck.basedir, fp);

                fclose(fp);
            }
        }
    }



    /*** Second check. look for trojan entries in common binaries ***/
    if (rootcheck.checks.rc_trojans)
    {
        if(!rootcheck.rootkit_trojans)
        {
            #ifndef WIN32
            merror("%s: No rootcheck_trojans file configured.", ARGV0);
            #endif
        }

        else
        {
            fp = fopen(rootcheck.rootkit_trojans, "r");
            if(!fp)
            {
                merror("%s: No rootcheck_trojans file: '%s'",ARGV0,
                                            rootcheck.rootkit_trojans);
            }

            else
            {
                #ifndef HPUX
                check_rc_trojans(rootcheck.basedir, fp);
                #endif

                fclose(fp);
            }
        }
    }



    #ifdef WIN32

    /*** Getting process list ***/
    plist = os_get_process_list();


    /*** Windows audit check ***/
    if (rootcheck.checks.rc_winaudit)
    {
        if(!rootcheck.winaudit)
        {
            merror("%s: No winaudit file configured.", ARGV0);
        }
        else
        {
            fp = fopen(rootcheck.winaudit, "r");
            if(!fp)
            {
                merror("%s: No winaudit file: '%s'",ARGV0,
                                    rootcheck.winaudit);
            }
            else
            {
                check_rc_winaudit(fp, plist);
                fclose(fp);
            }
        }
    }

    /* Windows malware */
    if (rootcheck.checks.rc_winmalware)
    {
        if(!rootcheck.winmalware)
        {
            merror("%s: No winmalware file configured.", ARGV0);
        }
        else
        {
            fp = fopen(rootcheck.winmalware, "r");
            if(!fp)
            {
                merror("%s: No winmalware file: '%s'",ARGV0,
                                                    rootcheck.winmalware);
            }
            else
            {
                check_rc_winmalware(fp, plist);
                fclose(fp);
            }
        }
    }

    /* Windows Apps */
    if (rootcheck.checks.rc_winapps)
    {
        if(!rootcheck.winapps)
        {
            merror("%s: No winapps file configured.", ARGV0);
        }
        else
        {
            fp = fopen(rootcheck.winapps, "r");
            if(!fp)
            {
                merror("%s: No winapps file: '%s'",ARGV0,
                                                rootcheck.winapps);
            }
            else
            {
                check_rc_winapps(fp, plist);
                fclose(fp);
            }
        }
    }


    /* Freeing process list */
    del_plist((void *)plist);



    /** Checks for other non Windows. **/
    #else



    /*** Unix audit check ***/
    if (rootcheck.checks.rc_unixaudit)
    {
        if(rootcheck.unixaudit)
        {
            /* Getting process list. */
            plist = os_get_process_list();


            i = 0;
            while(rootcheck.unixaudit[i])
            {
                fp = fopen(rootcheck.unixaudit[i], "r");
                if(!fp)
                {
                    merror("%s: No unixaudit file: '%s'",ARGV0,
                            rootcheck.unixaudit[i]);
                }
                else
                {
                    /* Running unix audit. */
                    check_rc_unixaudit(fp, plist);

                    fclose(fp);
                }

                i++;
            }


            /* Freeing list */
            del_plist((void *)plist);
        }
    }


    #endif


    /*** Third check, looking for files on the /dev ***/
    if (rootcheck.checks.rc_dev)
    {
        debug1("%s: DEBUG: Going into check_rc_dev", ARGV0);
        check_rc_dev(rootcheck.basedir);
    }

    /*** Fourth check,  scan the whole system looking for additional issues */
    if (rootcheck.checks.rc_sys)
    {
        debug1("%s: DEBUG: Going into check_rc_sys", ARGV0);
        check_rc_sys(rootcheck.basedir);
    }

    /*** Process checking ***/
    if (rootcheck.checks.rc_pids)
    {
        debug1("%s: DEBUG: Going into check_rc_pids", ARGV0);
        check_rc_pids();
    }

    /*** Check all the ports ***/
    if (rootcheck.checks.rc_ports)
    {
        debug1("%s: DEBUG: Going into check_rc_ports", ARGV0);
        check_rc_ports();

        /*** Check open ports ***/
        debug1("%s: DEBUG: Going into check_open_ports", ARGV0);
        check_open_ports();
    }

    /*** Check interfaces ***/
    if (rootcheck.checks.rc_if)
    {
        debug1("%s: DEBUG: Going into check_rc_if", ARGV0);
        check_rc_if();
    }


    debug1("%s: DEBUG: Completed with all checks.", ARGV0);


    /* Cleaning the global memory */
    {
        int li;
        for(li = 0;li <= rk_sys_count; li++)
        {
            if(!rk_sys_file[li] ||
               !rk_sys_name[li])
                break;

            free(rk_sys_file[li]);
            free(rk_sys_name[li]);
        }
    }

    /*** Final message ***/
    time2 = time(0);

    if(rootcheck.notify != QUEUE)
    {
        printf("\n");
        printf("- Scan completed in %d seconds.\n\n", (int)(time2 - time1));
    }
    else
    {
        sleep(5);
    }


    /* Sending scan ending message */
    notify_rk(ALERT_POLICY_VIOLATION, "Ending rootcheck scan.");
    if(rootcheck.notify == QUEUE)
    {
        merror("%s: INFO: Ending rootcheck scan.", ARGV0);
    }


    debug1("%s: DEBUG: Leaving run_rk_check",ARGV0);
    return;
}


/* EOF */
