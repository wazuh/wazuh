/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"
#include "config/syscheck-config.h"
#include "syscheck.h"

static void log_realtime_status_rk(int next);

/* Report a problem */
int notify_rk(int rk_type, const char *msg)
{
    /* Non-queue notification */
    if (rootcheck.notify != QUEUE) {
        if (rk_type == ALERT_OK) {
            printf("[OK]: %s\n", msg);
        } else if (rk_type == ALERT_SYSTEM_ERR) {
            printf("[ERR]: %s\n", msg);
        } else if (rk_type == ALERT_POLICY_VIOLATION) {
            printf("[INFO]: %s\n", msg);
        } else {
            printf("[FAILED]: %s\n", msg);
        }

        printf("\n");
        return (0);
    }

    /* No need to alert on that to the server */
    if (rk_type <= ALERT_SYSTEM_ERR) {
        return (0);
    }

#ifdef OSSECHIDS
    /* When running in context of OSSEC-HIDS, send problem to the rootcheck queue */
    if (SendMSG(rootcheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ) < 0) {
        mterror(ARGV0, QUEUE_SEND);

        if ((rootcheck.queue = StartMQPredicated(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS, fim_shutdown_process_on)) < 0) {
            mterror_exit(ARGV0, QUEUE_FATAL, DEFAULTQUEUE);
        }

        if (SendMSG(rootcheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ) < 0) {
            mterror_exit(ARGV0, QUEUE_FATAL, DEFAULTQUEUE);
        }
    }
#endif

    return (0);
}

/* Execute the rootkit checks */
void run_rk_check()
{
    time_t time1;
    time_t time2;
    FILE *fp;
    OSList *plist;

#ifndef WIN32
    /* On non-Windows, always start at / */
    char basedir[] = "";
#else
    /* On Windows, always start at C:\ */
    char basedir[] = "C:";
#endif

    /* Set basedir */
    if (rootcheck.basedir == NULL || !strlen(rootcheck.basedir)) {
        free(rootcheck.basedir);
        rootcheck.basedir = strdup(basedir);
    } else {
        if (rootcheck.basedir[strlen(rootcheck.basedir)-1] == '/') {
            rootcheck.basedir[strlen(rootcheck.basedir)-1] = '\0';
        }
    }

    time1 = time(0);

    /* Initial message */
    if (rootcheck.notify != QUEUE) {
        printf("\n");
        printf("** Starting Rootcheck v0.9 by Daniel B. Cid        **\n");
        printf("** http://www.ossec.net/en/about.html#dev-team     **\n");
        printf("** http://www.ossec.net/rootcheck/                 **\n\n");
        printf("Be patient, it may take a few minutes to complete...\n");
        printf("\n");
    }

    /* Clean the global variables */
    rk_sys_count = 0;
    rk_sys_file[rk_sys_count] = NULL;
    rk_sys_name[rk_sys_count] = NULL;

    /* Send scan start message */
    notify_rk(ALERT_POLICY_VIOLATION, "Starting rootcheck scan.");
    if (rootcheck.notify == QUEUE) {
        mtinfo(ARGV0, "Starting rootcheck scan.");
    }

    /* Check for Rootkits */
    /* Open rootkit_files and pass the pointer to check_rc_files */
    if (rootcheck.checks.rc_files) {
        if (!rootcheck.rootkit_files) {
#ifndef WIN32
            mterror(ARGV0, "No rootcheck_files file configured.");
#endif
        } else {
            fp = wfopen(rootcheck.rootkit_files, "r");
            if (!fp) {
                mtwarn(ARGV0, "No rootcheck_files file: '%s'", rootcheck.rootkit_files);
            }

            else {
                check_rc_files(rootcheck.basedir, fp);
                fclose(fp);
            }
        }
    }

    /* Check for trojan entries in common binaries */
    if (rootcheck.checks.rc_trojans) {
        if (!rootcheck.rootkit_trojans) {
#ifndef WIN32
            mterror(ARGV0, "No rootcheck_trojans file configured.");
#endif
        } else {
            fp = wfopen(rootcheck.rootkit_trojans, "r");
            if (!fp) {
                mtwarn(ARGV0, "No rootcheck_trojans file: '%s'", rootcheck.rootkit_trojans);
            } else {
#ifndef HPUX
                check_rc_trojans(rootcheck.basedir, fp);
#endif
                fclose(fp);
            }
        }
    }

#ifdef WIN32
    /* Get process list */
    plist = os_get_process_list();

    /* Windows audit check */
    if (rootcheck.checks.rc_winaudit) {
        if (!rootcheck.winaudit) {
            mtinfo(ARGV0, "No winaudit file configured.");
        } else {
            fp = wfopen(rootcheck.winaudit, "r");
            if (!fp) {
                mtwarn(ARGV0, "No winaudit file: '%s'", rootcheck.winaudit);
            } else {
                check_rc_winaudit(fp, plist);
                fclose(fp);
            }
        }
    }

    /* Windows malware */
    if (rootcheck.checks.rc_winmalware) {
        if (!rootcheck.winmalware) {
            mtinfo(ARGV0, "No winmalware file configured.");
        } else {
            fp = wfopen(rootcheck.winmalware, "r");
            if (!fp) {
                mtwarn(ARGV0, "No winmalware file: '%s'", rootcheck.winmalware);
            } else {
                check_rc_winmalware(fp, plist);
                fclose(fp);
            }
        }
    }

    /* Windows Apps */
    if (rootcheck.checks.rc_winapps) {
        if (!rootcheck.winapps) {
            mtinfo(ARGV0, "No winapps file configured.");
        } else {
            fp = wfopen(rootcheck.winapps, "r");
            if (!fp) {
                mtwarn(ARGV0, "No winapps file: '%s'", rootcheck.winapps);
            } else {
                check_rc_winapps(fp, plist);
                fclose(fp);
            }
        }
    }

    /* Free the process list */
    del_plist((void *)plist);

#else
    size_t i;
    /* Checks for other non-Windows */

    /* Unix audit check ***/
    if (rootcheck.checks.rc_unixaudit) {
        if (rootcheck.unixaudit) {
            /* Get process list */
            plist = os_get_process_list();

            i = 0;
            while (rootcheck.unixaudit[i]) {
                fp = wfopen(rootcheck.unixaudit[i], "r");
                if (!fp) {
                    mtwarn(ARGV0, "No unixaudit file: '%s'", rootcheck.unixaudit[i]);
                } else {
                    /* Run unix audit */
                    check_rc_unixaudit(fp, plist);
                    fclose(fp);
                }

                i++;
            }

            /* Free list */
            del_plist(plist);
        }
    }

#endif /* !WIN32 */

    /* Check for files in the /dev filesystem */
    if (rootcheck.checks.rc_dev) {
        mtdebug1(ARGV0, "Going into check_rc_dev");
        check_rc_dev(rootcheck.basedir);
    }

    /* Scan the whole system for additional issues */
    if (rootcheck.checks.rc_sys) {
        mtdebug1(ARGV0, "Going into check_rc_sys");
        check_rc_sys(rootcheck.basedir);
    }

    /* Check processes */
    if (rootcheck.checks.rc_pids) {
        mtdebug1(ARGV0, "Going into check_rc_pids");
        check_rc_pids();
    }

    /* Check all ports */
    if (rootcheck.checks.rc_ports) {
        mtdebug1(ARGV0, "Going into check_rc_ports");
        check_rc_ports();

        /* Check open ports */
        mtdebug1(ARGV0, "Going into check_open_ports");
        check_open_ports();
    }

    /* Check interfaces */
    if (rootcheck.checks.rc_if) {
        mtdebug1(ARGV0, "Going into check_rc_if");
        check_rc_if();
    }

    mtdebug1(ARGV0, "Completed with all checks.");

    /* Clean the global memory */
    {
        int li;
        for (li = 0; li <= rk_sys_count; li++) {
            if (!rk_sys_file[li] ||
                    !rk_sys_name[li]) {
                break;
            }

            free(rk_sys_file[li]);
            free(rk_sys_name[li]);
        }
    }

    /* Final message */
    time2 = time(0);

    if (rootcheck.notify != QUEUE) {
        printf("\n");
        printf("- Scan completed in %d seconds.\n\n", (int)(time2 - time1));
    } else {
        sleep(5);
    }

    /* Send scan ending message */
    notify_rk(ALERT_POLICY_VIOLATION, "Ending rootcheck scan.");
    if (rootcheck.notify == QUEUE) {
        mtinfo(ARGV0, "Ending rootcheck scan.");
    }

    mtdebug1(ARGV0, "Leaving run_rk_check");
    return;
}

#ifdef WIN32
DWORD WINAPI w_rootcheck_thread(__attribute__((unused)) void * args){
#else
void * w_rootcheck_thread(__attribute__((unused)) void * args) {
#endif
    time_t curr_time = 0;
    time_t prev_time_rk = 0;
    syscheck_config *syscheck = args;

    while (1) {
        int run_now = 0;

        /* Check if syscheck should be restarted */
        run_now = os_check_restart_rootcheck();
        curr_time = time(0);

        /* If time elapsed is higher than the rootcheck_time, run it */
        if (syscheck->rootcheck) {
            if (((curr_time - prev_time_rk) > rootcheck.time) || run_now) {
                log_realtime_status_rk(2);
                run_rk_check();
                prev_time_rk = time(0);
            }
        }
        sleep(1);
    }

#ifndef WIN32
    return NULL;
#endif
}

void log_realtime_status_rk(int next) {
    /*
     * 0: stop (initial)
     * 1: run
     * 2: pause
     */

    static int status = 0;

    switch (status) {
    case 0:
        if (next == 1) {
            minfo("Starting rootcheck real-time monitoring.");
            status = next;
        }
        break;
    case 1:
        if (next == 2) {
            minfo("Pausing rootcheck real-time monitoring.");
            status = next;
        }
        break;
    case 2:
        if (next == 1) {
            minfo("Resuming rootcheck real-time monitoring.");
            status = next;
        }
    }
}
