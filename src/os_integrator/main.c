/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#include "integrator.h"
#include "shared.h"

IntegratorConfig **integrator_config;

void help(const char *prog)
{
    print_out(" ");
    print_out("%s %s - %s (%s)", __ossec_name, __ossec_version, __author, __contact);
    print_out("%s", __site);
    print_out(" ");
    print_out("  %s: -[Vhdt] [-u user] [-g group] [-c config] [-D dir]", prog);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   Run as 'user'");
    print_out("    -g <group>  Run as 'group'");
    print_out("    -c <config> Read the 'config' file");
    print_out("    -D <dir>    Chroot to 'dir'");
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int i = 0;
    int c = 0;
    int test_config = 0;
    int uid = 0;
    int gid = 0;
    int run_foreground = 0;
    int debug_level = 0;

    /* Highly recommended not to run as root. However, some integrations
     * may require it. */
    char *dir  = DEFAULTDIR;
    char *user = MAILUSER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    integrator_config = NULL;

    /* Setting the name */
    OS_SetName(ARGV0);

    while((c = getopt(argc, argv, "Vdhtfu:g:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'u':
                if(!optarg)
                    merror_exit("-u needs an argument");
                user = optarg;
                break;
            case 'g':
                if(!optarg)
                    merror_exit("-g needs an argument");
                group = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            default:
                help(ARGV0);
                break;
        }
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("integrator", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    /* Starting daemon */
    mdebug1(STARTED_MSG);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
    {
        merror_exit(USER_ERROR, user, group);
    }

    /* Reading configuration */
    if(!OS_ReadIntegratorConf(cfg, &integrator_config) || !integrator_config[0])
    {
        /* Not configured */
        minfo("Remote integrations not configured. "
                "Clean exit.");
        exit(0);
    }

    /* Exit here if test config is set */
    if(test_config)
        exit(0);

    /* Pid before going into daemon mode. */
    i = getpid();

    /* Going on daemon mode */

    if (!run_foreground) {
        nowDaemon();
        goDaemonLight();
    }

    /* Creating some randomness  */
    #ifdef __OpenBSD__
    srandomdev();
    #else
    srandom( time(0) + getpid()+ i);
    #endif

    os_random();

    /* Privilege separation */
    if(Privsep_SetGroup(gid) < 0)
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));

    /* Changing user */
    if(Privsep_SetUser(uid) < 0)
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));

    // Start com request thread
    w_create_thread(intgcom_main, NULL);

    /* Basic start up completed. */
    mdebug1(PRIVSEP_MSG ,dir,user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        merror_exit(PID_ERROR);

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* the real daemon now */
    OS_IntegratorD(integrator_config);
    exit(0);
}
