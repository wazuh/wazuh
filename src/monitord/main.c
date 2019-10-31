/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config/config.h"
#include "monitord.h"
#include "os_net/os_net.h"

int no_agents = 0;

/* Prototypes */
static void help_monitord(void) __attribute__((noreturn));


/* Print help statement */
static void help_monitord()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -n          Disable agent monitoring.");
    print_out("    -w <sec>    Time (sec.) to wait before rotating logs and alerts.");
    print_out(" ");
    exit(1);
}

static void init_conf()
{
    mond.enabled = 0;
    mond.max_size = 0;
    mond.interval = 24;
    mond.rotate = -1;
    mond.rotation_enabled = 1;
    mond.compress_rotation = 1;
    mond.ossec_log_plain = 0;
    mond.ossec_log_json = 0;
    mond.min_size_rotate = 0;
    mond.size_rotate = 0;
    mond.interval_units = 'h';
    mond.size_units = mond.min_size_units ='B';
    mond.maxage = 31;
    mond.day_wait = mond.day_wait == -1 ? 10 : mond.day_wait;
    mond.log_level = options.monitor.log_level.def;
    mond.monitor_agents = no_agents ? 0 : options.monitor.monitor_agents.def;
    mond.delete_old_agents = options.monitor.delete_old_agents.def;
    mond.thread_stack_size = options.global.thread_stack_size.def;

    return;
}

static void read_internal()
{
    int aux;

    if ((aux = getDefine_Int("monitord", "rotate_log", 0, 1)) != INT_OPT_NDEF)
        mond.rotation_enabled = aux;
    if ((aux = getDefine_Int("monitord", "size_rotate", 0, 4096)) != INT_OPT_NDEF) {
        mond.max_size = (unsigned long) aux * 1024 * 1024;
        mond.size_rotate = (unsigned long) aux;
        mond.size_units = 'M';              // Internal options has only MBytes available
    }
    if ((aux = getDefine_Int("monitord", "compress", 0, 1)) != INT_OPT_NDEF)
        mond.compress_rotation = aux;
    if ((aux = getDefine_Int("monitord", "day_wait", 0, MAX_DAY_WAIT)) != INT_OPT_NDEF)
        mond.day_wait = (short) aux;
    if ((aux = getDefine_Int("monitord", "keep_log_days", 0, 500)) != INT_OPT_NDEF)
        mond.maxage = aux;
    if ((aux = getDefine_Int("monitord", "debug", 0, 2)) != INT_OPT_NDEF)
        mond.log_level = aux;
    if ((aux = getDefine_Int("monitord", "monitor_agents", 0, 1)) != INT_OPT_NDEF)
        mond.monitor_agents = no_agents ? 0 : aux;
    if ((aux = getDefine_Int("monitord", "delete_old_agents", 0, 9600)) != INT_OPT_NDEF)
        mond.delete_old_agents = aux;
    if ((aux = getDefine_Int("wazuh", "thread_stack_size", options.global.thread_stack_size.min, options.global.thread_stack_size.max)) != INT_OPT_NDEF )
        mond.thread_stack_size = aux;

    return;
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;
    char * end;
    int debug_level = 0;

    /* Initialize global variables */
    mond.a_queue = 0;
    mond.day_wait = -1;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:nw:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_monitord();
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'n':
                no_agents = 1;
                break;
            case 'w':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }

                if (mond.day_wait = (short)strtol(optarg, &end, 10), !end || *end || mond.day_wait < 0 || mond.day_wait > MAX_DAY_WAIT) {
                    merror_exit("Invalid value for option -%c.", c);
                }

                break;
            default:
                help_monitord();
                break;
        }

    }

    /* Start daemon */
    mdebug1(STARTED_MSG);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group);
    }

    mond.agents = NULL;
    mond.smtpserver = NULL;
    mond.emailfrom = NULL;
    mond.emailidsname = NULL;

    init_conf();

    c = 0;
    c |= CREPORTS;
    c |= CROTMONITORD;
    if (ReadConfig(c, cfg, &mond, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    read_internal();

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = mond.log_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    /* If we have any reports configured, read smtp/emailfrom */
    if (mond.reports) {
        OS_XML xml;
        char *tmpsmtp;

        const char *(xml_smtp[]) = {"ossec_config", "global", "smtp_server", NULL};
        const char *(xml_from[]) = {"ossec_config", "global", "email_from", NULL};
        const char *(xml_idsname[]) = {"ossec_config", "global", "email_idsname", NULL};

        if (OS_ReadXML(cfg, &xml) < 0) {
            merror_exit(CONFIG_ERROR, cfg);
        }

        tmpsmtp = OS_GetOneContentforElement(&xml, xml_smtp);
        mond.emailfrom = OS_GetOneContentforElement(&xml, xml_from);
        mond.emailidsname = OS_GetOneContentforElement(&xml, xml_idsname);

        if (tmpsmtp && mond.emailfrom) {
            if (tmpsmtp[0] == '/') {
                os_strdup(tmpsmtp, mond.smtpserver);
            } else {
                mond.smtpserver = OS_GetHost(tmpsmtp, 5);
                if (!mond.smtpserver) {
                    merror(INVALID_SMTP, tmpsmtp);
                    if (mond.emailfrom) {
                        free(mond.emailfrom);
                    }
                    mond.emailfrom = NULL;
                    merror("Invalid SMTP server.  Disabling email reports.");
                }
            }
        } else {
            if (tmpsmtp) {
                free(tmpsmtp);
            }
            if (mond.emailfrom) {
                free(mond.emailfrom);
            }

            mond.emailfrom = NULL;
            merror("SMTP server or 'email from' missing. Disabling email reports.");
        }

        OS_ClearXML(&xml);
    }

    // Do not monitor agents in client nodes

    OS_XML cl_xml;
    const char * xmlf[] = {"ossec_config", "cluster", "disabled", NULL};
    const char * xmlf2[] = {"ossec_config", "cluster", "node_type", NULL};

    if (OS_ReadXML(cfg, &cl_xml) < 0) {
        mdebug1(XML_ERROR, cfg, cl_xml.err, cl_xml.err_line);
    } else {
        // Read the cluster status and the node type from the configuration file
        char * cl_status = OS_GetOneContentforElement(&cl_xml, xmlf);
        if (cl_status && cl_status[0] != '\0') {
            if (!strncmp(cl_status, "no", 2)) {
                char * cl_type = OS_GetOneContentforElement(&cl_xml, xmlf2);
                if (cl_type && cl_type[0] != '\0') {
                    if (!strncmp(cl_type, "client", 6) || !strncmp(cl_type, "worker", 6)) {
                        mdebug1("Cluster client node: Disabled the agent monitoring");
                        mond.monitor_agents = 0;
                    }
                    free(cl_type);
                }
            }

            free(cl_status);
        }
    }
    OS_ClearXML(&cl_xml);

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }

    nowChroot();

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    mdebug1(PRIVSEP_MSG, dir, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real daemon now */
    Monitord();
    exit(0);
}
