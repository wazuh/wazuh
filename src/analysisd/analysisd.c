/* Copyright (C) 2010-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* ossec-analysisd
 * Responsible for correlation and log decoding
 */

#ifndef ARGV0
#define ARGV0 "ossec-analysisd"
#endif

#include "shared.h"
#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "os_execd/execd.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "eventinfo.h"
#include "accumulator.h"
#include "analysisd.h"
#include "fts.h"
#include "cleanevent.h"
#include "dodiff.h"
#include "output/jsonout.h"

#ifdef PICVIZ_OUTPUT_ENABLED
#include "output/picviz.h"
#endif

#ifdef PRELUDE_OUTPUT_ENABLED
#include "output/prelude.h"
#endif

#ifdef ZEROMQ_OUTPUT_ENABLED
#include "output/zeromq.h"
#endif

/** Prototypes **/
void OS_ReadMSG(int m_queue);
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node);
static void LoopRule(RuleNode *curr_node, FILE *flog);

/* For decoders */
void DecodeEvent(Eventinfo *lf);
int DecodeSyscheck(Eventinfo *lf);
int DecodeRootcheck(Eventinfo *lf);
int DecodeHostinfo(Eventinfo *lf);

/* For stats */
static void DumpLogstats(void);

/** Global definitions **/
int today;
int thishour;
int prev_year;
char prev_month[4];
int __crt_hour;
int __crt_wday;
time_t c_time;
char __shost[512];
OSDecoderInfo *NULL_Decoder;

/* execd queue */
static int execdq = 0;

/* Active response queue */
static int arq = 0;

static int hourly_alerts;
static int hourly_events;
static int hourly_syscheck;
static int hourly_firewall;


/* Print help statement */
__attribute__((noreturn))
static void help_analysisd(void)
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
    print_out(" ");
    exit(1);
}

#ifndef TESTRULE
int main(int argc, char **argv)
#else
__attribute__((noreturn))
int main_analysisd(int argc, char **argv)
#endif
{
    int c = 0, m_queue = 0, test_config = 0, run_foreground = 0;
    int debug_level = 0;
    const char *dir = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    uid_t uid;
    gid_t gid;

    const char *cfg = DEFAULTCPATH;

    /* Set the name */
    OS_SetName(ARGV0);

    thishour = 0;
    today = 0;
    prev_year = 0;
    memset(prev_month, '\0', 4);
    hourly_alerts = 0;
    hourly_events = 0;
    hourly_syscheck = 0;
    hourly_firewall = 0;

    while ((c = getopt(argc, argv, "Vtdhfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_analysisd();
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
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_analysisd();
                break;
        }

    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("analysisd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);
    DEBUG_MSG("%s: DEBUG: Starting on debug mode - %d ", ARGV0, (int)time(0));

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Found user */
    debug1(FOUND_USER, ARGV0);

    /* Initialize Active response */
    AR_Init();
    if (AR_ReadConfig(cfg) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }
    debug1(ASINIT, ARGV0);

    /* Read configuration file */
    if (GlobalConf(cfg) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    debug1(READ_CONFIG, ARGV0);

    /* Fix Config.ar */
    Config.ar = ar_flag;
    if (Config.ar == -1) {
        Config.ar = 0;
    }

    /* Get server's hostname */
    memset(__shost, '\0', 512);
    if (gethostname(__shost, 512 - 1) != 0) {
        strncpy(__shost, OSSEC_SERVER, 512 - 1);
    } else {
        char *_ltmp;

        /* Remove domain part if available */
        _ltmp = strchr(__shost, '.');
        if (_ltmp) {
            *_ltmp = '\0';
        }
    }

    /* Continuing in Daemon mode */
    if (!test_config && !run_foreground) {
        nowDaemon();
        goDaemon();
    }

#ifdef PRELUDE_OUTPUT_ENABLED
    /* Start prelude */
    if (Config.prelude) {
        prelude_start(Config.prelude_profile, argc, argv);
    }
#endif

#ifdef ZEROMQ_OUTPUT_ENABLED
    /* Start zeromq */
    if (Config.zeromq_output) {
        zeromq_output_start(Config.zeromq_output_uri);
    }
#endif

#ifdef PICVIZ_OUTPUT_ENABLED
    /* Open the Picviz socket */
    if (Config.picviz) {
        OS_PicvizOpen(Config.picviz_socket);

        if (chown(Config.picviz_socket, uid, gid) == -1) {
            ErrorExit(CHOWN_ERROR, ARGV0, Config.picviz_socket, errno, strerror(errno));
        }
    }
#endif

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }
    nowChroot();

    /*
     * Anonymous Section: Load rules, decoders, and lists
     *
     * As lists require two-pass loading of rules that makes use of lists, lookups
     * are created with blank database structs, and need to be filled in after
     * completion of all rules and lists.
     */
    {
        {
            /* Initialize the decoders list */
            OS_CreateOSDecoderList();

            if (!Config.decoders) {
                /* Legacy loading */
                /* Read decoders */
                if (!ReadDecodeXML(XML_DECODER)) {
                    ErrorExit(CONFIG_ERROR, ARGV0,  XML_DECODER);
                }

                /* Read local ones */
                c = ReadDecodeXML(XML_LDECODER);
                if (!c) {
                    if ((c != -2)) {
                        ErrorExit(CONFIG_ERROR, ARGV0,  XML_LDECODER);
                    }
                } else {
                    if (!test_config) {
                        verbose("%s: INFO: Reading local decoder file.", ARGV0);
                    }
                }
            } else {
                /* New loaded based on file speified in ossec.conf */
                char **decodersfiles;
                decodersfiles = Config.decoders;
                while ( decodersfiles && *decodersfiles) {
                    if (!test_config) {
                        verbose("%s: INFO: Reading decoder file %s.", ARGV0, *decodersfiles);
                    }
                    if (!ReadDecodeXML(*decodersfiles)) {
                        ErrorExit(CONFIG_ERROR, ARGV0, *decodersfiles);
                    }

                    free(*decodersfiles);
                    decodersfiles++;
                }
            }

            /* Load decoders */
            SetDecodeXML();
        }
        {
            /* Load Lists */
            /* Initialize the lists of list struct */
            Lists_OP_CreateLists();
            /* Load each list into list struct */
            {
                char **listfiles;
                listfiles = Config.lists;
                while (listfiles && *listfiles) {
                    if (!test_config) {
                        verbose("%s: INFO: Reading loading the lists file: '%s'", ARGV0, *listfiles);
                    }
                    if (Lists_OP_LoadList(*listfiles) < 0) {
                        ErrorExit(LISTS_ERROR, ARGV0, *listfiles);
                    }
                    free(*listfiles);
                    listfiles++;
                }
                free(Config.lists);
                Config.lists = NULL;
            }
        }

        {
            /* Load Rules */
            /* Create the rules list */
            Rules_OP_CreateRules();

            /* Read the rules */
            {
                char **rulesfiles;
                rulesfiles = Config.includes;
                while (rulesfiles && *rulesfiles) {
                    if (!test_config) {
                        verbose("%s: INFO: Reading rules file: '%s'", ARGV0, *rulesfiles);
                    }
                    if (Rules_OP_ReadRules(*rulesfiles) < 0) {
                        ErrorExit(RULES_ERROR, ARGV0, *rulesfiles);
                    }

                    free(*rulesfiles);
                    rulesfiles++;
                }

                free(Config.includes);
                Config.includes = NULL;
            }

            /* Find all rules that require list lookups and attache the the
             * correct list struct to the rule. This keeps rules from having to
             * search thought the list of lists for the correct file during
             * rule evaluation.
             */
            OS_ListLoadRules();
        }
    }

    /* Fix the levels/accuracy */
    {
        int total_rules;
        RuleNode *tmp_node = OS_GetFirstRule();

        total_rules = _setlevels(tmp_node, 0);
        if (!test_config) {
            verbose("%s: INFO: Total rules enabled: '%d'", ARGV0, total_rules);
        }
    }

    /* Create a rules hash (for reading alerts from other servers) */
    {
        RuleNode *tmp_node = OS_GetFirstRule();
        Config.g_rules_hash = OSHash_Create();
        if (!Config.g_rules_hash) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }
        AddHash_Rule(tmp_node);
    }

    /* Ignored files on syscheck */
    {
        char **files;
        files = Config.syscheck_ignore;
        while (files && *files) {
            if (!test_config) {
                verbose("%s: INFO: Ignoring file: '%s'", ARGV0, *files);
            }
            files++;
        }
    }

    /* Check if log_fw is enabled */
    Config.logfw = (u_int8_t) getDefine_Int("analysisd",
                                 "log_fw",
                                 0, 1);

    /* Success on the configuration test */
    if (test_config) {
        exit(0);
    }

    /* Verbose message */
    debug1(CHROOT_MSG, ARGV0, dir);
    debug1(PRIVSEP_MSG, ARGV0, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Create the PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Set the queue */
    if ((m_queue = StartMQ(DEFAULTQUEUE, READ)) < 0) {
        ErrorExit(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));
    }

    /* Whitelist */
    if (Config.white_list == NULL) {
        if (Config.ar) {
            verbose("%s: INFO: No IP in the white list for active reponse.", ARGV0);
        }
    } else {
        if (Config.ar) {
            os_ip **wl;
            int wlc = 0;
            wl = Config.white_list;
            while (*wl) {
                verbose("%s: INFO: White listing IP: '%s'", ARGV0, (*wl)->ip);
                wl++;
                wlc++;
            }
            verbose("%s: INFO: %d IPs in the white list for active response.",
                    ARGV0, wlc);
        }
    }

    /* Hostname whitelist */
    if (Config.hostname_white_list == NULL) {
        if (Config.ar)
            verbose("%s: INFO: No Hostname in the white list for active reponse.",
                    ARGV0);
    } else {
        if (Config.ar) {
            int wlc = 0;
            OSMatch **wl;

            wl = Config.hostname_white_list;
            while (*wl) {
                char **tmp_pts = (*wl)->patterns;
                while (*tmp_pts) {
                    verbose("%s: INFO: White listing Hostname: '%s'", ARGV0, *tmp_pts);
                    wlc++;
                    tmp_pts++;
                }
                wl++;
            }
            verbose("%s: INFO: %d Hostname(s) in the white list for active response.",
                    ARGV0, wlc);
        }
    }

    /* Startup message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* Going to main loop */
    OS_ReadMSG(m_queue);

#ifdef PICVIZ_OUTPUT_ENABLED
    if (Config.picviz) {
        OS_PicvizClose();
    }
#endif

    exit(0);
}

/* Main function. Receives the messages(events) and analyze them all */
#ifndef TESTRULE
__attribute__((noreturn))
void OS_ReadMSG(int m_queue)
#else
__attribute__((noreturn))
void OS_ReadMSG_analysisd(int m_queue)
#endif
{
    int i;
    char msg[OS_MAXSTR + 1];
    Eventinfo *lf;

    RuleInfo *stats_rule = NULL;

    /* Null to global currently pointers */
    currently_rule = NULL;

    /* Initialize the logs */
    OS_InitLog();

    /* Initialize the integrity database */
    SyscheckInit();

    /* Initialize Rootcheck */
    RootcheckInit();

    /* Initialize host info */
    HostinfoInit();

    /* Create the event list */
    OS_CreateEventList(Config.memorysize);

    /* Initiate the FTS list */
    if (!FTS_Init()) {
        ErrorExit(FTS_LIST_ERROR, ARGV0);
    }

    /* Initialize the Accumulator */
    if (!Accumulate_Init()) {
        merror("accumulator: ERROR: Initialization failed");
        exit(1);
    }

    /* Start the active response queues */
    if (Config.ar) {
        /* Waiting the ARQ to settle */
        sleep(3);

#ifndef LOCAL
        if (Config.ar & REMOTE_AR) {
            if ((arq = StartMQ(ARQUEUE, WRITE)) < 0) {
                merror(ARQ_ERROR, ARGV0);

                /* If LOCAL_AR is set, keep it there */
                if (Config.ar & LOCAL_AR) {
                    Config.ar = 0;
                    Config.ar |= LOCAL_AR;
                } else {
                    Config.ar = 0;
                }
            } else {
                verbose(CONN_TO, ARGV0, ARQUEUE, "active-response");
            }
        }
#else
        /* Only for LOCAL_ONLY installs */
        if (Config.ar & REMOTE_AR) {
            if (Config.ar & LOCAL_AR) {
                Config.ar = 0;
                Config.ar |= LOCAL_AR;
            } else {
                Config.ar = 0;
            }
        }
#endif

        if (Config.ar & LOCAL_AR) {
            if ((execdq = StartMQ(EXECQUEUE, WRITE)) < 0) {
                merror(ARQ_ERROR, ARGV0);

                /* If REMOTE_AR is set, keep it there */
                if (Config.ar & REMOTE_AR) {
                    Config.ar = 0;
                    Config.ar |= REMOTE_AR;
                } else {
                    Config.ar = 0;
                }
            } else {
                verbose(CONN_TO, ARGV0, EXECQUEUE, "exec");
            }
        }
    }
    debug1("%s: DEBUG: Active response Init completed.", ARGV0);

    /* Get current time before starting */
    c_time = time(NULL);

    /* Start the hourly/weekly stats */
    if (Start_Hour() < 0) {
        Config.stats = 0;
    } else {
        /* Initialize stats rules */
        stats_rule = zerorulemember(
                         STATS_MODULE,
                         Config.stats,
                         0, 0, 0, 0, 0, 0);

        if (!stats_rule) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }
        stats_rule->group = "stats,";
        stats_rule->comment = "Excessive number of events (above normal).";
    }

    /* Do some cleanup */
    memset(msg, '\0', OS_MAXSTR + 1);

    /* Initialize the logs */
    {
        lf = (Eventinfo *)calloc(1, sizeof(Eventinfo));
        if (!lf) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }
        lf->year = prev_year;
        strncpy(lf->mon, prev_month, 3);
        lf->day = today;

        if (OS_GetLogLocation(lf) < 0) {
            ErrorExit("%s: Error allocating log files", ARGV0);
        }

        Free_Eventinfo(lf);
    }

    debug1("%s: DEBUG: Startup completed. Waiting for new messages..", ARGV0);

    if (Config.custom_alert_output) {
        debug1("%s: INFO: Custom output found.!", ARGV0);
    }

    /* Daemon loop */
    while (1) {
        lf = (Eventinfo *)calloc(1, sizeof(Eventinfo));

        /* This shouldn't happen */
        if (lf == NULL) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        DEBUG_MSG("%s: DEBUG: Waiting for msgs - %d ", ARGV0, (int)time(0));

        /* Receive message from queue */
        if ((i = OS_RecvUnix(m_queue, OS_MAXSTR, msg))) {
            RuleNode *rulenode_pt;

            /* Get the time we received the event */
            c_time = time(NULL);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            /* Check for a valid message */
            if (i < 4) {
                merror(IMSG_ERROR, ARGV0, msg);
                Free_Eventinfo(lf);
                continue;
            }

            /* Message before extracting header */
            DEBUG_MSG("%s: DEBUG: Received msg: %s ", ARGV0, msg);

            /* Clean the msg appropriately */
            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, ARGV0, msg);
                Free_Eventinfo(lf);
                continue;
            }

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            /* Current rule must be null in here */
            currently_rule = NULL;

            /** Check the date/hour changes **/

            /* Update the hour */
            if (thishour != __crt_hour) {
                /* Search all the rules and print the number
                 * of alerts that each one fired
                 */
                DumpLogstats();
                thishour = __crt_hour;

                /* Check if the date has changed */
                if (today != lf->day) {
                    if (Config.stats) {
                        /* Update the hourly stats (done daily) */
                        Update_Hour();
                    }

                    if (OS_GetLogLocation(lf) < 0) {
                        ErrorExit("%s: Error allocating log files", ARGV0);
                    }

                    today = lf->day;
                    strncpy(prev_month, lf->mon, 3);
                    prev_year = lf->year;
                }
            }


            /* Increment number of events received */
            hourly_events++;

            /***  Run decoders ***/

            /* Integrity check from syscheck */
            if (msg[0] == SYSCHECK_MQ) {
                hourly_syscheck++;

                if (!DecodeSyscheck(lf)) {
                    /* We don't process syscheck events further */
                    goto CLMEM;
                }

                /* Get log size */
                lf->size = strlen(lf->log);
            }

            /* Rootcheck decoding */
            else if (msg[0] == ROOTCHECK_MQ) {
                if (!DecodeRootcheck(lf)) {
                    /* We don't process rootcheck events further */
                    goto CLMEM;
                }
                lf->size = strlen(lf->log);
            }

            /* Host information special decoder */
            else if (msg[0] == HOSTINFO_MQ) {
                if (!DecodeHostinfo(lf)) {
                    /* We don't process hostinfo events further */
                    goto CLMEM;
                }
                lf->size = strlen(lf->log);
            }

            /* Run the general Decoders */
            else {
                /* Get log size */
                lf->size = strlen(lf->log);

                DecodeEvent(lf);
            }

            /* Run accumulator */
            if ( lf->decoder_info->accumulate == 1 ) {
                lf = Accumulate(lf);
            }

            /* Firewall event */
            if (lf->decoder_info->type == FIREWALL) {
                /* If we could not get any information from
                 * the log, just ignore it
                 */
                hourly_firewall++;
                if (Config.logfw) {
                    if (!FW_Log(lf)) {
                        goto CLMEM;
                    }
                }
            }

            /* We only check if the last message is
             * duplicated on syslog
             */
            else if (lf->decoder_info->type == SYSLOG) {
                /* Check if the message is duplicated */
                if (LastMsg_Stats(lf->full_log) == 1) {
                    goto CLMEM;
                } else {
                    LastMsg_Change(lf->full_log);
                }
            }

            /* Stats checking */
            if (Config.stats) {
                if (Check_Hour() == 1) {
                    RuleInfo *saved_rule = lf->generated_rule;
                    char *saved_log;

                    /* Save previous log */
                    saved_log = lf->full_log;

                    lf->generated_rule = stats_rule;
                    lf->full_log = __stats_comment;

                    /* Alert for statistical analysis */
                    if (stats_rule->alert_opts & DO_LOGALERT) {
                        __crt_ftell = ftell(_aflog);
                        if (Config.custom_alert_output) {
                            OS_CustomLog(lf, Config.custom_alert_output_format);
                        } else {
                            OS_Log(lf);
                        }
                        /* Log to json file */
                        if (Config.jsonout_output) {
                            jsonout_output_event(lf);
                        }

                    }

                    /* Set lf to the old values */
                    lf->generated_rule = saved_rule;
                    lf->full_log = saved_log;
                }
            }

            /* Check the rules */
            DEBUG_MSG("%s: DEBUG: Checking the rules - %d ",
                      ARGV0, lf->decoder_info->type);

            /* Loop over all the rules */
            rulenode_pt = OS_GetFirstRule();
            if (!rulenode_pt) {
                ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                          ARGV0);
            }

            do {
                if (lf->decoder_info->type == OSSEC_ALERT) {
                    if (!lf->generated_rule) {
                        goto CLMEM;
                    }

                    /* Process the alert */
                    currently_rule = lf->generated_rule;
                }

                /* Categories must match */
                else if (rulenode_pt->ruleinfo->category !=
                         lf->decoder_info->type) {
                    continue;
                }

                /* Check each rule */
                else if ((currently_rule = OS_CheckIfRuleMatch(lf, rulenode_pt))
                         == NULL) {
                    continue;
                }

                /* Ignore level 0 */
                if (currently_rule->level == 0) {
                    break;
                }

                /* Check ignore time */
                if (currently_rule->ignore_time) {
                    if (currently_rule->time_ignored == 0) {
                        currently_rule->time_ignored = lf->time;
                    }
                    /* If the current time - the time the rule was ignored
                     * is less than the time it should be ignored,
                     * leave (do not alert again)
                     */
                    else if ((lf->time - currently_rule->time_ignored)
                             < currently_rule->ignore_time) {
                        break;
                    } else {
                        currently_rule->time_ignored = lf->time;
                    }
                }

                /* Pointer to the rule that generated it */
                lf->generated_rule = currently_rule;

                /* Check if we should ignore it */
                if (currently_rule->ckignore && IGnore(lf)) {
                    /* Ignore rule */
                    lf->generated_rule = NULL;
                    break;
                }

                /* Check if we need to add to ignore list */
                if (currently_rule->ignore) {
                    AddtoIGnore(lf);
                }

                /* Log the alert if configured to */
                if (currently_rule->alert_opts & DO_LOGALERT) {
                    __crt_ftell = ftell(_aflog);

                    if (Config.custom_alert_output) {
                        OS_CustomLog(lf, Config.custom_alert_output_format);
                    } else {
                        OS_Log(lf);
                    }
                    /* Log to json file */
                    if (Config.jsonout_output) {
                        jsonout_output_event(lf);
                    }
                }

#ifdef PRELUDE_OUTPUT_ENABLED
                /* Log to prelude */
                if (Config.prelude) {
                    if (Config.prelude_log_level <= currently_rule->level) {
                        OS_PreludeLog(lf);
                    }
                }
#endif

#ifdef ZEROMQ_OUTPUT_ENABLED
                /* Log to zeromq */
                if (Config.zeromq_output) {
                    zeromq_output_event(lf);
                }
#endif


#ifdef PICVIZ_OUTPUT_ENABLED
                /* Log to Picviz */
                if (Config.picviz) {
                    OS_PicvizLog(lf);
                }
#endif

                /* Execute an active response */
                if (currently_rule->ar) {
                    int do_ar;
                    active_response **rule_ar;

                    rule_ar = currently_rule->ar;

                    while (*rule_ar) {
                        do_ar = 1;
                        if ((*rule_ar)->ar_cmd->expect & USERNAME) {
                            if (!lf->dstuser ||
                                    !OS_PRegex(lf->dstuser, "^[a-zA-Z._0-9@?-]*$")) {
                                if (lf->dstuser) {
                                    merror(CRAFTED_USER, ARGV0, lf->dstuser);
                                }
                                do_ar = 0;
                            }
                        }
                        if ((*rule_ar)->ar_cmd->expect & SRCIP) {
                            if (!lf->srcip ||
                                    !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$")) {
                                if (lf->srcip) {
                                    merror(CRAFTED_IP, ARGV0, lf->srcip);
                                }
                                do_ar = 0;
                            }
                        }
                        if ((*rule_ar)->ar_cmd->expect & FILENAME) {
                            if (!lf->filename) {
                                do_ar = 0;
                            }
                        }

                        if (do_ar) {
                            OS_Exec(execdq, arq, lf, *rule_ar);
                        }
                        rule_ar++;
                    }
                }

                /* Copy the structure to the state memory of if_matched_sid */
                if (currently_rule->sid_prev_matched) {
                    if (!OSList_AddData(currently_rule->sid_prev_matched, lf)) {
                        merror("%s: Unable to add data to sig list.", ARGV0);
                    } else {
                        lf->sid_node_to_delete =
                            currently_rule->sid_prev_matched->last_node;
                    }
                }
                /* Group list */
                else if (currently_rule->group_prev_matched) {
                    unsigned int j = 0;

                    while (j < currently_rule->group_prev_matched_sz) {
                        if (!OSList_AddData(
                                    currently_rule->group_prev_matched[j],
                                    lf)) {
                            merror("%s: Unable to add data to grp list.", ARGV0);
                        }
                        j++;
                    }
                }

                OS_AddEvent(lf);

                break;

            } while ((rulenode_pt = rulenode_pt->next) != NULL);

            /* If configured to log all, do it */
            if (Config.logall) {
                OS_Store(lf);
            }

CLMEM:
            /** Cleaning the memory **/

            /* Only clear the memory if the eventinfo was not
             * added to the stateful memory
             * -- message is free inside clean event --
             */
            if (lf->generated_rule == NULL) {
                Free_Eventinfo(lf);
            }
        } else {
            free(lf);
        }
    }
}

/* Checks if the current_rule matches the event information */
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node)
{
    /* We check for:
     * decoded_as,
     * fts,
     * word match (fast regex),
     * regex,
     * url,
     * id,
     * user,
     * maxsize,
     * protocol,
     * srcip,
     * dstip,
     * srcport,
     * dstport,
     * time,
     * weekday,
     * status,
     */
    RuleInfo *rule = curr_node->ruleinfo;

    /* Can't be null */
    if (!rule) {
        merror("%s: Inconsistent state. currently rule NULL", ARGV0);
        return (NULL);
    }

#ifdef TESTRULE
    if (full_output && !alert_only)
        print_out("    Trying rule: %d - %s", rule->sigid,
                  rule->comment);
#endif

    /* Check if any decoder pre-matched here */
    if (rule->decoded_as &&
            rule->decoded_as != lf->decoder_info->id) {
        return (NULL);
    }

    /* Check program name */
    if (rule->program_name) {
        if (!lf->program_name) {
            return (NULL);
        }

        if (!OSMatch_Execute(lf->program_name,
                             lf->p_name_size,
                             rule->program_name)) {
            return (NULL);
        }
    }

    /* Check for the ID */
    if (rule->id) {
        if (!lf->id) {
            return (NULL);
        }

        if (!OSMatch_Execute(lf->id,
                             strlen(lf->id),
                             rule->id)) {
            return (NULL);
        }
    }

    /* Check if any word to match exists */
    if (rule->match) {
        if (!OSMatch_Execute(lf->log, lf->size, rule->match)) {
            return (NULL);
        }
    }

    /* Check if exist any regex for this rule */
    if (rule->regex) {
        if (!OSRegex_Execute(lf->log, rule->regex)) {
            return (NULL);
        }
    }

    /* Check for actions */
    if (rule->action) {
        if (!lf->action) {
            return (NULL);
        }

        if (strcmp(rule->action, lf->action) != 0) {
            return (NULL);
        }
    }

    /* Checking for the URL */
    if (rule->url) {
        if (!lf->url) {
            return (NULL);
        }

        if (!OSMatch_Execute(lf->url, strlen(lf->url), rule->url)) {
            return (NULL);
        }
    }

    /* Get TCP/IP packet information */
    if (rule->alert_opts & DO_PACKETINFO) {
        /* Check for the srcip */
        if (rule->srcip) {
            if (!lf->srcip) {
                return (NULL);
            }

            if (!OS_IPFoundList(lf->srcip, rule->srcip)) {
                return (NULL);
            }
        }

        /* Check for the dstip */
        if (rule->dstip) {
            if (!lf->dstip) {
                return (NULL);
            }

            if (!OS_IPFoundList(lf->dstip, rule->dstip)) {
                return (NULL);
            }
        }

        if (rule->srcport) {
            if (!lf->srcport) {
                return (NULL);
            }

            if (!OSMatch_Execute(lf->srcport,
                                 strlen(lf->srcport),
                                 rule->srcport)) {
                return (NULL);
            }
        }
        if (rule->dstport) {
            if (!lf->dstport) {
                return (NULL);
            }

            if (!OSMatch_Execute(lf->dstport,
                                 strlen(lf->dstport),
                                 rule->dstport)) {
                return (NULL);
            }
        }
    } /* END PACKET_INFO */

    /* Extra information from event */
    if (rule->alert_opts & DO_EXTRAINFO) {
        /* Check compiled rule */
        if (rule->compiled_rule) {
            if (!rule->compiled_rule(lf)) {
                return (NULL);
            }
        }

        /* Checking if exist any user to match */
        if (rule->user) {
            if (lf->dstuser) {
                if (!OSMatch_Execute(lf->dstuser,
                                     strlen(lf->dstuser),
                                     rule->user)) {
                    return (NULL);
                }
            } else if (lf->srcuser) {
                if (!OSMatch_Execute(lf->srcuser,
                                     strlen(lf->srcuser),
                                     rule->user)) {
                    return (NULL);
                }
            } else {
                /* no user set */
                return (NULL);
            }
        }

        /* Check if any rule related to the size exist */
        if (rule->maxsize) {
            if (lf->size < rule->maxsize) {
                return (NULL);
            }
        }

        /* Check if we are in the right time */
        if (rule->day_time) {
            if (!OS_IsonTime(lf->hour, rule->day_time)) {
                return (NULL);
            }
        }

        /* Check week day */
        if (rule->week_day) {
            if (!OS_IsonDay(__crt_wday, rule->week_day)) {
                return (NULL);
            }
        }

        /* Get extra data */
        if (rule->extra_data) {
            if (!lf->data) {
                return (NULL);
            }

            if (!OSMatch_Execute(lf->data,
                                 strlen(lf->data),
                                 rule->extra_data)) {
                return (NULL);
            }
        }

        /* Check hostname */
        if (rule->hostname) {
            if (!lf->hostname) {
                return (NULL);
            }

            if (!OSMatch_Execute(lf->hostname,
                                 strlen(lf->hostname),
                                 rule->hostname)) {
                return (NULL);
            }
        }

        /* Check for status */
        if (rule->status) {
            if (!lf->status) {
                return (NULL);
            }

            if (!OSMatch_Execute(lf->status,
                                 strlen(lf->status),
                                 rule->status)) {
                return (NULL);
            }
        }


        /* Do diff check */
        if (rule->context_opts & SAME_DODIFF) {
            if (!doDiff(rule, lf)) {
                return (NULL);
            }
        }
    }

    /* Check for the FTS flag */
    if (rule->alert_opts & DO_FTS) {
        /** FTS CHECKS **/
        if (lf->decoder_info->fts) {
            if (lf->decoder_info->fts & FTS_DONE) {
                /* We already did the fts in here */
            } else if (!FTS(lf)) {
                return (NULL);
            }
        } else {
            return (NULL);
        }
    }

    /* List lookups */
    if (rule->lists != NULL) {
        ListRule *list_holder = rule->lists;
        while (list_holder) {
            switch (list_holder->field) {
                case RULE_SRCIP:
                    if (!lf->srcip) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->srcip)) {
                        return (NULL);
                    }
                    break;
                case RULE_SRCPORT:
                    if (!lf->srcport) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->srcport)) {
                        return (NULL);
                    }
                    break;
                case RULE_DSTIP:
                    if (!lf->dstip) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->dstip)) {
                        return (NULL);
                    }
                    break;
                case RULE_DSTPORT:
                    if (!lf->dstport) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->dstport)) {
                        return (NULL);
                    }
                    break;
                case RULE_USER:
                    if (lf->srcuser) {
                        if (!OS_DBSearch(list_holder, lf->srcuser)) {
                            return (NULL);
                        }
                    } else if (lf->dstuser) {
                        if (!OS_DBSearch(list_holder, lf->dstuser)) {
                            return (NULL);
                        }
                    } else {
                        return (NULL);
                    }
                    break;
                case RULE_URL:
                    if (!lf->url) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->url)) {
                        return (NULL);
                    }
                    break;
                case RULE_ID:
                    if (!lf->id) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->id)) {
                        return (NULL);
                    }
                    break;
                case RULE_HOSTNAME:
                    if (!lf->hostname) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->hostname)) {
                        return (NULL);
                    }
                    break;
                case RULE_PROGRAM_NAME:
                    if (!lf->program_name) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->program_name)) {
                        return (NULL);
                    }
                    break;
                case RULE_STATUS:
                    if (!lf->status) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->status)) {
                        return (NULL);
                    }
                    break;
                case RULE_ACTION:
                    if (!lf->action) {
                        return (NULL);
                    }
                    if (!OS_DBSearch(list_holder, lf->action)) {
                        return (NULL);
                    }
                    break;
                default:
                    return (NULL);
            }

            list_holder = list_holder->next;
        }
    }

    /* If it is a context rule, search for it */
    if (rule->context == 1) {
        if (!(rule->context_opts & SAME_DODIFF)) {
            if (!rule->event_search(lf, rule)) {
                return (NULL);
            }
        }
    }

#ifdef TESTRULE
    if (full_output && !alert_only) {
        print_out("       *Rule %d matched.", rule->sigid);
    }
#endif

    /* Search for dependent rules */
    if (curr_node->child) {
        RuleNode *child_node = curr_node->child;
        RuleInfo *child_rule = NULL;

#ifdef TESTRULE
        if (full_output && !alert_only) {
            print_out("       *Trying child rules.");
        }
#endif

        while (child_node) {
            child_rule = OS_CheckIfRuleMatch(lf, child_node);
            if (child_rule != NULL) {
                return (child_rule);
            }

            child_node = child_node->next;
        }
    }

    /* If we are set to no alert, keep going */
    if (rule->alert_opts & NO_ALERT) {
        return (NULL);
    }

    hourly_alerts++;
    rule->firedtimes++;

    return (rule); /* Matched */
}

/*  Update each rule and print it to the logs */
static void LoopRule(RuleNode *curr_node, FILE *flog)
{
    if (curr_node->ruleinfo->firedtimes) {
        fprintf(flog, "%d-%d-%d-%d\n",
                thishour,
                curr_node->ruleinfo->sigid,
                curr_node->ruleinfo->level,
                curr_node->ruleinfo->firedtimes);
        curr_node->ruleinfo->firedtimes = 0;
    }

    if (curr_node->child) {
        RuleNode *child_node = curr_node->child;

        while (child_node) {
            LoopRule(child_node, flog);
            child_node = child_node->next;
        }
    }
    return;
}

/* Dump the hourly stats about each rule */
static void DumpLogstats()
{
    RuleNode *rulenode_pt;
    char logfile[OS_FLSIZE + 1];
    FILE *flog;

    /* Open log file */
    snprintf(logfile, OS_FLSIZE, "%s/%d/", STATSAVED, prev_year);
    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, ARGV0, logfile, errno, strerror(errno));
            return;
        }

    snprintf(logfile, OS_FLSIZE, "%s/%d/%s", STATSAVED, prev_year, prev_month);

    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, ARGV0, logfile, errno, strerror(errno));
            return;
        }


    /* Creat the logfile name */
    snprintf(logfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             STATSAVED,
             prev_year,
             prev_month,
             "totals",
             today);

    flog = fopen(logfile, "a");
    if (!flog) {
        merror(FOPEN_ERROR, ARGV0, logfile, errno, strerror(errno));
        return;
    }

    rulenode_pt = OS_GetFirstRule();

    if (!rulenode_pt) {
        ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                  ARGV0);
    }

    /* Loop over all the rules and print their stats */
    do {
        LoopRule(rulenode_pt, flog);
    } while ((rulenode_pt = rulenode_pt->next) != NULL);


    /* Print total for the hour */
    fprintf(flog, "%d--%d--%d--%d--%d\n\n",
            thishour,
            hourly_alerts, hourly_events, hourly_syscheck, hourly_firewall);
    hourly_alerts = 0;
    hourly_events = 0;
    hourly_syscheck = 0;
    hourly_firewall = 0;

    fclose(flog);
}

