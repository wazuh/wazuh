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
#include "labels.h"

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
int DecodeSyscollector(Eventinfo *lf);
int DecodeCiscat(Eventinfo *lf);

/* For stats */
static void DumpLogstats(void);

// Message handler thread
void * ad_input_main(void * args);

/** Global definitions **/
int today;
int thishour;
int prev_year;
char prev_month[4];
int __crt_hour;
int __crt_wday;
struct timespec c_timespec;
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

static w_queue_t * input_queue;

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

#ifdef LIBGEOIP_ENABLED
    geoipdb = NULL;
#endif


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
    mdebug1(STARTED_MSG);
    DEBUG_MSG("%s: DEBUG: Starting on debug mode - %d ", ARGV0, (int)time(0));

    srandom_init();

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group);
    }

    /* Found user */
    mdebug1(FOUND_USER);

    /* Initialize Active response */
    AR_Init();
    if (AR_ReadConfig(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }
    mdebug1(ASINIT);

    /* Read configuration file */
    if (GlobalConf(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    mdebug1(READ_CONFIG);

    if (!(Config.alerts_log || Config.jsonout_output)) {
        mwarn("All alert formats are disabled. Mail reporting, Syslog client and Integrator won't work properly.");
    }


#ifdef LIBGEOIP_ENABLED
    Config.geoip_jsonout = getDefine_Int("analysisd", "geoip_jsonout", 0, 1);

    /* Opening GeoIP DB */
    if(Config.geoipdb_file) {
        geoipdb = GeoIP_open(Config.geoipdb_file, GEOIP_INDEX_CACHE);
        if (geoipdb == NULL)
        {
            merror("Unable to open GeoIP database from: %s (disabling GeoIP).", Config.geoipdb_file);
        }
    }
#endif

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

    // Set resource limit for file descriptors

    {
        rlim_t nofile = getDefine_Int("analysisd", "rlimit_nofile", 1024, INT_MAX);
        struct rlimit rlimit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
            merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
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
#if CZMQ_VERSION_MAJOR == 2
        zeromq_output_start(Config.zeromq_output_uri);
#elif CZMQ_VERSION_MAJOR >= 3
        zeromq_output_start(Config.zeromq_output_uri, Config.zeromq_output_client_cert, Config.zeromq_output_server_cert);
#endif
    }
#endif

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Chroot */
    if (Privsep_Chroot(dir) < 0) {
        merror_exit(CHROOT_ERROR, dir, errno, strerror(errno));
    }
    nowChroot();

    Config.decoder_order_size = (size_t)getDefine_Int("analysisd", "decoder_order_size", MIN_ORDER_SIZE, MAX_DECODER_ORDER_SIZE);

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
                    merror_exit(CONFIG_ERROR,  XML_DECODER);
                }

                /* Read local ones */
                c = ReadDecodeXML(XML_LDECODER);
                if (!c) {
                    if ((c != -2)) {
                        merror_exit(CONFIG_ERROR,  XML_LDECODER);
                    }
                } else {
                    if (!test_config) {
                        minfo("Reading local decoder file.");
                    }
                }
            } else {
                /* New loaded based on file speified in ossec.conf */
                char **decodersfiles;
                decodersfiles = Config.decoders;
                while ( decodersfiles && *decodersfiles) {
                    if (!test_config) {
                        minfo("Reading decoder file %s.", *decodersfiles);
                    }
                    if (!ReadDecodeXML(*decodersfiles)) {
                        merror_exit(CONFIG_ERROR, *decodersfiles);
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
                        minfo("Reading loading the lists file: '%s'", *listfiles);
                    }
                    if (Lists_OP_LoadList(*listfiles) < 0) {
                        merror_exit(LISTS_ERROR, *listfiles);
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
                        minfo("Reading rules file: '%s'", *rulesfiles);
                    }
                    if (Rules_OP_ReadRules(*rulesfiles) < 0) {
                        merror_exit(RULES_ERROR, *rulesfiles);
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
            minfo("Total rules enabled: '%d'", total_rules);
        }
    }

    /* Create a rules hash (for reading alerts from other servers) */
    {
        RuleNode *tmp_node = OS_GetFirstRule();
        Config.g_rules_hash = OSHash_Create();
        if (!Config.g_rules_hash) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        AddHash_Rule(tmp_node);
    }

    /* Ignored files on syscheck */
    {
        char **files;
        files = Config.syscheck_ignore;
        while (files && *files) {
            if (!test_config) {
                minfo("Ignoring file: '%s'", *files);
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
    mdebug1(PRIVSEP_MSG, dir, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* Create the PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Set the queue */
    if ((m_queue = StartMQ(DEFAULTQUEUE, READ)) < 0) {
        merror_exit(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
    }

    /* Whitelist */
    if (Config.white_list == NULL) {
        if (Config.ar) {
            minfo("No IP in the white list for active response.");
        }
    } else {
        if (Config.ar) {
            os_ip **wl;
            int wlc = 0;
            wl = Config.white_list;
            while (*wl) {
                minfo("White listing IP: '%s'", (*wl)->ip);
                wl++;
                wlc++;
            }
            minfo("%d IPs in the white list for active response.", wlc);
        }
    }

    /* Hostname whitelist */
    if (Config.hostname_white_list == NULL) {
        if (Config.ar)
            minfo("No Hostname in the white list for active response.");
    } else {
        if (Config.ar) {
            int wlc = 0;
            OSMatch **wl;

            wl = Config.hostname_white_list;
            while (*wl) {
                char **tmp_pts = (*wl)->patterns;
                while (*tmp_pts) {
                    minfo("White listing Hostname: '%s'", *tmp_pts);
                    wlc++;
                    tmp_pts++;
                }
                wl++;
            }
            minfo("%d Hostname(s) in the white list for active response.",wlc);
        }
    }

    /* Startup message */
    minfo(STARTUP_MSG, (int)getpid());

    /* Going to main loop */
    OS_ReadMSG(m_queue);

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
    char * msg = NULL;
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

    /* Initialize Syscollector */
    SyscollectorInit();

    /* Initialize CIS-CAT */
    CiscatInit();

    /* Initialize host info */
    HostinfoInit();

    /* Create the event list */
    OS_CreateEventList(Config.memorysize);

    /* Initiate the FTS list */
    if (!FTS_Init()) {
        merror_exit(FTS_LIST_ERROR);
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
                merror(ARQ_ERROR);

                /* If LOCAL_AR is set, keep it there */
                if (Config.ar & LOCAL_AR) {
                    Config.ar = 0;
                    Config.ar |= LOCAL_AR;
                } else {
                    Config.ar = 0;
                }
            } else {
                minfo(CONN_TO, ARQUEUE, "active-response");
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
                merror(ARQ_ERROR);

                /* If REMOTE_AR is set, keep it there */
                if (Config.ar & REMOTE_AR) {
                    Config.ar = 0;
                    Config.ar |= REMOTE_AR;
                } else {
                    Config.ar = 0;
                }
            } else {
                minfo(CONN_TO, EXECQUEUE, "exec");
            }
        }
    }
    mdebug1("Active response Init completed.");

    /* Get current time before starting */
    gettime(&c_timespec);

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
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        stats_rule->group = "stats,";
        stats_rule->comment = "Excessive number of events (above normal).";
    }

    /* Initialize the logs */
    {
        os_calloc(1, sizeof(Eventinfo), lf);
        os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
        lf->year = prev_year;
        strncpy(lf->mon, prev_month, 3);
        lf->day = today;

        if (OS_GetLogLocation(lf) < 0) {
            merror_exit("Error allocating log files");
        }

        Free_Eventinfo(lf);
    }

    /* Initialize label cache */
    labels_init();
    Config.label_cache_maxage = getDefine_Int("analysisd", "label_cache_maxage", 0, 60);
    Config.show_hidden_labels = getDefine_Int("analysisd", "show_hidden_labels", 0, 1);

    // Create input buffer and thread

    input_queue = queue_init(Config.queue_size);
    w_create_thread(ad_input_main, &m_queue);

    mdebug1("Startup completed. Waiting for new messages..");

    if (Config.custom_alert_output) {
        mdebug1("Custom output found.!");
    }

    /* Daemon loop */
    while (1) {
        os_calloc(1, sizeof(Eventinfo), lf);
        os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
        free(msg);
        msg = NULL;

        DEBUG_MSG("%s: DEBUG: Waiting for msgs - %d ", ARGV0, (int)time(0));

        /* Receive message from queue */
        if (msg = queue_pop_ex(input_queue), msg) {
            RuleNode *rulenode_pt;

            /* Get the time we received the event */
            gettime(&c_timespec);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            /* Check for a valid message */
            if (strlen(msg) < 4) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                continue;
            }

            /* Message before extracting header */
            DEBUG_MSG("%s: DEBUG: Received msg: %s ", ARGV0, msg);

            /* Clean the msg appropriately */
            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
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
                        merror_exit("Error allocating log files");
                    }

                    today = lf->day;
                    strncpy(prev_month, lf->mon, 3);
                    prev_year = lf->year;
                }
            }

            OS_RotateLogs(lf);

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
            /* Syscollector decoding */
            else if (msg[0] == SYSCOLLECTOR_MQ) {
                if (!DecodeSyscollector(lf)) {
                    /* We don't process Syscollector events further */
                    goto CLMEM;
                }
                lf->size = strlen(lf->log);
            }
            /* CIS-CAT decoding */
            else if (msg[0] == CISCAT_MQ) {
                if (!DecodeCiscat(lf)) {
                    /* We don't process cis-cat events further */
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
                        if (Config.custom_alert_output) {
                            __crt_ftell = ftell(_aflog);
                            OS_CustomLog(lf, Config.custom_alert_output_format);
                        } else if (Config.alerts_log) {
                            __crt_ftell = ftell(_aflog);
                            OS_Log(lf);
                        } else {
                            __crt_ftell = ftell(_jflog);
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

            // Insert labels
            lf->labels = labels_find(lf);

            /* Check the rules */
            DEBUG_MSG("%s: DEBUG: Checking the rules - %d ",
                      ARGV0, lf->decoder_info->type);

            /* Loop over all the rules */
            rulenode_pt = OS_GetFirstRule();
            if (!rulenode_pt) {
                merror_exit("Rules in an inconsistent state. Exiting.");
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
                        currently_rule->time_ignored = lf->time.tv_sec;
                    }
                    /* If the current time - the time the rule was ignored
                     * is less than the time it should be ignored,
                     * leave (do not alert again)
                     */
                    else if ((lf->time.tv_sec - currently_rule->time_ignored)
                             < currently_rule->ignore_time) {
                        break;
                    } else {
                        currently_rule->time_ignored = lf->time.tv_sec;
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
                    lf->comment = ParseRuleComment(lf);

                    if (Config.custom_alert_output) {
                        __crt_ftell = ftell(_aflog);
                        OS_CustomLog(lf, Config.custom_alert_output_format);
                    } else if (Config.alerts_log) {
                        __crt_ftell = ftell(_aflog);
                        OS_Log(lf);
                    } else {
                        __crt_ftell = ftell(_jflog);
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
                                    mwarn(CRAFTED_USER, lf->dstuser);
                                }
                                do_ar = 0;
                            }
                        }
                        if ((*rule_ar)->ar_cmd->expect & SRCIP) {
                            if (!lf->srcip ||
                                    !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$")) {
                                if (lf->srcip) {
                                    mwarn(CRAFTED_IP, lf->srcip);
                                }
                                do_ar = 0;
                            }
                        }
                        if ((*rule_ar)->ar_cmd->expect & FILENAME) {
                            if (!lf->filename) {
                                do_ar = 0;
                            }
                        }

                        if (do_ar && execdq >= 0) {
                            OS_Exec(execdq, arq, lf, *rule_ar);
                        }
                        rule_ar++;
                    }
                }

                /* Copy the structure to the state memory of if_matched_sid */
                if (currently_rule->sid_prev_matched) {
                    if (!OSList_AddData(currently_rule->sid_prev_matched, lf)) {
                        merror("Unable to add data to sig list.");
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
                            merror("Unable to add data to grp list.");
                        }
                        j++;
                    }
                }

                OS_AddEvent(lf);

                break;

            } while ((rulenode_pt = rulenode_pt->next) != NULL);

            /* If configured to log all, do it */
            if (Config.logall)
                OS_Store(lf);
            if (Config.logall_json)
                jsonout_output_archive(lf);


CLMEM:
            /** Cleaning the memory **/

            /* Only clear the memory if the eventinfo was not
             * added to the stateful memory
             * -- message is free inside clean event --
             */
            if (lf->generated_rule == NULL) {
                Free_Eventinfo(lf);
            } else if (lf->generated_rule->last_events) {
                lf->generated_rule->last_events[0] = NULL;
            }
        } else {
            free(lf->fields);
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
    int i;
    const char *field;

    /* Can't be null */
    if (!rule) {
        merror("Inconsistent state. currently rule NULL");
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

    /* Checking for the URL */
    if (rule->location) {
        if (!lf->location) {
            return (NULL);
        }

        if (!OSMatch_Execute(lf->location, strlen(lf->location), rule->location)) {
            return (NULL);
        }
    }

    /* Check for dynamic fields */

    for (i = 0; i < Config.decoder_order_size && rule->fields[i]; i++) {
        field = FindField(lf, rule->fields[i]->name);

        if (!(field && OSRegex_Execute(field, rule->fields[i]->regex)))
            return NULL;
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

        /* Adding checks for geoip. */
        if(rule->srcgeoip) {
            if(lf->srcgeoip) {
                if(!OSMatch_Execute(lf->srcgeoip,
                            strlen(lf->srcgeoip),
                            rule->srcgeoip))
                    return(NULL);
            } else {
                return(NULL);
            }
        }


        if(rule->dstgeoip) {
            if(lf->dstgeoip) {
                if(!OSMatch_Execute(lf->dstgeoip,
                            strlen(lf->dstgeoip),
                            rule->dstgeoip))
                    return(NULL);
            } else {
                return(NULL);
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
                case RULE_DYNAMIC:
                    field = FindField(lf, list_holder->dfield);

                    if (!(field &&OS_DBSearch(list_holder, (char*)field)))
                        return NULL;

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
            if (rule->event_search) {
                if (!rule->event_search(lf, rule)) {
                    return (NULL);
                }
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
            merror(MKDIR_ERROR, logfile, errno, strerror(errno));
            return;
        }

    snprintf(logfile, OS_FLSIZE, "%s/%d/%s", STATSAVED, prev_year, prev_month);

    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, logfile, errno, strerror(errno));
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
        merror(FOPEN_ERROR, logfile, errno, strerror(errno));
        return;
    }

    rulenode_pt = OS_GetFirstRule();

    if (!rulenode_pt) {
        merror_exit("Rules in an inconsistent state. Exiting.");
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

// Message handler thread
void * ad_input_main(void * args) {
    int m_queue = *(int *)args;
    char buffer[OS_MAXSTR + 1] = "";
    char * copy;
    int reported = 0;

    mdebug1("Input message handler thread started.");

    while (1) {
        if (OS_RecvUnix(m_queue, OS_MAXSTR, buffer)) {
            w_mutex_lock(&input_queue->mutex);

            if (queue_full(input_queue)) {
                mdebug2("Discarding input event, head='%c'", buffer[0]);

                if (!reported) {
                    reported = 1;
                    mwarn("Input buffer is full (%zu). Events may be lost.", input_queue->size);
                }
            } else {
                os_strdup(buffer, copy);
                queue_push(input_queue, copy);
                w_cond_signal(&input_queue->available);
            }

            w_mutex_unlock(&input_queue->mutex);
        }
    }

    return NULL;
}
