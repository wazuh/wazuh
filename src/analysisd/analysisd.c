/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

/* wazuh-analysisd
 * Responsible for correlation and log decoding
 */

#ifndef ARGV0
#define ARGV0 "wazuh-analysisd"
#endif

#include "shared.h"
#include <time.h>
#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif
#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "os_execd/execd.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "active-response.h"
#include "config.h"
#include "limits.h"
#include "rules.h"
#include "mitre.h"
#include "stats.h"
#include "eventinfo.h"
#include "accumulator.h"
#include "analysisd.h"
#include "fts.h"
#include "cleanevent.h"
#include "output/jsonout.h"
#include "labels.h"
#include "state.h"
#include "syscheck_op.h"
#include "lists_make.h"

#ifdef PRELUDE_OUTPUT_ENABLED
#include "output/prelude.h"
#endif

#ifdef ZEROMQ_OUTPUT_ENABLED
#include "output/zeromq.h"
#endif

/** Prototypes **/
void OS_ReadMSG(int m_queue);
static void LoopRule(RuleNode *curr_node, FILE *flog);

/* For decoders */
int DecodeSyscheck(Eventinfo *lf, _sdb *sdb);
int decode_fim_event(_sdb *sdb, Eventinfo *lf); // Decode events in json format
int DecodeRootcheck(Eventinfo *lf);
int DecodeHostinfo(Eventinfo *lf);
int DecodeSyscollector(Eventinfo *lf, int *socket);
int DecodeCiscat(Eventinfo *lf, int *socket);
int DecodeWinevt(Eventinfo *lf);
int DecodeSCA(Eventinfo *lf, int *socket);
void DispatchDBSync(dbsync_context_t * ctx, Eventinfo * lf);

// Init sdb and decoder struct
void sdb_init(_sdb *localsdb, OSDecoderInfo *fim_decoder);

/* For stats */
static void DumpLogstats(void);

/* For hot reload ruleset */
typedef struct _w_hotreload_ruleset_data_t
{
    // Ruleset data
    RuleNode* rule_list; ///< Rule list [os_analysisd_rulelist]
    OSDecoderNode*
        decoderlist_forpname; ///< Decoder list to match logs which have a program name [os_analysisd_decoderlist_pn]
    OSDecoderNode* decoderlist_nopname; ///< Decoder list to match logs which haven't a program name
                                        ///< [os_analysisd_decoderlist_nopn]
    OSStore* decoder_store;             ///< Decoder list to save internals decoders [os_analysisd_decoder_store]
    ListNode* cdblistnode;              ///< List of CDB lists [os_analysisd_cdblists]
    ListRule* cdblistrule;              ///< List to attach rules and CDB lists [os_analysisd_cdbrules]
    EventList* eventlist;               ///< Previous events list [os_analysisd_last_events]
    OSHash* rules_hash;                 ///< Hash table of rules [Config.g_rules_hash]
    OSList* fts_list;                   ///< Save FTS previous events [os_analysisd_fts_list]
    OSHash* fts_store;                  ///< Save FTS values processed [os_analysisd_fts_store]
    OSHash* acm_store;                  ///< Hash to save data which have the same id [os_analysisd_acm_store]
    int acm_lookups;     ///< Counter of the number of times purged. Option accumulate [os_analysisd_acm_lookups]
    time_t acm_purge_ts; ///< Counter of the time interval of last purge. Option accumulate [os_analysisd_acm_purge_ts]
    // Config data
    char** decoders; ///< List of decoders [Config.decoders]
    char** includes; ///< List of rules [Config.includes]
    char** lists;    ///< List of lists [Config.lists]

} w_hotreload_ruleset_data_t;

// Hot reload ruleset
void w_hotreload_reload_internal_decoders();
w_hotreload_ruleset_data_t* w_hotreload_switch_ruleset(w_hotreload_ruleset_data_t* new_ruleset);
w_hotreload_ruleset_data_t* w_hotreload_create_ruleset(OSList* list_msg);
void w_hotreload_clean_ruleset(w_hotreload_ruleset_data_t** ptr_ruleset);
bool w_hotreload_ruleset_load(_Config* ruleset_config, OSList* list_msg);
bool w_hotreload_ruleset_load_config(OS_XML* xml,
    XML_NODE conf_section_nodes,
    _Config* ruleset_config,
    OSList* list_msg);

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
int num_rule_matching_threads;
OSHash *analysisd_agents_state;
socket_forwarder* forwarder_socket_list;

extern analysisd_state_t analysisd_state;

/* execd queue */
static int execdq = 0;

/* Active response queue */
static int arq = 0;

static unsigned int hourly_events;
static unsigned int hourly_syscheck;
static unsigned int hourly_firewall;

/* Archives writer thread */
void * w_writer_thread(__attribute__((unused)) void * args );

/* Alerts log writer thread */
void * w_writer_log_thread(__attribute__((unused)) void * args );

/* Statistical writer thread */
void * w_writer_log_statistical_thread(__attribute__((unused)) void * args );

/* Firewall log writer thread */
void * w_writer_log_firewall_thread(__attribute__((unused)) void * args );

/* FTS log writer thread */
void * w_writer_log_fts_thread(__attribute__((unused)) void * args );

/* Flush logs thread */
void w_log_flush();

/* Decode syscollector threads */
void * w_decode_syscollector_thread(__attribute__((unused)) void * args);

/* Decode syscheck threads */
void * w_decode_syscheck_thread(__attribute__((unused)) void * args);

/* Decode hostinfo threads */
void * w_decode_hostinfo_thread(__attribute__((unused)) void * args);

/* Decode rootcheck threads */
void * w_decode_rootcheck_thread(__attribute__((unused)) void * args);

/* Decode Security Configuration Assessment threads */
void * w_decode_sca_thread(__attribute__((unused)) void * args);

/* Decode event threads */
void * w_decode_event_thread(__attribute__((unused)) void * args);

/* Process decoded event - rule matching threads */
void * w_process_event_thread(__attribute__((unused)) void * id);

/* Do log rotation thread */
void * w_log_rotate_thread(__attribute__((unused)) void * args);

/* Decode winevt threads */
void * w_decode_winevt_thread(__attribute__((unused)) void * args);

/* Database synchronization thread */
static void * w_dispatch_dbsync_thread(void * args);

static void * w_dispatch_upgrade_module_thread(__attribute__((unused)) void *args);

typedef struct _clean_msg {
    Eventinfo *lf;
    char *msg;
} clean_msg;

typedef struct _decode_event {
    Eventinfo *lf;
    char type;
} decode_event;

typedef struct _osmatch_exec {
    Eventinfo *lf;
    RuleInfo *rule;
} _osmatch_execute;

/* Archives writer queue */
w_queue_t * writer_queue;

/* Alerts log writer queue */
w_queue_t * writer_queue_log;

/* Statistical log writer queue */
w_queue_t * writer_queue_log_statistical;

/* Firewall log writer queue */
w_queue_t * writer_queue_log_firewall;

/* Decode syscheck input queue */
w_queue_t * decode_queue_syscheck_input;

/* Decode syscollector input queue */
w_queue_t * decode_queue_syscollector_input;

/* Decode rootcheck input queue */
w_queue_t * decode_queue_rootcheck_input;

/* Decode policy monitoring input queue */
w_queue_t * decode_queue_sca_input;

/* Decode hostinfo input queue */
w_queue_t * decode_queue_hostinfo_input;

/* Decode event input queue */
w_queue_t * decode_queue_event_input;

/* Decode pending event output */
w_queue_t * decode_queue_event_output;

/* Decode windows event input queue */
w_queue_t * decode_queue_winevt_input;

/* Database synchronization input queue */
w_queue_t * dispatch_dbsync_input;

/* Upgrade module decoder  */
w_queue_t * upgrade_module_input;

/* Hourly firewall mutex */
static pthread_mutex_t hourly_firewall_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Accumulate mutex */
static pthread_mutex_t accumulate_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t current_time_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Reported variables */
static int reported_syscheck = 0;
static int reported_syscollector = 0;
static int reported_hostinfo = 0;
static int reported_rootcheck = 0;
static int reported_sca = 0;
static int reported_event = 0;
static int reported_writer = 0;
static int reported_winevt = 0;
static int reported_dbsync;
static int reported_upgrade_module = 0;
static int reported_eps_drop = 0;
static int reported_eps_drop_hourly = 0;

/* Mutexes */
pthread_mutex_t process_event_check_hour_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t process_event_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Hourly alerts mutex */
pthread_mutex_t hourly_alert_mutex = PTHREAD_MUTEX_INITIALIZER;
/* hot reload mutes */
static pthread_rwlock_t g_hotreload_ruleset_mutex = PTHREAD_RWLOCK_INITIALIZER;

/* Reported mutexes */
static pthread_mutex_t writer_threads_mutex = PTHREAD_MUTEX_INITIALIZER;

/* To translate between month (int) to month (char) */
static const char *(month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                  };

/* CPU Info*/
static int cpu_cores;

static time_t current_time;

/* Print help statement */
__attribute__((noreturn))
static void help_analysisd(char * home_path)
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
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out("    -D <dir>    Directory to chroot and chdir into (default: %s)", home_path);
    print_out(" ");
    os_free(home_path);
    exit(1);
}

#ifndef TESTRULE
#ifdef WAZUH_UNIT_TESTING
__attribute((weak))
#endif
int main(int argc, char **argv)
#else
__attribute__((noreturn))
int main_analysisd(int argc, char **argv)
#endif
{
    int c = 0, m_queue = 0, test_config = 0, run_foreground = 0;
    int debug_level = 0;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    uid_t uid;
    gid_t gid;

    const char *cfg = OSSECCONF;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

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
                help_analysisd(home_path);
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
                snprintf(home_path, PATH_MAX, "%s", optarg);
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
                help_analysisd(home_path);
                break;
        }

    }

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    sys_debug_level = getDefine_Int("analysisd", "debug", 0, 2);

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = sys_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Start daemon */
    DEBUG_MSG("%s: DEBUG: Starting on debug mode - %d ", ARGV0, (int)time(0));

    srandom_init();

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
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

/* Check sockets */
    if (Config.socket_list && Config.forwarders_list) {
        forwarder_socket_list = Config.socket_list;

        for(int num_sk = 0; forwarder_socket_list && forwarder_socket_list[num_sk].name; num_sk++) {
            mdebug1("Socket '%s' (%s) added. Location: %s", forwarder_socket_list[num_sk].name, forwarder_socket_list[num_sk].mode == IPPROTO_UDP ? "udp" : "tcp", forwarder_socket_list[num_sk].location);
        }

        for (int target_num = 0; Config.forwarders_list[target_num]; target_num++) {
            int found = -1;
            for (int num_sk = 0; forwarder_socket_list && forwarder_socket_list[num_sk].name; num_sk++) {
                found = strcmp(forwarder_socket_list[num_sk].name, Config.forwarders_list[target_num]);
                if (found == 0) {
                    break;
                } else if (found != 0) {
                    mwarn("Socket for target '%s' is not defined.", Config.forwarders_list[target_num]);
                }
            }
        }
    }

    /* Get server's hostname */
    memset(__shost, '\0', 512);
    if (gethostname(__shost, 512 - 1) != 0) {
        strncpy(__shost, WAZUH_SERVER, 512 - 1);
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
        nofile = getDefine_Int("analysisd", "rlimit_nofile", 1024, 1048576);
        struct rlimit rlimit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
            merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
        }
    }

    /* Check the CPU INFO */
    /* If we have the threads set to 0 on internal_options.conf, then */
    /* we assign them automatically based on the number of cores */
    cpu_cores = get_nproc();

    num_rule_matching_threads = getDefine_Int("analysisd", "rule_matching_threads", 0, 32);

    if(num_rule_matching_threads == 0){
        num_rule_matching_threads = cpu_cores;
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
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }
    nowChroot();

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* Verbose message */
    mdebug1(PRIVSEP_MSG, home_path, user);
    os_free(home_path);

    if (!test_config) {
        /* Signal manipulation */
        StartSIG(ARGV0);

        /* Create the PID file */
        if (CreatePID(ARGV0, getpid()) < 0) {
            merror_exit(PID_ERROR);
        }

        /* Set the queue */
        if ((m_queue = StartMQ(DEFAULTQUEUE, READ, 0)) < 0) {
            merror_exit(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
        }
    }

    Config.decoder_order_size = (size_t)getDefine_Int("analysisd", "decoder_order_size", MIN_ORDER_SIZE, MAX_DECODER_ORDER_SIZE);

    if (!os_analysisd_last_events) {
        os_calloc(1, sizeof(EventList), os_analysisd_last_events);
        OS_CreateEventList(Config.memorysize, os_analysisd_last_events);
    }

    /*
     * Anonymous Section: Load rules, decoders, and lists
     *
     * As lists require two-pass loading of rules that makes use of lists, lookups
     * are created with blank database structs, and need to be filled in after
     * completion of all rules and lists.
     */
    {
        {
            /* Error and warning messages */
            char * msg;
            OSList * list_msg = OSList_Create();
            OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);
            OSListNode * node_log_msg;
            int error_exit = 0;

            /* Initialize the decoders list */
            OS_CreateOSDecoderList();

            /* If we haven't specified a decoders directory, load default */
            if (!Config.decoders) {
                /* Legacy loading */
                /* Read default decoders */
                Read_Rules(NULL, &Config, NULL);
            }

            /* New loaded based on file loaded (in ossec.conf or default) */
            {
                char **decodersfiles;
                decodersfiles = Config.decoders;
                while ( decodersfiles && *decodersfiles) {
                    if (!test_config) {
                        mdebug1("Reading decoder file %s.", *decodersfiles);
                    }
                    if (!ReadDecodeXML(*decodersfiles, &os_analysisd_decoderlist_pn,
                                        &os_analysisd_decoderlist_nopn, &os_analysisd_decoder_store, list_msg)) {
                        error_exit = 1;
                    }
                    node_log_msg = OSList_GetFirstNode(list_msg);

                    while (node_log_msg) {
                        os_analysisd_log_msg_t * data_msg = node_log_msg->data;
                        msg = os_analysisd_string_log_msg(data_msg);

                        if (data_msg->level == LOGLEVEL_WARNING) {
                            mwarn("%s", msg);
                        } else if (data_msg->level == LOGLEVEL_ERROR) {
                            merror("%s", msg);
                        }
                        os_free(msg);
                        os_analysisd_free_log_msg(data_msg);
                        OSList_DeleteCurrentlyNode(list_msg);
                        node_log_msg = OSList_GetFirstNode(list_msg);
                    }
                    if (error_exit) {
                        merror_exit(CONFIG_ERROR, *decodersfiles);
                    }

                    decodersfiles++;
                }
            }

            /* Load decoders */
            SetDecodeXML(list_msg, &os_analysisd_decoder_store, &os_analysisd_decoderlist_nopn, &os_analysisd_decoderlist_pn);
            node_log_msg = OSList_GetFirstNode(list_msg);
            while (node_log_msg) {
                os_analysisd_log_msg_t * data_msg = node_log_msg->data;
                msg = os_analysisd_string_log_msg(data_msg);

                if (data_msg->level == LOGLEVEL_WARNING) {
                    mwarn("%s", msg);
                } else if (data_msg->level == LOGLEVEL_ERROR) {
                    merror("%s", msg);
                    error_exit = 1;
                }
                os_free(msg);
                os_analysisd_free_log_msg(data_msg);
                OSList_DeleteCurrentlyNode(list_msg);
                node_log_msg = OSList_GetFirstNode(list_msg);
            }
            if (error_exit) {
                merror_exit(DEC_PLUGIN_ERR);
            }
            os_free(list_msg);
        }
        {
            /* Load Lists */
            /* Initialize the lists of list struct */
            Lists_OP_CreateLists();
            /* Load each list into list struct */
            {
                /* Error and warning messages */
                OSList * list_msg = OSList_Create();
                OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);

                char **listfiles;
                listfiles = Config.lists;
                int error_exit = 0;
                while (listfiles && *listfiles) {

                    if (!test_config) {
                        mdebug1("Reading the lists file: '%s'", *listfiles);
                    }
                    if (Lists_OP_LoadList(*listfiles, &os_analysisd_cdblists, list_msg) < 0) {
                        error_exit = 1;
                    }
                    char * msg;
                    OSListNode * node_log_msg;
                    node_log_msg = OSList_GetFirstNode(list_msg);
                    while (node_log_msg) {
                        os_analysisd_log_msg_t * data_msg = node_log_msg->data;
                        msg = os_analysisd_string_log_msg(data_msg);
                        if (data_msg->level == LOGLEVEL_WARNING) {
                            mwarn("%s", msg);
                        } else if (data_msg->level == LOGLEVEL_ERROR) {
                            merror("%s", msg);
                        }
                        os_free(msg);
                        os_analysisd_free_log_msg(data_msg);
                        OSList_DeleteCurrentlyNode(list_msg);
                        node_log_msg = OSList_GetFirstNode(list_msg);
                    }
                    if (error_exit) {
                        merror_exit(LISTS_ERROR, *listfiles);
                    }

                    listfiles++;
                }
                os_free(list_msg);
            }
            mdebug1("Building CDB lists.");
            Lists_OP_MakeAll(0, 0, &os_analysisd_cdblists);
        }

        {
            /* Load Rules */
            /* Create the rules list */
            Rules_OP_CreateRules();

            /* If we haven't specified a rules directory, load default */
            if (!Config.includes) {
                Read_Rules(NULL, &Config, NULL);
            }

            /* Read the rules */
            {
                /* Error and warning msg */
                char * msg;
                OSList * list_msg = OSList_Create();
                OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);
                OSList_SetFreeDataPointer(list_msg, (void (*)(void *))os_analysisd_free_log_msg);

                OSListNode * node_log_msg;
                int error_exit = 0;

                char **rulesfiles;
                rulesfiles = Config.includes;
                while (rulesfiles && *rulesfiles) {
                    if (!test_config) {
                        mdebug1("Reading rules file: '%s'", *rulesfiles);
                    }

                    if (Rules_OP_ReadRules(*rulesfiles, &os_analysisd_rulelist,
                                           &os_analysisd_cdblists, &os_analysisd_last_events,
                                           &os_analysisd_decoder_store, list_msg, true) < 0) {
                        error_exit = 1;
                    }

                    node_log_msg = OSList_GetFirstNode(list_msg);
                    while (node_log_msg) {
                        os_analysisd_log_msg_t * data_msg = node_log_msg->data;
                        msg = os_analysisd_string_log_msg(data_msg);

                        if (data_msg->level == LOGLEVEL_WARNING) {
                            mwarn("%s", msg);
                        } else if (data_msg->level == LOGLEVEL_ERROR) {
                            merror("%s", msg);
                        }
                        os_free(msg);
                        os_analysisd_free_log_msg(data_msg);
                        OSList_DeleteCurrentlyNode(list_msg);
                        node_log_msg = OSList_GetFirstNode(list_msg);
                    }

                    if (error_exit) {
                        merror_exit(RULES_ERROR, *rulesfiles);
                    }

                    rulesfiles++;
                }
                OSList_Destroy(list_msg);
            }

            /* Find all rules that require list lookups and attache the the
             * correct list struct to the rule. This keeps rules from having to
             * search thought the list of lists for the correct file during
             * rule evaluation.
             */
            OS_ListLoadRules(&os_analysisd_cdblists, &os_analysisd_cdbrules);
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

    /* Check if log_fw is enabled */
    Config.logfw = (u_int8_t) getDefine_Int("analysisd",
                                 "log_fw",
                                 0, 1);

    /* Success on the configuration test */
    if (test_config) {
        exit(0);
    }

    if (Config.queue_size != 0) {
        minfo("The option <queue_size> is deprecated and won't apply. Set up each queue size in the internal_options file.");
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
            minfo("%d Hostname(s) in the white list for active response.", wlc);
        }
    }

    /* Startup message */
    minfo(STARTUP_MSG, (int)getpid());

    w_init_queues();

    // Start com request thread
    w_create_thread(asyscom_main, NULL);

    /* Load Mitre JSON File and Mitre hash table */
    mitre_load();

    /* Initialize Logtest */
    w_create_thread(w_logtest_init, NULL);

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
    Eventinfo *lf = NULL;
    int i;

    /* Initialize the logs */
    OS_InitLog();

    /* Initialize the integrity database */
    if (!fim_init()) merror_exit("fim: Initialization failed");

    /* Initialize Rootcheck */
    RootcheckInit();

    /* Initialize Syscollector */
    SyscollectorInit();

    /* Initialize CIS-CAT */
    CiscatInit();

    /* Initialize host info */
    HostinfoInit();

    /* Initialize windows event */
    WinevtInit();

    /* Initialize Security Configuration Assessment event */
    SecurityConfigurationAssessmentInit();

    /* Initialize the Accumulator */
    if (!Accumulate_Init(&os_analysisd_acm_store, &os_analysisd_acm_lookups, &os_analysisd_acm_purge_ts)) {
        merror("accumulator: ERROR: Initialization failed");
        exit(1);
    }

    /* Start the active response queues */
    if (Config.ar) {
        /* Waiting the ARQ to settle */
        sleep(3);

#ifndef LOCAL
        if (Config.ar & REMOTE_AR) {
            if ((arq = StartMQ(ARQUEUE, WRITE, 1)) < 0) {
                merror(ARQ_ERROR);
            } else {
                minfo(CONN_TO, ARQUEUE, "active-response");
            }
        }
#endif

        if (Config.ar & LOCAL_AR) {
            if ((execdq = StartMQ(EXECQUEUE, WRITE, 1)) < 0) {
                merror(ARQ_ERROR);
            } else {
                minfo(CONN_TO, EXECQUEUE, "exec");
            }
        }
    }
    mdebug1("Active response Init completed.");

    /* Get current time before starting */
    gettime(&c_timespec);
    Start_Time();

    /* Start the hourly/weekly stats directories*/
    if(Init_Stats_Directories() < 0) {
        Config.stats = 0;
    }

    /* Initialize the logs */
    {
        os_calloc(1, sizeof(Eventinfo), lf);
        os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
        lf->year = prev_year;
        memset(lf->mon, 0, sizeof(lf->mon));
        lf->day = today;

        if (OS_GetLogLocation(today, prev_year, prev_month) < 0) {
            merror_exit("Error allocating log files");
        }

        Free_Eventinfo(lf);
    }

    /* Initialize label cache */
    if (!labels_init()) merror_exit("Error allocating labels");

    Config.label_cache_maxage = getDefine_Int("analysisd", "label_cache_maxage", 0, 60);
    Config.show_hidden_labels = getDefine_Int("analysisd", "show_hidden_labels", 0, 1);

    if (Config.custom_alert_output) {
        mdebug1("Custom output found.!");
    }

    int num_decode_event_threads = getDefine_Int("analysisd", "event_threads", 0, 32);
    int num_decode_syscheck_threads = getDefine_Int("analysisd", "syscheck_threads", 0, 32);
    int num_decode_syscollector_threads = getDefine_Int("analysisd", "syscollector_threads", 0, 32);
    int num_decode_rootcheck_threads = getDefine_Int("analysisd", "rootcheck_threads", 0, 32);
    int num_decode_sca_threads = getDefine_Int("analysisd", "sca_threads", 0, 32);
    int num_decode_hostinfo_threads = getDefine_Int("analysisd", "hostinfo_threads", 0, 32);
    int num_decode_winevt_threads = getDefine_Int("analysisd", "winevt_threads", 0, 32);
    int num_dispatch_dbsync_threads = getDefine_Int("analysisd", "dbsync_threads", 0, 32);

    if(num_decode_event_threads == 0){
        num_decode_event_threads = cpu_cores;
    }

    if(num_decode_syscheck_threads == 0){
        num_decode_syscheck_threads = cpu_cores;
    }

    if(num_decode_syscollector_threads == 0){
        num_decode_syscollector_threads = cpu_cores;
    }

    if(num_decode_rootcheck_threads == 0){
        num_decode_rootcheck_threads = cpu_cores;
    }

    if(num_decode_sca_threads == 0){
        num_decode_sca_threads = cpu_cores;
    }

    if(num_decode_hostinfo_threads == 0){
        num_decode_hostinfo_threads = cpu_cores;
    }

    if(num_decode_winevt_threads == 0){
        num_decode_winevt_threads = cpu_cores;
    }

    num_dispatch_dbsync_threads = (num_dispatch_dbsync_threads > 0) ? num_dispatch_dbsync_threads : cpu_cores;

    /* Initiate the FTS list */
    if (!FTS_Init(num_rule_matching_threads, &os_analysisd_fts_list, &os_analysisd_fts_store)) {
        merror_exit(FTS_LIST_ERROR);
    }

    mdebug1("FTS_Init completed.");

    /* Global stats uptime */
    analysisd_state.uptime = time(NULL);

    /* Create OSHash for agents statistics */
    analysisd_agents_state = OSHash_Create();
    if (!analysisd_agents_state) {
        merror_exit(HASH_ERROR);
    }
    if (!OSHash_setSize(analysisd_agents_state, 2048)) {
        merror_exit(HSETSIZE_ERROR, "analysisd_agents_state");
    }

    /* Initialize EPS limits */
    load_limits(Config.eps.maximum, Config.eps.timeframe, Config.eps.maximum_found);
    w_set_available_credits_prev(Config.eps.maximum * Config.eps.timeframe);

    /* Create message handler thread */
    w_create_thread(ad_input_main, &m_queue);

    /* Create archives writer thread */
    w_create_thread(w_writer_thread, NULL);

    /* Create alerts log writer thread */
    w_create_thread(w_writer_log_thread, NULL);

    /* Create statistical log writer thread */
    w_create_thread(w_writer_log_statistical_thread, NULL);

    /* Create firewall log writer thread */
    w_create_thread(w_writer_log_firewall_thread, NULL);

    /* Create FTS log writer thread */
    w_create_thread(w_writer_log_fts_thread, NULL);

    /* Create log rotation thread */
    w_create_thread(w_log_rotate_thread, NULL);

    /* Create decode syscheck threads */
    for(i = 0; i < num_decode_syscheck_threads;i++){
        w_create_thread(w_decode_syscheck_thread, NULL);
    }

    /* Create decode syscollector threads */
    for(i = 0; i < num_decode_syscollector_threads;i++){
        w_create_thread(w_decode_syscollector_thread, NULL);
    }

    /* Create decode hostinfo threads */
    for(i = 0; i < num_decode_hostinfo_threads;i++){
        w_create_thread(w_decode_hostinfo_thread, NULL);
    }

    /* Create decode rootcheck threads */
    for(i = 0; i < num_decode_rootcheck_threads;i++){
        w_create_thread(w_decode_rootcheck_thread, NULL);
    }

    /* Create decode Security Configuration Assessment threads */
    for(i = 0; i < num_decode_sca_threads;i++){
        w_create_thread(w_decode_sca_thread, NULL);
    }

    /* Create decode event threads */
    for(i = 0; i < num_decode_event_threads;i++){
        w_create_thread(w_decode_event_thread, NULL);
    }

    /* Create the process event threads */
    for(i = 0; i < num_rule_matching_threads;i++){
        w_create_thread(w_process_event_thread,(void *) (intptr_t)i);
    }

    /* Create decode winevt threads */
    for(i = 0; i < num_decode_winevt_threads;i++){
        w_create_thread(w_decode_winevt_thread, NULL);
    }

    /* Create database synchronization dispatcher threads */
    for (i = 0; i < num_dispatch_dbsync_threads; i++){
        w_create_thread(w_dispatch_dbsync_thread, NULL);
    }

    /* Create upgrade module dispatcher thread */
    w_create_thread(w_dispatch_upgrade_module_thread, NULL);

    /* Create State thread */
    w_create_thread(w_analysisd_state_main, NULL);

    mdebug1("Startup completed. Waiting for new messages..");

    while (1) {
        sleep(1);

        unsigned int credits = 0;
        if (limit_reached(&credits)) {
            w_inc_eps_seconds_over_limit();
        }
        w_set_available_credits_prev(credits);

        update_limits();
    }
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

    flog = wfopen(logfile, "a");
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
    w_guard_mutex_variable(hourly_alert_mutex, (hourly_alerts = 0));
    hourly_events = 0;
    hourly_syscheck = 0;
    hourly_firewall = 0;

    fclose(flog);
}

// Message handler thread
void * ad_input_main(void * args) {
    int m_queue = *(int *)args;
    char buffer[OS_MAXSTR + 1] = "";
    char *copy;
    char *msg;
    int result;
    int recv = 0;

    mdebug1("Input message handler thread started.");

    while (1) {
        if (recv = OS_RecvUnix(m_queue, OS_MAXSTR, buffer), recv) {
            buffer[recv] = '\0';
            msg = buffer;

            /* Get the time we received the event */
            gettime(&c_timespec);

            /* Check for a valid message */
            if (strlen(msg) < 4) {
                merror(IMSG_ERROR, msg);
                continue;
            }

            w_add_recv((unsigned long) recv);
            w_inc_received_events();

            result = -1;
            // take the ruleset
            w_rwlock_rdlock(&g_hotreload_ruleset_mutex);

            if (msg[0] == SYSCHECK_MQ) {
                if (!queue_full(decode_queue_syscheck_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_syscheck_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                        hourly_syscheck++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_syscheck_dropped_events();

                    if (!reported_syscheck) {
                        mwarn("Syscheck decoder queue is full.");
                        reported_syscheck = 1;
                    }
                }
            } else if (msg[0] == ROOTCHECK_MQ) {
                if (!queue_full(decode_queue_rootcheck_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_rootcheck_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_rootcheck_dropped_events();

                    if (!reported_rootcheck) {
                        mwarn("Rootcheck decoder queue is full.");
                        reported_rootcheck = 1;
                    }
                }
            } else if (msg[0] == SCA_MQ) {
                if (!queue_full(decode_queue_sca_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_sca_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_sca_dropped_events();

                    if (!reported_sca) {
                        mwarn("Security Configuration Assessment decoder queue is full.");
                        reported_sca = 1;
                    }
                }
            } else if (msg[0] == SYSCOLLECTOR_MQ) {
                if (!queue_full(decode_queue_syscollector_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_syscollector_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_syscollector_dropped_events();

                    if (!reported_syscollector) {
                        mwarn("Syscollector decoder queue is full.");
                        reported_syscollector = 1;
                    }
                }
            } else if (msg[0] == HOSTINFO_MQ) {
                if (!queue_full(decode_queue_hostinfo_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_hostinfo_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_logcollector_others_dropped_events();

                    if (!reported_hostinfo) {
                        mwarn("Hostinfo decoder queue is full.");
                        reported_hostinfo = 1;
                    }
                }
            } else if (msg[0] == WIN_EVT_MQ) {
                if (!queue_full(decode_queue_winevt_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_winevt_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_logcollector_eventchannel_dropped_events();

                    if (!reported_winevt) {
                        mwarn("Windows eventchannel decoder queue is full.");
                        reported_winevt = 1;
                    }
                }
            } else if (msg[0] == DBSYNC_MQ) {
                if (!queue_full(dispatch_dbsync_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(dispatch_dbsync_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_dbsync_dropped_events();

                    if (!reported_dbsync) {
                        mwarn("Database synchronization decoder queue is full.");
                        reported_dbsync = 1;
                    }
                }
            } else if (msg[0] == UPGRADE_MQ) {
                if (!queue_full(upgrade_module_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(upgrade_module_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    w_inc_modules_upgrade_dropped_events();

                    if (!reported_upgrade_module) {
                        mwarn("Upgrade module decoder queue is full.");
                        reported_upgrade_module = 1;
                    }
                }
            } else {
                if (!queue_full(decode_queue_event_input)) {
                    os_strdup(buffer, copy);

                    result = queue_push_ex(decode_queue_event_input, copy);

                    if (result == -1) {
                        free(copy);
                    } else {
                        hourly_events++;
                    }
                }

                if (result == -1) {
                    if (msg[0] == CISCAT_MQ) {
                        w_inc_modules_ciscat_dropped_events();
                    } else if (msg[0] == SYSLOG_MQ) {
                        w_inc_syslog_dropped_events();
                    } else if (msg[0] == LOCALFILE_MQ) {
                        w_inc_dropped_by_component_events(extract_module_from_message(msg));
                    }

                    if (!reported_event) {
                        mwarn("Input queue is full.");
                        reported_event = 1;
                    }
                }
            }


            w_rwlock_unlock(&g_hotreload_ruleset_mutex);

            if (result == -1) {
                if (!reported_eps_drop) {
                    if (limit_reached(NULL)) {
                        reported_eps_drop = 1;
                        if (!reported_eps_drop_hourly) {
                            mwarn("Queues are full and no EPS credits, dropping events.");
                        } else {
                            mdebug2("Queues are full and no EPS credits, dropping events.");
                        }
                        w_inc_eps_events_dropped();
                    } else {
                        w_inc_eps_events_dropped_not_eps();
                    }
                } else {
                    w_inc_eps_events_dropped();
                }
            } else {
                if (reported_eps_drop) {
                    reported_eps_drop = 0;
                    if (!reported_eps_drop_hourly) {
                        minfo("Queues back to normal and EPS credits, no dropping events.");
                        reported_eps_drop_hourly = 1;
                    } else {
                        mdebug2("Queues back to normal and EPS credits, no dropping events.");
                    }
                }
            }
        }
    }

    return NULL;
}

void * w_writer_thread(__attribute__((unused)) void * args ){
    Eventinfo *lf = NULL;

    while(1){
        /* Receive message from queue */
        if (lf = queue_pop_ex(writer_queue), lf) {

            w_mutex_lock(&writer_threads_mutex);
            w_inc_archives_written(lf->agent_id);

            /* If configured to log all, do it */
            if (Config.logall) {
                OS_Store(lf);
            }
            if (Config.logall_json) {
                jsonout_output_archive(lf);
            }

            Free_Eventinfo(lf);
            w_mutex_unlock(&writer_threads_mutex);
        }
    }
}

void * w_writer_log_thread(__attribute__((unused)) void * args ){
    Eventinfo *lf = NULL;

    while(1){
        /* Receive message from queue */
        if (lf = queue_pop_ex(writer_queue_log), lf) {

            w_mutex_lock(&writer_threads_mutex);
            w_inc_alerts_written(lf->agent_id);

            if (Config.custom_alert_output) {
                __crt_ftell = ftell(_aflog);
                OS_CustomLog(lf, Config.custom_alert_output_format);
            } else if (Config.alerts_log) {
                __crt_ftell = ftell(_aflog);
                OS_Log(lf, _aflog);
            } else if (Config.jsonout_output) {
                __crt_ftell = ftell(_jflog);
            }
            /* Log to json file */
            if (Config.jsonout_output) {
                jsonout_output_event(lf);

                if (Config.forwarders_list) {
                    char* json_msg = Eventinfo_to_jsonstr(lf, false, NULL);
                    SendJSONtoSCK(json_msg, Config.socket_list);
                }
            }

#ifdef PRELUDE_OUTPUT_ENABLED
            /* Log to prelude */
            if (Config.prelude) {
                RuleInfo *rule = lf->generated_rule;

                if (rule && Config.prelude_log_level <= rule->level) {
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
            w_mutex_unlock(&writer_threads_mutex);
            Free_Eventinfo(lf);
        }
    }
}

void * w_decode_syscheck_thread(__attribute__((unused)) void * args){
    Eventinfo *lf = NULL;
    char *msg = NULL;
    _sdb sdb;
    OSDecoderInfo *fim_decoder = NULL;

    os_calloc(1, sizeof(OSDecoderInfo), fim_decoder);

    /* Initialize the integrity database */
    sdb_init(&sdb, fim_decoder);

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_syscheck_input), msg) {
            get_eps_credit();

            int res = 0;
            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            w_inc_modules_syscheck_decoded_events(lf->agent_id);

            lf->decoder_info = fim_decoder;

            // If the event comes in JSON format agent version is >= 3.11. Therefore we decode, alert and update DB entry.
            if (*lf->log == '{') {
                res = decode_fim_event(&sdb, lf);
            } else {
                res = DecodeSyscheck(lf, &sdb);
            }

            if (res == 1 && queue_push_ex_block(decode_queue_event_output, lf) == 0) {
                continue;
            } else {
                /* We don't process syscheck events further */
                w_free_event_info(lf);
            }
        }
    }
}

void * w_decode_syscollector_thread(__attribute__((unused)) void * args){
    Eventinfo *lf = NULL;
    char *msg = NULL;
    int socket = -1;

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_syscollector_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            w_inc_modules_syscollector_decoded_events(lf->agent_id);

            if (!DecodeSyscollector(lf, &socket)) {
                /* We don't process syscollector events further */
                w_free_event_info(lf);
            }
            else {
                if (queue_push_ex_block(decode_queue_event_output, lf) < 0) {
                    w_free_event_info(lf);
                }
            }
        }
    }
}

void * w_decode_rootcheck_thread(__attribute__((unused)) void * args){
    Eventinfo *lf = NULL;
    char *msg = NULL;

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_rootcheck_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            w_inc_modules_rootcheck_decoded_events(lf->agent_id);

            if (!DecodeRootcheck(lf)) {
                /* We don't process rootcheck events further */
                w_free_event_info(lf);
            }
            else {
                if (queue_push_ex_block(decode_queue_event_output, lf) < 0) {
                    w_free_event_info(lf);
                }
            }
        }
    }
}

void * w_decode_sca_thread(__attribute__((unused)) void * args){
    Eventinfo *lf = NULL;
    char *msg = NULL;
    int socket = -1;

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_sca_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            w_inc_modules_sca_decoded_events(lf->agent_id);

            if (!DecodeSCA(lf, &socket)) {
                /* We don't process rootcheck events further */
                w_free_event_info(lf);
            }
            else {
                if (queue_push_ex_block(decode_queue_event_output, lf) < 0) {
                    w_free_event_info(lf);
                }
            }
        }
    }
}

void * w_decode_hostinfo_thread(__attribute__((unused)) void * args){
    Eventinfo *lf = NULL;
    char * msg = NULL;

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_hostinfo_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            w_inc_modules_logcollector_others_decoded_events(lf->agent_id);

            if (!DecodeHostinfo(lf)) {
                /* We don't process syscheck events further */
                w_free_event_info(lf);
            }
            else {
                if (queue_push_ex_block(decode_queue_event_output, lf) < 0) {
                    w_free_event_info(lf);
                }
            }
        }
    }
}

void * w_decode_event_thread(__attribute__((unused)) void * args){
    Eventinfo *lf = NULL;
    OSDecoderNode *node;
    char * msg = NULL;
    regex_matching decoder_match;
    memset(&decoder_match, 0, sizeof(regex_matching));
    int sock = -1;

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_event_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            if (msg[0] == CISCAT_MQ) {
                w_inc_modules_ciscat_decoded_events(lf->agent_id);
                if (!DecodeCiscat(lf, &sock)) {
                    w_free_event_info(lf);
                    free(msg);
                    continue;
                }
            } else {
                if (msg[0] == SYSLOG_MQ) {
                    w_inc_syslog_decoded_events();
                } else if (msg[0] == LOCALFILE_MQ) {
                    w_inc_decoded_by_component_events(extract_module_from_location(lf->location), lf->agent_id);
                }
                node = OS_GetFirstOSDecoder(lf->program_name);
                DecodeEvent(lf, Config.g_rules_hash, &decoder_match, node);
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            if (queue_push_ex_block(decode_queue_event_output, lf) < 0) {
                Free_Eventinfo(lf);
            }
        }
    }
}

void * w_decode_winevt_thread(__attribute__((unused)) void * args) {
    Eventinfo *lf = NULL;
    char * msg = NULL;

    while(1) {
        /* Receive message from queue */
        if (msg = queue_pop_ex(decode_queue_winevt_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

            /* Default values for the log info */
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);

            w_inc_modules_logcollector_eventchannel_decoded_events(lf->agent_id);

            if (DecodeWinevt(lf)) {
                /* We don't process windows events further */
                w_free_event_info(lf);
            }
            else {
                if (queue_push_ex_block(decode_queue_event_output, lf) < 0) {
                    w_free_event_info(lf);
                }
            }
        }
    }
}

void * w_dispatch_dbsync_thread(__attribute__((unused)) void * args) {
    char * msg;
    Eventinfo * lf;
    dbsync_context_t ctx = { .db_sock = -1, .ar_sock = -1 };

    for (;;) {
        if (msg = queue_pop_ex(dispatch_dbsync_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            w_inc_dbsync_decoded_events(lf->agent_id);

            DispatchDBSync(&ctx, lf);
            Free_Eventinfo(lf);
        }
    }

    return NULL;
}

void * w_dispatch_upgrade_module_thread(__attribute__((unused)) void * args) {
    char * msg;
    Eventinfo * lf;

    while (true) {
        if (msg = queue_pop_ex(upgrade_module_input), msg) {
            get_eps_credit();

            os_calloc(1, sizeof(Eventinfo), lf);
            os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
            Zero_Eventinfo(lf);

            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);
                Free_Eventinfo(lf);
                free(msg);
                continue;
            }

            free(msg);

            w_inc_modules_upgrade_decoded_events(lf->agent_id);

            // Inserts agent id into incomming message and sends it to upgrade module
            cJSON *message_obj = cJSON_Parse(lf->log);

            if (message_obj) {
                cJSON *message_params = cJSON_GetObjectItem(message_obj, "parameters");

                if (message_params) {
                    int sock = OS_ConnectUnixDomain(WM_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR);

                    if (sock == OS_SOCKTERR) {
                        merror("Could not connect to upgrade module socket at '%s'. Error: %s", WM_UPGRADE_SOCK, strerror(errno));
                    } else {
                        int agent = atoi(lf->agent_id);
                        cJSON* agents = cJSON_CreateIntArray(&agent, 1);
                        cJSON_AddItemToObject(message_params, "agents", agents);

                        char *message = cJSON_PrintUnformatted(message_obj);
                        OS_SendSecureTCP(sock, strlen(message), message);
                        os_free(message);

                        close(sock);
                    }
                } else {
                    merror("Could not get parameters from upgrade message: %s", lf->log);
                }
                cJSON_Delete(message_obj);
            } else {
                merror("Could not parse upgrade message: %s", lf->log);
            }

            Free_Eventinfo(lf);
        }
    }

    return NULL;
}

void * w_process_event_thread(__attribute__((unused)) void * id){
    Eventinfo *lf = NULL;
    RuleInfo *t_currently_rule = NULL;
    int result;
    int t_id = (intptr_t)id;
    regex_matching rule_match;
    memset(&rule_match, 0, sizeof(regex_matching));
    Eventinfo *lf_cpy = NULL;
    Eventinfo *lf_logall = NULL;
    int sock = -1;

    /* Stats */
    RuleInfo *stats_rule = NULL;

    /* Start the hourly/weekly stats */
    if (Start_Hour(t_id, num_rule_matching_threads) < 0) {
        Config.stats = 0;
    } else {
        /* Initialize stats rules */
        stats_rule = zerorulemember(STATS_MODULE, Config.stats, 0, 0, 0, 0, 0, 0, &os_analysisd_last_events);

        if (!stats_rule) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        stats_rule->group = "stats,";
        stats_rule->comment = "Excessive number of events (above normal).";
    }

    while(1) {
        RuleNode *rulenode_pt;
        lf_logall = NULL;

        /* Extract decoded event from the queue */
        if (lf = queue_pop_ex(decode_queue_event_output), !lf) {
            continue;
        }

        lf->tid = t_id;
        t_currently_rule = NULL;

        lf->size = strlen(lf->log);

        /* Run accumulator */
        if ( lf->decoder_info->accumulate == 1 ) {
            w_mutex_lock(&accumulate_mutex);
            lf = Accumulate(lf, &os_analysisd_acm_store, &os_analysisd_acm_lookups, &os_analysisd_acm_purge_ts);
            w_mutex_unlock(&accumulate_mutex);
        }

        /* Firewall event */
        if (lf->decoder_info->type == FIREWALL) {
            /* If we could not get any information from
                * the log, just ignore it
                */
            w_mutex_lock(&hourly_firewall_mutex);
            hourly_firewall++;
            w_mutex_unlock(&hourly_firewall_mutex);
            if (Config.logfw) {

                if (!lf->action || !lf->srcip || !lf->dstip || !lf->srcport ||
                        !lf->dstport || !lf->protocol) {
                    w_free_event_info(lf);
                    continue;
                }

                os_calloc(1, sizeof(Eventinfo), lf_cpy);
                w_copy_event_for_log(lf, lf_cpy);

                if (queue_push_ex_block(writer_queue_log_firewall, lf_cpy) < 0) {
                    Free_Eventinfo(lf_cpy);
                }
            }
        }

        /* Stats checking */
        if (Config.stats) {
            w_mutex_lock(&process_event_check_hour_mutex);
            if (Check_Hour() == 1) {
                RuleInfo *saved_rule = lf->generated_rule;
                char *saved_log;

                /* Save previous log */
                saved_log = lf->full_log;

                lf->generated_rule = stats_rule;
                lf->full_log = __stats_comment;

                /* Alert for statistical analysis */
                if (stats_rule && (stats_rule->alert_opts & DO_LOGALERT)) {
                    os_calloc(1, sizeof(Eventinfo), lf_cpy);
                    w_copy_event_for_log(lf, lf_cpy);

                    if (queue_push_ex_block(writer_queue_log_statistical, lf_cpy) < 0) {
                        Free_Eventinfo(lf_cpy);
                    }
                }

                /* Set lf to the old values */
                lf->generated_rule = saved_rule;
                lf->full_log = saved_log;
            }
            w_mutex_unlock(&process_event_check_hour_mutex);
        }

        // Insert labels
        lf->labels = labels_find(lf->agent_id, &sock);

        /* Check the rules */
        DEBUG_MSG("%s: DEBUG: Checking the rules - %d ",
                    ARGV0, lf->decoder_info->type);

        w_inc_processed_events(lf->agent_id);

        /* Loop over all the rules */
        rulenode_pt = OS_GetFirstRule();
        if (!rulenode_pt) {
            merror_exit("Rules in an inconsistent state. Exiting.");
        }
        do {
            if (lf->decoder_info->type == OSSEC_ALERT) {
                if (!lf->generated_rule) {
                    goto next_it;
                }

                /* Process the alert */
                t_currently_rule = lf->generated_rule;
            }
            /* Categories must match */
            else if (rulenode_pt->ruleinfo->category !=
                        lf->decoder_info->type) {
                continue;
            }

            /* Check each rule */
            else if (t_currently_rule = OS_CheckIfRuleMatch(lf, os_analysisd_last_events, &os_analysisd_cdblists,
                     rulenode_pt, &rule_match, &os_analysisd_fts_list, &os_analysisd_fts_store, true, NULL), !t_currently_rule) {

                continue;
            }

            /* Ignore level 0 */
            if (t_currently_rule->level == 0) {
                break;
            }

            /* Check ignore time */
            if (t_currently_rule->ignore_time) {
                if (t_currently_rule->time_ignored == 0) {
                    t_currently_rule->time_ignored = lf->generate_time;
                }
                /* If the current time - the time the rule was ignored
                    * is less than the time it should be ignored,
                    * alert about the parent one instead
                    */
                else if ((lf->generate_time - t_currently_rule->time_ignored)
                            < t_currently_rule->ignore_time) {

                    if (lf->prev_rule) {
                        t_currently_rule = (RuleInfo*)lf->prev_rule;
                        w_FreeArray(lf->last_events);
                    } else {
                        break;
                    }
                } else {
                    t_currently_rule->time_ignored = lf->generate_time;
                }
            }

            /* Pointer to the rule that generated it */
            lf->generated_rule = t_currently_rule;

            /* Check if we should ignore it */
            if (t_currently_rule->ckignore && IGnore(lf, t_id)) {
                /* Ignore rule */
                lf->generated_rule = NULL;
                break;
            }

            /* Check if we need to add to ignore list */
            if (t_currently_rule->ignore) {
                AddtoIGnore(lf, t_id);
            }

            lf->comment = ParseRuleComment(lf);

            /* Log the alert if configured to */
            if (t_currently_rule->alert_opts & DO_LOGALERT) {
                os_calloc(1, sizeof(Eventinfo), lf_cpy);
                w_copy_event_for_log(lf, lf_cpy);
                if (queue_push_ex_block(writer_queue_log, lf_cpy) < 0) {
                    Free_Eventinfo(lf_cpy);
                }
            }

            /* Execute an active response */
            if (t_currently_rule->ar) {
                int do_ar;
                active_response **rule_ar;

                rule_ar = t_currently_rule->ar;

                while (*rule_ar) {
                    do_ar = 1;
                    if (lf->dstuser && !OS_PRegex(lf->dstuser, "^[a-zA-Z._0-9@?-]*$")) {
                        mwarn(CRAFTED_USER, lf->dstuser);
                        do_ar = 0;
                    }
                    if (lf->srcip && !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$")) {
                        mwarn(CRAFTED_IP, lf->srcip);
                        do_ar = 0;
                    }

                    if (do_ar) {
                        OS_Exec(&execdq, &arq, &sock, lf, *rule_ar);
                    }
                    rule_ar++;
                }
            }

            /* Copy the structure to the state memory of if_matched_sid */
            if (t_currently_rule->sid_prev_matched) {
                OSListNode *node;
                w_mutex_lock(&t_currently_rule->mutex);
                if (node = OSList_AddData(t_currently_rule->sid_prev_matched, lf), !node) {
                    merror("Unable to add data to sig list.");
                } else {
                    lf->sid_node_to_delete = node;
                }
                w_mutex_unlock(&t_currently_rule->mutex);
            }
            /* Group list */
            else if (t_currently_rule->group_prev_matched) {
                unsigned int j = 0;
                OSListNode *node;

                w_mutex_lock(&t_currently_rule->mutex);
                os_calloc(t_currently_rule->group_prev_matched_sz, sizeof(OSListNode *), lf->group_node_to_delete);
                while (j < t_currently_rule->group_prev_matched_sz) {
                    if (node = OSList_AddData(t_currently_rule->group_prev_matched[j], lf), !node) {
                        merror("Unable to add data to grp list.");
                    } else {
                        lf->group_node_to_delete[j] = node;
                    }
                    j++;
                }
                w_mutex_unlock(&t_currently_rule->mutex);
            }

            lf->queue_added = 1;
            os_calloc(1, sizeof(Eventinfo), lf_logall);
            w_copy_event_for_log(lf, lf_logall);
            w_free_event_info(lf);
            OS_AddEvent(lf, os_analysisd_last_events);
            break;

        } while ((rulenode_pt = rulenode_pt->next) != NULL);

        if (Config.logall || Config.logall_json){
            if (!lf_logall) {
                os_calloc(1, sizeof(Eventinfo), lf_logall);
                w_copy_event_for_log(lf, lf_logall);
            }
            result = queue_push_ex(writer_queue, lf_logall);
            if (result < 0) {
                if (!reported_writer){
                    mwarn("Archive writer queue is full. %d", t_id);
                    reported_writer = 1;
                }
                Free_Eventinfo(lf_logall);
            }
        } else if (lf_logall) {
            Free_Eventinfo(lf_logall);
        }
next_it:
        if (!lf->queue_added) {
            w_free_event_info(lf);
        }
    }
}

void * w_log_rotate_thread(__attribute__((unused)) void * args){
    int day = 0;
    int year = 0;
    struct tm tm_result = { .tm_sec = 0 };
    char mon[4] = {0};

    while(1){
        w_guard_mutex_variable(current_time_mutex, (current_time = time(NULL)));
        localtime_r(&c_time, &tm_result);
        day = tm_result.tm_mday;
        year = tm_result.tm_year + 1900;
        strncpy(mon, month[tm_result.tm_mon], 3);

        /* Set the global hour/weekday */
        __crt_hour = tm_result.tm_hour;
        __crt_wday = tm_result.tm_wday;

        w_mutex_lock(&writer_threads_mutex);

        w_log_flush();
        if (thishour != __crt_hour) {
            /* Search all the rules and print the number
                * of alerts that each one fired
                */
            DumpLogstats();
            thishour = __crt_hour;

            /* Reset EPS logging flag to avoid flodding */
            if (reported_eps_drop_hourly && !reported_eps_drop) {
                reported_eps_drop_hourly = 0;
            }

            /* Check if the date has changed */
            if (today != day) {
                if (Config.stats) {
                    /* Update the hourly stats (done daily) */
                    Update_Hour();
                }

                if (OS_GetLogLocation(day, year, mon) < 0) {
                    merror_exit("Error allocating log files");
                }

                today = day;
                memcpy(prev_month, mon, sizeof(mon));
                prev_year = year;
            }
        }

        OS_RotateLogs(day, year, mon);
        w_mutex_unlock(&writer_threads_mutex);
        sleep(1);
    }
}

void * w_writer_log_statistical_thread(__attribute__((unused)) void * args ){
    Eventinfo *lf = NULL;

    while(1){
        /* Receive message from queue */
        if (lf = queue_pop_ex(writer_queue_log_statistical), lf) {

            w_mutex_lock(&writer_threads_mutex);
            w_inc_stats_written();

            if (Config.custom_alert_output) {
                __crt_ftell = ftell(_aflog);
                OS_CustomLog(lf, Config.custom_alert_output_format);
            } else if (Config.alerts_log) {
                __crt_ftell = ftell(_aflog);
                OS_Log(lf, _aflog);
            } else if (Config.jsonout_output) {
                __crt_ftell = ftell(_jflog);
            }

            /* Log to json file */
            if (Config.jsonout_output) {
                jsonout_output_event(lf);
            }

            w_mutex_unlock(&writer_threads_mutex);

            Free_Eventinfo(lf);
        }
    }
}

void * w_writer_log_firewall_thread(__attribute__((unused)) void * args ){
    Eventinfo *lf = NULL;

    while(1){
        /* Receive message from queue */
        if (lf = queue_pop_ex(writer_queue_log_firewall), lf) {

            w_mutex_lock(&writer_threads_mutex);
            w_inc_firewall_written(lf->agent_id);
            FW_Log(lf);
            w_mutex_unlock(&writer_threads_mutex);

            Free_Eventinfo(lf);
        }
    }
}

void w_log_flush(){

    /* Flush archives.log and archives.json */
    if (Config.logall) {
        OS_Store_Flush();
    }

    if (Config.logall_json) {
        jsonout_output_archive_flush();
    }

    /* Flush alerts.json */
    if (Config.jsonout_output) {
        jsonout_output_event_flush();
    }

    if (Config.custom_alert_output) {
        OS_CustomLog_Flush();
    }

    if (Config.alerts_log) {
        OS_Log_Flush();
    }

    FTS_Flush();

}

void * w_writer_log_fts_thread(__attribute__((unused)) void * args ){
    char * line;

    while(1){
        /* Receive message from queue */
        if (line = queue_pop_ex(writer_queue_log_fts), line) {

            w_mutex_lock(&writer_threads_mutex);
            w_inc_fts_written();
            FTS_Fprintf(line);
            w_mutex_unlock(&writer_threads_mutex);

            free(line);
        }
    }
}

void w_init_queues(){
     /* Init the archives writer queue */
    writer_queue = queue_init(getDefine_Int("analysisd", "archives_queue_size", 128, 2000000));

    /* Init the alerts log writer queue */
    writer_queue_log = queue_init(getDefine_Int("analysisd", "alerts_queue_size", 128, 2000000));

    /* Init statistical the log writer queue */
    writer_queue_log_statistical = queue_init(getDefine_Int("analysisd", "statistical_queue_size", 128, 2000000));

    /* Init the firewall log writer queue */
    writer_queue_log_firewall = queue_init(getDefine_Int("analysisd", "firewall_queue_size", 128, 2000000));

    /* Init the FTS log writer queue */
    writer_queue_log_fts = queue_init(getDefine_Int("analysisd", "fts_queue_size", 128, 2000000));

    /* Init the decode syscheck queue input */
    decode_queue_syscheck_input = queue_init(getDefine_Int("analysisd", "decode_syscheck_queue_size", 128, 2000000));

    /* Init the decode syscollector queue input */
    decode_queue_syscollector_input = queue_init(getDefine_Int("analysisd", "decode_syscollector_queue_size", 128, 2000000));

    /* Init the decode rootcheck queue input */
    decode_queue_rootcheck_input = queue_init(getDefine_Int("analysisd", "decode_rootcheck_queue_size", 128, 2000000));

    /* Init the decode SCA queue input */
    decode_queue_sca_input = queue_init(getDefine_Int("analysisd", "decode_sca_queue_size", 128, 2000000));

    /* Init the decode hostinfo queue input */
    decode_queue_hostinfo_input = queue_init(getDefine_Int("analysisd", "decode_hostinfo_queue_size", 128, 2000000));

    /* Init the decode winevt queue input */
    decode_queue_winevt_input = queue_init(getDefine_Int("analysisd", "decode_winevt_queue_size", 128, 2000000));

    /* Init the decode event queue input */
    decode_queue_event_input = queue_init(getDefine_Int("analysisd", "decode_event_queue_size", 128, 2000000));

    /* Init the decode event queue output */
    decode_queue_event_output = queue_init(getDefine_Int("analysisd", "decode_output_queue_size", 128, 2000000));

    /* Initialize database synchronization message queue */
    dispatch_dbsync_input = queue_init(getDefine_Int("analysisd", "dbsync_queue_size", 128, 2000000));

    /* Initialize upgrade module message queue */
    upgrade_module_input = queue_init(getDefine_Int("analysisd", "upgrade_queue_size", 128, 2000000));
}

time_t w_get_current_time(void) {
    time_t _current_time;
    w_guard_mutex_variable(current_time_mutex, (_current_time = current_time));
    return _current_time;
}

/******************************************************************************
 *                          Hot reload ruleset
 ******************************************************************************/
bool w_hotreload_reload(OSList* list_msg)
{
    /* logging handler */
    /*
    OSList* list_msg = OSList_Create();
    if (!list_msg)
    {
        merror_exit(LIST_ERROR);
    }
    OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);
    OSList_SetFreeDataPointer(list_msg, (void (*)(void*))os_analysisd_free_log_msg);
    */

    assert(list_msg != NULL);

    // Get the ruleset
    w_hotreload_ruleset_data_t* ruleset = w_hotreload_create_ruleset(list_msg);
    if (!ruleset)
    {
        mdebug1("Error creating ruleset for hotreload");
        return true;
    }

    // Sync thread for reloading ruleset,
    mdebug1("Blocking input threads to reload ruleset");
    w_rwlock_wrlock(&g_hotreload_ruleset_mutex);

    // Wait for a clean pipeline
    mdebug1("Wait for pipeline to be clean");
    while (!queue_empty_ex(decode_queue_event_output) || !queue_empty_ex(decode_queue_syscheck_input) ||
           !queue_empty_ex(decode_queue_syscollector_input) || !queue_empty_ex(decode_queue_rootcheck_input) ||
           !queue_empty_ex(decode_queue_sca_input) || !queue_empty_ex(decode_queue_hostinfo_input) ||
           !queue_empty_ex(decode_queue_winevt_input) || !queue_empty_ex(dispatch_dbsync_input) ||
           !queue_empty_ex(upgrade_module_input) || !queue_empty_ex(writer_queue_log) || !queue_empty_ex(writer_queue))
    {
        usleep(1000);
    }

    usleep(1000); // Give some time for the threads to finish TODO: Check this

    mdebug1("Pipeline is clean, switching ruleset");

    // Switch the ruleset and get the old one
    w_hotreload_ruleset_data_t* old_ruleset = w_hotreload_switch_ruleset(ruleset);

    // Reset the internal decoders
    w_hotreload_reload_internal_decoders();

    // Run the new ruleset
    w_rwlock_unlock(&g_hotreload_ruleset_mutex);

    // Free the old ruleset
    w_hotreload_clean_ruleset(&old_ruleset);

    // Delete only the struct where store the new ruleset
    os_free(ruleset);

    return false;
}

/**
 * @brief Reload the internal decoders
 *
 * Reload the internal decoders, updating decoder store internally
 */
void w_hotreload_reload_internal_decoders()
{

    RootcheckHotReload();
    SyscollectorHotReload();
    CiscatHotReload();
    HostinfoHotReload();
    WinevtHotReload();
    SecurityConfigurationAssessmentHotReload();
    fim_hot_reload();
}

/**
 * @brief Switch the current ruleset with the new one
 * 
 * This function will switch the current ruleset with the new one, updating the global configuration
 * This function is not thread safe
 * @param new_ruleset New ruleset to be set
 * @return w_hotreload_ruleset_data_t* a struct pointing to the old ruleset
 */
w_hotreload_ruleset_data_t* w_hotreload_switch_ruleset(w_hotreload_ruleset_data_t* new_ruleset)
{
    assert(new_ruleset != NULL);

    w_hotreload_ruleset_data_t* old_ruleset = NULL;
    os_calloc(1, sizeof(w_hotreload_ruleset_data_t), old_ruleset);

    // Rules
    old_ruleset->eventlist = os_analysisd_last_events;
    old_ruleset->rule_list = os_analysisd_rulelist;
    os_analysisd_last_events = new_ruleset->eventlist;
    os_analysisd_rulelist = new_ruleset->rule_list;

    // Decoders
    old_ruleset->decoderlist_forpname = os_analysisd_decoderlist_pn;
    old_ruleset->decoderlist_nopname = os_analysisd_decoderlist_nopn;
    old_ruleset->decoder_store = os_analysisd_decoder_store;
    os_analysisd_decoderlist_pn = new_ruleset->decoderlist_forpname;
    os_analysisd_decoderlist_nopn = new_ruleset->decoderlist_nopname;
    os_analysisd_decoder_store = new_ruleset->decoder_store;

    // CDB
    old_ruleset->cdblistnode = os_analysisd_cdblists;
    old_ruleset->cdblistrule = os_analysisd_cdbrules;
    os_analysisd_cdblists = new_ruleset->cdblistnode;
    os_analysisd_cdbrules = new_ruleset->cdblistrule;

    // FTS Switch
    old_ruleset->fts_list = os_analysisd_fts_list;
    old_ruleset->fts_store = os_analysisd_fts_store;
    os_analysisd_fts_list = new_ruleset->fts_list;
    os_analysisd_fts_store = new_ruleset->fts_store;

    // ACM
    old_ruleset->acm_store = os_analysisd_acm_store;
    old_ruleset->acm_lookups = os_analysisd_acm_lookups;
    old_ruleset->acm_purge_ts = os_analysisd_acm_purge_ts;
    os_analysisd_acm_store = new_ruleset->acm_store;
    os_analysisd_acm_lookups = new_ruleset->acm_lookups;
    os_analysisd_acm_purge_ts = new_ruleset->acm_purge_ts;

    // Global Config (list of files and hash rules)
    old_ruleset->rules_hash = Config.g_rules_hash;
    old_ruleset->includes = Config.includes;
    old_ruleset->lists = Config.lists;
    old_ruleset->decoders = Config.decoders;
    Config.g_rules_hash = new_ruleset->rules_hash;
    Config.includes = new_ruleset->includes;
    Config.lists = new_ruleset->lists;
    Config.decoders = new_ruleset->decoders;

    return old_ruleset;
}

/**
 * @brief Create a new ruleset
 * 
 * @param list_msg [output] List of messages to be logged (error, warning and info messages)
 * @return w_hotreload_ruleset_data_t* new ruleset
 */
w_hotreload_ruleset_data_t* w_hotreload_create_ruleset(OSList* list_msg)
{

    bool retval = true; // Failure

    /* Temporary ruleset */
    w_hotreload_ruleset_data_t* ruleset;
    os_calloc(1, sizeof(w_hotreload_ruleset_data_t), ruleset);
    _Config ruleset_config = {0};

    /* Create the event list */
    {
        os_calloc(1, sizeof(EventList), ruleset->eventlist);
        OS_CreateEventList(Config.memorysize, ruleset->eventlist);
    }

    /* Read the ossec.conf to get the ruleset files and alert level */
    if (!w_hotreload_ruleset_load(&ruleset_config, list_msg))
    {
        goto cleanup;
    }
    ruleset->decoders = ruleset_config.decoders;
    ruleset->includes = ruleset_config.includes;
    ruleset->lists = ruleset_config.lists;

    /* Load decoders */
    {
        char** files = ruleset->decoders;
        while (files != NULL && *files != NULL)
        {
            if (ReadDecodeXML(*files,
                              &ruleset->decoderlist_forpname,
                              &ruleset->decoderlist_nopname,
                              &ruleset->decoder_store,
                              list_msg) == 0)
            {
                goto cleanup;
            }
            files++;
        }

        if (SetDecodeXML(
                list_msg, &ruleset->decoder_store, &ruleset->decoderlist_nopname, &ruleset->decoderlist_forpname) == 0)
        {
            goto cleanup;
        }
    }

    /* Load CDB lists */
    {
        char** files = ruleset_config.lists;
        while (files != NULL && *files != NULL)
        {
            if (Lists_OP_LoadList(*files, &ruleset->cdblistnode, list_msg) < 0)
            {
                goto cleanup;
            }
            files++;
        }
        Lists_OP_MakeAll(0, 0, &ruleset->cdblistnode);
    }

    /* Load rules */
    {
        char** files = ruleset_config.includes;

        while (files != NULL && *files != NULL)
        {
            // TODO: Ojo con lo del active response
            if (Rules_OP_ReadRules(*files,
                                   &ruleset->rule_list,
                                   &ruleset->cdblistnode,
                                   &ruleset->eventlist,
                                   &ruleset->decoder_store,
                                   list_msg,
                                   true) < 0)
            {
                goto cleanup;
            }
            files++;
        }
        /* Associate rules and CDB lists */
        OS_ListLoadRules(&ruleset->cdblistnode, &ruleset->cdblistrule);
        _setlevels(ruleset->rule_list, 0);

        /* Creating rule hash */
        if (ruleset->rules_hash = OSHash_Create(), !ruleset->rules_hash)
        {
            goto cleanup;
        }

        AddHash_Rule(ruleset->rule_list);
    }

    /* Initiate the FTS list */
    if (!w_logtest_fts_init(&ruleset->fts_list, &ruleset->fts_store))
    {
        goto cleanup;
    }

    /* Initialize the Accumulator */
    if (!Accumulate_Init(&ruleset->acm_store, &ruleset->acm_lookups, &ruleset->acm_purge_ts))
    {
        goto cleanup;
    }

    retval = false; // Success

cleanup: // TODO Delete this goto

    if (retval)
    {
        w_hotreload_clean_ruleset(&ruleset);
    }

    return ruleset;
}

/**
 * @brief Clean a ruleset
 * 
 * @param ptr_ruleset Pointer to the ruleset to be cleaned
 * @return void
 */
void w_hotreload_clean_ruleset(w_hotreload_ruleset_data_t** ptr_ruleset)
{

    w_hotreload_ruleset_data_t* ruleset = *ptr_ruleset;
    // Clean conf
    free_strarray(ruleset->decoders);
    free_strarray(ruleset->includes);
    free_strarray(ruleset->lists);

    // Clean previous events
    if (ruleset->eventlist)
    {
        os_remove_eventlist(ruleset->eventlist);
    }

    /* Remove rule list and rule hash */
    os_remove_rules_list(ruleset->rule_list);
    if (ruleset->rules_hash)
    {
        OSHash_Free(ruleset->rules_hash);
    }

    /* Remove decoder lists */
    os_remove_decoders_list(ruleset->decoderlist_forpname, ruleset->decoderlist_nopname);
    if (ruleset->decoder_store != NULL)
    {
        OSStore_Free(ruleset->decoder_store);
    }

    /* Remove cdblistnode and cdblistrule */
    os_remove_cdblist(&ruleset->cdblistnode);
    os_remove_cdbrules(&ruleset->cdblistrule);

    /* Remove fts list and hash */
    if (ruleset->fts_store)
    {
        OSHash_Free(ruleset->fts_store);
    }
    OSList_CleanOnlyNodes(ruleset->fts_list);
    os_free(ruleset->fts_list);

    /* Remove accumulator hash */
    if (ruleset->acm_store)
    {
        w_analysisd_accumulate_free(&ruleset->acm_store);
    }

    os_free(ruleset);
    *ptr_ruleset = NULL;
}

/**
 * @brief Load the ruleset files from ossec.conf
 * 
 * @param ruleset_config [output] Ruleset configuration
 * @param list_msg [output] List of messages to be logged (error, warning and info messages)
 * @return false if the ruleset was loaded successfully, true otherwise
 */
bool w_hotreload_ruleset_load(_Config* ruleset_config, OSList* list_msg)
{

    const char* FILE_CONFIG = OSSECCONF;
    const char* XML_MAIN_NODE = "ossec_config";
    bool retval = true;

    OS_XML xml;
    XML_NODE node;

    /* Load and find the root */
    if (OS_ReadXML(FILE_CONFIG, &xml) < 0)
    {
        smerror(list_msg, XML_ERROR, FILE_CONFIG, xml.err, xml.err_line);
        return false;
    }
    else if (node = OS_GetElementsbyNode(&xml, NULL), node == NULL)
    {
        OS_ClearXML(&xml);
        smerror(list_msg, "There are no configuration blocks inside of '%s'", FILE_CONFIG);
        return false;
    }

    /* Find the nodes of ossec_conf */
    for (int i = 0; node[i]; i++)
    {
        /* NULL element */
        if (node[i]->element == NULL)
        {
            smerror(list_msg, XML_ELEMNULL);
            retval = false;
            break;
        }
        /* Main node type (ossec_config) */
        else if (strcmp(node[i]->element, XML_MAIN_NODE) == 0)
        {

            XML_NODE conf_section_arr = NULL;
            conf_section_arr = OS_GetElementsbyNode(&xml, node[i]);

            /* If have configuration sections, iterates them */
            if (conf_section_arr != NULL)
            {
                if (!w_hotreload_ruleset_load_config(&xml, conf_section_arr, ruleset_config, list_msg))
                {
                    smerror(list_msg, CONFIG_ERROR, FILE_CONFIG);
                    OS_ClearNode(conf_section_arr);
                    retval = false;
                    break;
                }
                OS_ClearNode(conf_section_arr);
            }
        }
    }

    /* Clean up */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    return retval;
}

/**
 * @brief Load the ruleset configuration
 * 
 * @param xml XML object
 * @param conf_section_nodes xml nodes from ossec_config
 * @param ruleset_config Ruleset configuration files
 * @param list_msg [output] List of messages to be logged (error, warning and info messages)
 * @return false if the ruleset was loaded successfully, true otherwise
 */
bool w_hotreload_ruleset_load_config(OS_XML* xml,
                                     XML_NODE conf_section_nodes,
                                     _Config* ruleset_config,
                                     OSList* list_msg)
{

    const char* XML_RULESET = "ruleset";
    bool retval = true;

    /* Load configuration of the configuration section */
    for (int i = 0; conf_section_nodes[i]; i++)
    {
        XML_NODE options_node = NULL;

        if (!conf_section_nodes[i]->element)
        {
            smerror(list_msg, XML_ELEMNULL);
            retval = false;
            break;
        }
        /* Empty configuration sections are not allowed. */
        else if (options_node = OS_GetElementsbyNode(xml, conf_section_nodes[i]), options_node == NULL)
        {
            smerror(list_msg, XML_ELEMNULL);
            retval = false;
            break;
        }

        /* Load ruleset */
        if (strcmp(conf_section_nodes[i]->element, XML_RULESET) == 0 &&
            Read_Rules(options_node, ruleset_config, list_msg) < 0)
        {

            OS_ClearNode(options_node);
            retval = false;
            break;
        }

        OS_ClearNode(options_node);
    }

    return retval;
}
