/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef ARGV0
#undef ARGV0
#define ARGV0 "ossec-testrule"
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

/** Internal Functions **/
void OS_ReadMSG(char *ut_str);

/* Analysisd function */
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node, regex_matching *rule_match);

void DecodeEvent(Eventinfo *lf, regex_matching *decoder_match);

// Cleanup at exit
static void onexit();

// Signal handler
static void onsignal(int signum);

/* Print help statement */
__attribute__((noreturn))
static void help_logtest(void)
{
    print_header();
    print_out("  %s: -[Vhdtva] [-c config] [-D dir] [-U rule:alert:decoder]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -a          Alerts output");
    print_out("    -v          Verbose (full) output/rule debugging");
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -U <rule:alert:decoder>  Unit test. Refer to contrib/ossec-testing/runtests.py");
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int test_config = 0;
    int c = 0;
    char *ut_str = NULL;
    const char *dir = DEFAULTDIR;
    const char *cfg = DEFAULTCPATH;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    uid_t uid;
    gid_t gid;
    struct sigaction action = { .sa_handler = onsignal };
    int quiet = 0;
    num_rule_matching_threads = 1;
    last_events_list = NULL;

    /* Set the name */
    OS_SetName(ARGV0);

    thishour = 0;
    today = 0;
    prev_year = 0;
    full_output = 0;
    alert_only = 0;

    active_responses = NULL;
    memset(prev_month, '\0', 4);

#ifdef LIBGEOIP_ENABLED
    geoipdb = NULL;
#endif

    while ((c = getopt(argc, argv, "VatvdhU:D:c:q")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 't':
                test_config = 1;
                break;
            case 'h':
                help_logtest();
                break;
            case 'd':
                nowDebug();
                break;
            case 'U':
                if (!optarg) {
                    merror_exit("-U needs an argument");
                }
                ut_str = optarg;
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
            case 'a':
                alert_only = 1;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'v':
                full_output = 1;
                break;
            default:
                help_logtest();
                break;
        }
    }

    /* Read configuration file */
    if (GlobalConf(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    mdebug1(READ_CONFIG);

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

    /* Get server hostname */
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

    srandom_init();

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group);
    }

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

    if (!last_events_list) {
        os_calloc(1, sizeof(EventList), last_events_list);
        OS_CreateEventList(Config.memorysize, last_events_list);
    }

    /*
     * Anonymous Section: Load rules, decoders, and lists
     *
     * As lists require two pass loading of rules that make use of list lookups
     * are created with blank database structs, and need to be filled in after
     * completion of all rules and lists.
     */
    {
        {
            /* Load decoders */
            /* Initialize the decoders list */
            OS_CreateOSDecoderList();

            if (!Config.decoders) {
                /* Legacy loading */
                /* Read decoders */
                Read_Rules(NULL, &Config, NULL);

                /* New loaded based on file specified in ossec.conf */
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

                /* Read local ones */

                c = ReadDecodeXML("etc/local_decoder.xml");
                if (!c) {
                    if ((c != -2)) {
                        merror_exit(CONFIG_ERROR,  XML_LDECODER);
                    }
                } else {
                    minfo("Reading local decoder file.");
                }

            } else {
                /* New loaded based on file specified in ossec.conf */
                char **decodersfiles;
                decodersfiles = Config.decoders;
                while ( decodersfiles && *decodersfiles) {

                    if(!quiet) {
                        mdebug1("Reading decoder file %s.", *decodersfiles);
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
                    mdebug1("Reading the lists file: '%s'", *listfiles);
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
                    mdebug1("Reading rules file: '%s'", *rulesfiles);
                    if (Rules_OP_ReadRules(*rulesfiles) < 0) {
                        merror_exit(RULES_ERROR, *rulesfiles);
                    }

                    free(*rulesfiles);
                    rulesfiles++;
                }

                free(Config.includes);
                Config.includes = NULL;
            }

            /* Find all rules with that require list lookups and attache the
             * the correct list struct to the rule.  This keeps rules from
             * having to search thought the list of lists for the correct file
             * during rule evaluation.
             */
            OS_ListLoadRules();
        }
    }

    w_init_queues();

    /* Fix the levels/accuracy */
    {
        int total_rules;
        RuleNode *tmp_node = OS_GetFirstRule();

        total_rules = _setlevels(tmp_node, 0);
        mdebug1("Total rules enabled: '%d'", total_rules);
    }

    /* Creating a rules hash (for reading alerts from other servers) */
    {
        RuleNode *tmp_node = OS_GetFirstRule();
        Config.g_rules_hash = OSHash_Create();
        if (!Config.g_rules_hash) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        AddHash_Rule(tmp_node);
    }

    if (test_config == 1) {
        exit(0);
    }

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* Signal handling */

    atexit(onexit);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* Going to main loop */
    OS_ReadMSG(ut_str);

    exit(0);
}

/* Receive the messages (events) and analyze them */
__attribute__((noreturn))
void OS_ReadMSG(char *ut_str)
{
    char msg[OS_MAXSTR + 1];
    int exit_code = 0;
    char *ut_alertlevel = NULL;
    char *ut_rulelevel = NULL;
    char *ut_decoder_name = NULL;
    regex_matching rule_match, decoder_match;
    memset(&rule_match, 0, sizeof(regex_matching));
    memset(&decoder_match, 0, sizeof(regex_matching));

    if (ut_str) {
        /* XXX Break apart string */
        ut_rulelevel = ut_str;
        ut_alertlevel =  strchr(ut_rulelevel, ':');
        if (!ut_alertlevel) {
            merror_exit("-U requires the matching format to be "
                      "\"<rule_id>:<alert_level>:<decoder_name>\"");
        } else {
            *ut_alertlevel = '\0';
            ut_alertlevel++;
        }
        ut_decoder_name = strchr(ut_alertlevel, ':');
        if (!ut_decoder_name) {
            merror_exit("-U requires the matching format to be "
                      "\"<rule_id>:<alert_level>:<decoder_name>\"");
        } else {
            *ut_decoder_name = '\0';
            ut_decoder_name++;
        }
    }

    RuleInfoDetail *last_info_detail;
    Eventinfo *lf;

    RuleInfo * currently_rule;
    /* Null global pointer to current rule */
    currently_rule = NULL;

    /* Initiate the FTS list */
    if (!FTS_Init(1)) {
        merror_exit(FTS_LIST_ERROR);
    }

    /* Initialize the Accumulator */
    if (!Accumulate_Init()) {
        merror("accumulator: ERROR: Initialization failed");
        exit(1);
    }

    __crt_ftell = 1;

    /* Get current time before starting */
    c_time = time(NULL);

    /* Do some cleanup */
    memset(msg, '\0', OS_MAXSTR + 1);

    if (!alert_only) {
        print_out("%s: Type one log per line.\n", ARGV0);
    }

    /* Daemon loop */
    while (1) {
        os_calloc(1, sizeof(Eventinfo), lf);
        os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);

        /* Fix the msg */
        snprintf(msg, 15, "1:stdin:");

        /* Receive message from queue */
        if (fgets(msg + 8, OS_MAXSTR - 8, stdin)) {
            RuleNode *rulenode_pt;

            /* Get the time we received the event */
            c_time = time(NULL);

            /* Remov newline */
            if (msg[strlen(msg) - 1] == '\n') {
                msg[strlen(msg) - 1] = '\0';
            }

            /* Make sure we ignore blank lines */
            if (strlen(msg) < 10) {
                Free_Eventinfo(lf);
                continue;
            }

            if (!alert_only) {
                print_out("\n");
            }

            /* Default values for the log info */
            Zero_Eventinfo(lf);
            lf->tid = 0;

            /* Clean the msg appropriately */
            if (OS_CleanMSG(msg, lf) < 0) {
                merror(IMSG_ERROR, msg);

                Free_Eventinfo(lf);

                continue;
            }

            /* Current rule must be null in here */
            currently_rule = NULL;

            /***  Run decoders ***/
            /* Get log size */
            lf->size = strlen(lf->log);

            /* Decode event */
            DecodeEvent(lf, &decoder_match);

            /* Run accumulator */
            if ( lf->decoder_info->accumulate == 1 ) {
                print_out("\n**ACCUMULATOR: LEVEL UP!!**\n");
                lf = Accumulate(lf);
            }

            /* Loop over all the rules */
            rulenode_pt = OS_GetFirstRule();
            if (!rulenode_pt) {
                merror_exit("Rules in an inconsistent state. Exiting.");
            }

#ifdef TESTRULE
            if (full_output && !alert_only) {
                print_out("\n**Rule debugging:");
            }
#endif

            do {
                if (lf->decoder_info->type == OSSEC_ALERT) {
                    if (!lf->generated_rule) {
                        break;
                    }

                    /* Process the alert */
                    currently_rule = lf->generated_rule;
                }

                /* The categories must match */
                else if (rulenode_pt->ruleinfo->category !=
                         lf->decoder_info->type) {
                    continue;
                }

                /* Check each rule */
                else if (currently_rule = OS_CheckIfRuleMatch(lf, rulenode_pt, &rule_match), !currently_rule) {
                    continue;
                }

                /* Pointer to the rule that generated it */
                lf->generated_rule = currently_rule;

#ifdef TESTRULE
                if (!alert_only) {
                    const char *(ruleinfodetail_text[]) = {"Text", "Link", "CVE", "OSVDB", "BUGTRACKID"};
                    lf->comment = ParseRuleComment(lf);
                    print_out("\n**Phase 3: Completed filtering (rules).");
                    print_out("       Rule id: '%d'", currently_rule->sigid);
                    print_out("       Level: '%d'", currently_rule->level);
                    print_out("       Description: '%s'", lf->comment);
                    for (last_info_detail = currently_rule->info_details; last_info_detail != NULL; last_info_detail = last_info_detail->next) {
                        print_out("       Info - %s: '%s'", ruleinfodetail_text[last_info_detail->type], last_info_detail->data);
                    }
                }
#endif

                /* Ignore level 0 */
                if (currently_rule->level == 0) {
                    break;
                }

                /* Check ignore time */
                if (currently_rule->ignore_time) {
                    if (currently_rule->time_ignored == 0) {
                        currently_rule->time_ignored = lf->generate_time;
                    }
                    /* If the current time - the time the rule was ignored
                     * is less than the time it should be ignored,
                     * do not alert again
                     */
                    else if ((lf->generate_time - currently_rule->time_ignored)
                             < currently_rule->ignore_time) {
                        break;
                    } else {
                        currently_rule->time_ignored = 0;
                    }
                }

                /* Check if we should ignore it */
                if (currently_rule->ckignore && IGnore(lf, 0)) {
                    lf->generated_rule = NULL;
                    break;
                }

                /* Check if we need to add to ignore list */
                if (currently_rule->ignore) {
                    AddtoIGnore(lf, 0);
                }

                /* Log the alert if configured to */
                if (currently_rule->alert_opts & DO_LOGALERT) {
                    if (alert_only) {
                        OS_LogOutput(lf);
                        __crt_ftell++;
                    } else {
                        print_out("**Alert to be generated.\n\n");
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
                    unsigned int i = 0;

                    while (i < currently_rule->group_prev_matched_sz) {
                        if (!OSList_AddData(
                                    currently_rule->group_prev_matched[i],
                                    lf)) {
                            merror("Unable to add data to grp list.");
                        }
                        i++;
                    }
                }

                OS_AddEvent(lf, last_events_list);
                break;

            } while ((rulenode_pt = rulenode_pt->next) != NULL);

            if (ut_str) {
                /* Set up exit code if we are doing unit testing */
                char holder[1024];
                holder[1] = '\0';
                exit_code = 3;
                print_out("lf->decoder_info->name: '%s'", lf->decoder_info->name);
                print_out("ut_decoder_name       : '%s'", ut_decoder_name);
                if (lf->decoder_info->name != NULL && strcasecmp(ut_decoder_name, lf->decoder_info->name) == 0) {
                    exit_code--;

                    if (!currently_rule) {
                        merror("currently_rule not set!");
                        exit(-1);
                    }
                    snprintf(holder, 1023, "%d", currently_rule->sigid);
                    if (strcasecmp(ut_rulelevel, holder) == 0) {
                        exit_code--;
                        snprintf(holder, 1023, "%d", currently_rule->level);
                        if (strcasecmp(ut_alertlevel, holder) == 0) {
                            exit_code--;
                            printf("%d\n", exit_code);
                        }
                    }
                } else if (lf->decoder_info->name != NULL) {
                    print_out("decoder matched : '%s'", lf->decoder_info->name);
                    print_out("decoder expected: '%s'", ut_decoder_name);
                } else {
                    print_out("decoder matched : 'NULL'");
                }
            }

            /* Only clear the memory if the eventinfo was not
             * added to the stateful memory
             * -- message is free inside clean event --
             */
            if (lf->generated_rule == NULL) {
                Free_Eventinfo(lf);
            }

        } else {
            exit(exit_code);
        }
    }
    exit(exit_code);
}

// Cleanup at exit
void onexit() {
    char testdir[PATH_MAX + 1];
    snprintf(testdir, PATH_MAX + 1, "%s/%s", DIFF_DIR, DIFF_TEST_HOST);
    rmdir_ex(testdir);
}

// Signal handler
void onsignal(__attribute__((unused)) int signum) {
    exit(EXIT_SUCCESS);
}
