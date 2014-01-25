/* @(#) $Id: ./src/analysisd/analysisd.c, 2012/07/26 dcid Exp $
 */

/* Copyright (C) 2010-2012 Trend Micro Inc.
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


/* Part of the OSSEC
 * Available at http://www.ossec.net
 */


/* ossec-analysisd.
 * Responsible for correlation and log decoding.
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


/** Local headers **/
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"

#include "eventinfo.h"
#include "analysisd.h"

#include "picviz.h"

#ifdef PRELUDE
#include "prelude.h"
#endif

#ifdef ZEROMQ_OUTPUT
#include "zeromq_output.h"
#endif

/** Global data **/

/* execd queue */
int execdq = 0;

/* active response queue */
int arq = 0;


/** Internal Functions **/
void OS_ReadMSG(int m_queue);
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node);


/** External functions prototypes (only called here) **/

/* For config  */
int GlobalConf(char * cfgfile);


/* For rules */
void Rules_OP_CreateRules();
void Lists_OP_CreateLists();
int Rules_OP_ReadRules(char * cfgfile);
int _setlevels(RuleNode *node, int nnode);
int AddHash_Rule(RuleNode *node);


/* For cleanmsg */
int OS_CleanMSG(char *msg, Eventinfo *lf);


/* for FTS */
int FTS_Init();
int FTS(Eventinfo *lf);
int AddtoIGnore(Eventinfo *lf);
int IGnore(Eventinfo *lf);
int doDiff(RuleInfo *currently_rule, Eventinfo *lf);


/* For decoders */
void DecodeEvent(Eventinfo *lf);
int DecodeSyscheck(Eventinfo *lf);
int DecodeRootcheck(Eventinfo *lf);
int DecodeHostinfo(Eventinfo *lf);


/* For Decoders */
int ReadDecodeXML(char *file);
int SetDecodeXML();


/* For syscheckd (integrity checking) */
void SyscheckInit();
void RootcheckInit();
void HostinfoInit();


/* For stats */
int Start_Hour();
int Check_Hour(Eventinfo *lf);
void Update_Hour();
void DumpLogstats();

/* Hourly alerts */
int hourly_alerts;
int hourly_events;
int hourly_syscheck;
int hourly_firewall;


/** int main(int argc, char **argv)
 */
#ifndef TESTRULE
int main(int argc, char **argv)
#else
int main_analysisd(int argc, char **argv)
#endif
{
    int c = 0, m_queue = 0, test_config = 0,run_foreground = 0;
    char *dir = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    int uid = 0,gid = 0;

    char *cfg = DEFAULTCPATH;

    /* Setting the name */
    OS_SetName(ARGV0);

    thishour = 0;
    today = 0;
    prev_year = 0;
    memset(prev_month, '\0', 4);
    hourly_alerts = 0;
    hourly_events = 0;
    hourly_syscheck = 0;
    hourly_firewall = 0;

    while((c = getopt(argc, argv, "Vtdhfu:g:D:c:")) != -1){
        switch(c){
	    case 'V':
		print_version();
		break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user = optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group = optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
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


    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);
    DEBUG_MSG("%s: DEBUG: Starting on debug mode - %d ", ARGV0, (int)time(0));


    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);


    /* Found user */
    debug1(FOUND_USER, ARGV0);


    /* Initializing Active response */
    AR_Init();
    if(AR_ReadConfig(test_config, cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR,ARGV0, cfg);
    }
    debug1(ASINIT, ARGV0);


    /* Reading configuration file */
    if(GlobalConf(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR,ARGV0, cfg);
    }

    debug1(READ_CONFIG, ARGV0);


    /* Fixing Config.ar */
    Config.ar = ar_flag;
    if(Config.ar == -1)
        Config.ar = 0;


    /* Getting servers hostname */
    memset(__shost, '\0', 512);
    if(gethostname(__shost, 512 -1) != 0)
    {
        strncpy(__shost, OSSEC_SERVER, 512 -1);
    }
    else
    {
        char *_ltmp;

        /* Remove domain part if available */
        _ltmp = strchr(__shost, '.');
        if(_ltmp)
            *_ltmp = '\0';
    }

    /* going on Daemon mode */
    if(!test_config && !run_foreground)
    {
        nowDaemon();
        goDaemon();
    }


    /* Starting prelude */
    #ifdef PRELUDE
    if(Config.prelude)
    {
        prelude_start(Config.prelude_profile, argc, argv);
    }
    #endif

    /* Starting zeromq */
    #ifdef ZEROMQ_OUTPUT 
    if(Config.zeromq_output)
    {
      zeromq_output_start(Config.zeromq_output_uri, argc, argv);
    }
    #endif

    /* Opening the Picviz socket */
    if(Config.picviz)
    {
        OS_PicvizOpen(Config.picviz_socket);
        chown(Config.picviz_socket, uid, gid);
    }

    /* Setting the group */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    /* Chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);


    nowChroot();



    /*
     * Anonymous Section: Load rules, decoders, and lists
     *
     * As lists require two pass loading of rules that make use of list lookups
     * are created with blank database structs, and need to be filled in after
     * completion of all rules and lists.
     */
    {
        {
            /* Initializing the decoders list */
            OS_CreateOSDecoderList();

            if(!Config.decoders)
            { /* Legacy loading */
                /* Reading decoders */
                if(!ReadDecodeXML(XML_DECODER))
                {
                    ErrorExit(CONFIG_ERROR, ARGV0,  XML_DECODER);
                }

                /* Reading local ones. */
                c = ReadDecodeXML(XML_LDECODER);
                if(!c)
                {
                    if((c != -2))
                        ErrorExit(CONFIG_ERROR, ARGV0,  XML_LDECODER);
                }
                else
                {
                    if(!test_config)
                        verbose("%s: INFO: Reading local decoder file.", ARGV0);
                }
            }
            else
            { /* New loaded based on file speified in ossec.conf */
                char **decodersfiles;
                decodersfiles = Config.decoders;
                while( decodersfiles && *decodersfiles)
                {
                    if(!test_config)
                        verbose("%s: INFO: Reading decoder file %s.", ARGV0, *decodersfiles);
                    if(!ReadDecodeXML(*decodersfiles))
                        ErrorExit(CONFIG_ERROR, ARGV0, *decodersfiles);

                    free(*decodersfiles);
                    decodersfiles++;
                }
            }

            /* Load decoders */
            SetDecodeXML();
        }
        { /* Load Lists */
            /* Initializing the lists of list struct */
            Lists_OP_CreateLists();
            /* Load each list into list struct */
            {
                char **listfiles;
                listfiles = Config.lists;
                while(listfiles && *listfiles)
                {
                    if(!test_config)
                        verbose("%s: INFO: Reading loading the lists file: '%s'", ARGV0, *listfiles);
                    if(Lists_OP_LoadList(*listfiles) < 0)
                        ErrorExit(LISTS_ERROR, ARGV0, *listfiles);
                    free(*listfiles);
                    listfiles++;
                }
                free(Config.lists);
                Config.lists = NULL;
            }
        }
        { /* Load Rules */
            /* Creating the rules list */
            Rules_OP_CreateRules();

            /* Reading the rules */
            {
                char **rulesfiles;
                rulesfiles = Config.includes;
                while(rulesfiles && *rulesfiles)
                {
                    if(!test_config)
                        verbose("%s: INFO: Reading rules file: '%s'", ARGV0, *rulesfiles);
                    if(Rules_OP_ReadRules(*rulesfiles) < 0)
                        ErrorExit(RULES_ERROR, ARGV0, *rulesfiles);

                    free(*rulesfiles);
                    rulesfiles++;
                }

                free(Config.includes);
                Config.includes = NULL;
            }

            /* Find all rules with that require list lookups and attache the
             * the correct list struct to the rule.  This keeps rules from having to
             * search thought the list of lists for the correct file during rule evaluation.
             */
            OS_ListLoadRules();
        }
    }


    /* Fixing the levels/accuracy */
    {
        int total_rules;
        RuleNode *tmp_node = OS_GetFirstRule();

        total_rules = _setlevels(tmp_node, 0);
        if(!test_config)
            verbose("%s: INFO: Total rules enabled: '%d'", ARGV0, total_rules);
    }



    /* Creating a rules hash (for reading alerts from other servers). */
    {
        RuleNode *tmp_node = OS_GetFirstRule();
        Config.g_rules_hash = OSHash_Create();
        if(!Config.g_rules_hash)
        {
            ErrorExit(MEM_ERROR, ARGV0);
        }
        AddHash_Rule(tmp_node);
    }



    /* Ignored files on syscheck */
    {
        char **files;
        files = Config.syscheck_ignore;
        while(files && *files)
        {
            if(!test_config)
                verbose("%s: INFO: Ignoring file: '%s'", ARGV0, *files);
            files++;
        }
    }


    /* Checking if log_fw is enabled. */
    Config.logfw = getDefine_Int("analysisd",
                                 "log_fw",
                                 0, 1);


    /* Success on the configuration test */
    if(test_config)
        exit(0);


    /* Verbose message */
    debug1(PRIVSEP_MSG, ARGV0, dir, user);


    /* Signal manipulation	*/
    StartSIG(ARGV0);


    /* Setting the user */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    /* Creating the PID file */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


    /* Setting the queue */
    if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
        ErrorExit(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));


    /* White list */
    if(Config.white_list == NULL)
    {
        if(Config.ar)
            verbose("%s: INFO: No IP in the white list for active reponse.", ARGV0);
    }
    else
    {
        if(Config.ar)
        {
            os_ip **wl;
            int wlc = 0;
            wl = Config.white_list;
            while(*wl)
            {
                verbose("%s: INFO: White listing IP: '%s'",ARGV0, (*wl)->ip);
                wl++;wlc++;
            }
            verbose("%s: INFO: %d IPs in the white list for active response.",
                    ARGV0, wlc);
        }
    }

    /* Hostname White list */
    if(Config.hostname_white_list == NULL)
    {
        if(Config.ar)
            verbose("%s: INFO: No Hostname in the white list for active reponse.",
            ARGV0);
    }
    else
    {
        if(Config.ar)
        {
            int wlc = 0;
            OSMatch **wl;

            wl = Config.hostname_white_list;
            while(*wl)
            {
                char **tmp_pts = (*wl)->patterns;
                while(*tmp_pts)
                {
                    verbose("%s: INFO: White listing Hostname: '%s'",ARGV0,*tmp_pts);
                    wlc++;
                    tmp_pts++;
                }
                wl++;
            }
            verbose("%s: INFO: %d Hostname(s) in the white list for active response.",
                    ARGV0, wlc);
        }
    }


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* Going to main loop */	
    OS_ReadMSG(m_queue);

    if (Config.picviz)
    {
        OS_PicvizClose();
    }

    exit(0);

}



/* OS_ReadMSG.
 * Main function. Receives the messages(events)
 * and analyze them all.
 */
#ifndef TESTRULE
void OS_ReadMSG(int m_queue)
#else
void OS_ReadMSG_analysisd(int m_queue)
#endif
{
    int i;
    char msg[OS_MAXSTR +1];
    Eventinfo *lf;

    RuleInfo *stats_rule;


    /* Null to global currently pointers */
    currently_rule = NULL;

    /* Initiating the logs */
    OS_InitLog();


    /* Initiating the integrity database */
    SyscheckInit();


    /* Initializing Rootcheck */
    RootcheckInit();


    /* Initializing host info */
    HostinfoInit();


    /* Creating the event list */
    OS_CreateEventList(Config.memorysize);


    /* Initiating the FTS list */
    if(!FTS_Init())
    {
        ErrorExit(FTS_LIST_ERROR, ARGV0);
    }


    /* Starting the active response queues */
    if(Config.ar)
    {
        /* Waiting the ARQ to settle .. */
        sleep(3);


        #ifndef LOCAL
        if(Config.ar & REMOTE_AR)
        {
            if((arq = StartMQ(ARQUEUE, WRITE)) < 0)
            {
                merror(ARQ_ERROR, ARGV0);

                /* If LOCAL_AR is set, keep it there */
                if(Config.ar & LOCAL_AR)
                {
                    Config.ar = 0;
                    Config.ar|=LOCAL_AR;
                }
                else
                {
                    Config.ar = 0;
                }
            }
            else
            {
                verbose(CONN_TO, ARGV0, ARQUEUE, "active-response");
            }
        }

        #else
        /* Only for LOCAL_ONLY installs */
        if(Config.ar & REMOTE_AR)
        {
            if(Config.ar & LOCAL_AR)
            {
                Config.ar = 0;
                Config.ar|=LOCAL_AR;
            }
            else
            {
                Config.ar = 0;
            }
        }
        #endif

        if(Config.ar & LOCAL_AR)
        {
            if((execdq = StartMQ(EXECQUEUE, WRITE)) < 0)
            {
                merror(ARQ_ERROR, ARGV0);

                /* If REMOTE_AR is set, keep it there */
                if(Config.ar & REMOTE_AR)
                {
                    Config.ar = 0;
                    Config.ar|=REMOTE_AR;
                }
                else
                {
                    Config.ar = 0;
                }
            }
            else
            {
                verbose(CONN_TO, ARGV0, EXECQUEUE, "exec");
            }
        }
    }
    debug1("%s: DEBUG: Active response Init completed.", ARGV0);


    /* Getting currently time before starting */
    c_time = time(NULL);


    /* Starting the hourly/weekly stats */
    if(Start_Hour() < 0)
        Config.stats = 0;
    else
    {
        /* Initializing stats rules */
        stats_rule = zerorulemember(
                STATS_MODULE,
                Config.stats,
                0,0,0,0,0,0);

        if(!stats_rule)
        {
            ErrorExit(MEM_ERROR, ARGV0);
        }
        stats_rule->group = "stats,";
        stats_rule->comment = "Excessive number of events (above normal).";
    }


    /* Doing some cleanup */
    memset(msg, '\0', OS_MAXSTR +1);


    /* Initializing the logs */
    {
        lf = (Eventinfo *)calloc(1,sizeof(Eventinfo));
        if(!lf)
            ErrorExit(MEM_ERROR, ARGV0);
        lf->year = prev_year;
        strncpy(lf->mon, prev_month, 3);
        lf->day = today;

        if(OS_GetLogLocation(lf) < 0)
        {
            ErrorExit("%s: Error allocating log files", ARGV0);
        }

        Free_Eventinfo(lf);
    }


    debug1("%s: DEBUG: Startup completed. Waiting for new messages..",ARGV0);

    if(Config.custom_alert_output)
      debug1("%s: INFO: Custom output found.!",ARGV0);

    /* Daemon loop */
    while(1)
    {
        lf = (Eventinfo *)calloc(1,sizeof(Eventinfo));

        /* This shouldn't happen .. */
        if(lf == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        DEBUG_MSG("%s: DEBUG: Waiting for msgs - %d ", ARGV0, (int)time(0));


        /* Receive message from queue */
        if((i = OS_RecvUnix(m_queue, OS_MAXSTR, msg)))
        {
            RuleNode *rulenode_pt;

            /* Getting the time we received the event */
            c_time = time(NULL);


            /* Default values for the log info */
            Zero_Eventinfo(lf);


            /* Checking for a valid message. */
            if(i < 4)
            {
                merror(IMSG_ERROR, ARGV0, msg);
                Free_Eventinfo(lf);
                continue;
            }


            /* Message before extracting header */
            DEBUG_MSG("%s: DEBUG: Received msg: %s ", ARGV0, msg);


            /* Clean the msg appropriately */
            if(OS_CleanMSG(msg, lf) < 0)
            {
                merror(IMSG_ERROR,ARGV0, msg);
                Free_Eventinfo(lf);
                continue;
            }


            /* Msg cleaned */
            DEBUG_MSG("%s: DEBUG: Msg cleanup: %s ", ARGV0, lf->log);


            /* Currently rule must be null in here */
            currently_rule = NULL;


            /** Checking the date/hour changes **/

            /* Update the hour */
            if(thishour != __crt_hour)
            {
                /* Search all the rules and print the number
                 * of alerts that each one fired.
                 */
                DumpLogstats();
                thishour = __crt_hour;

                /* Check if the date has changed */
                if(today != lf->day)
                {
                    if(Config.stats)
                    {
                        /* Update the hourly stats (done daily) */
                        Update_Hour();
                    }

                    if(OS_GetLogLocation(lf) < 0)
                    {
                        ErrorExit("%s: Error allocating log files", ARGV0);
                    }

                    today = lf->day;
                    strncpy(prev_month, lf->mon, 3);
                    prev_year = lf->year;
                }
            }


            /* Incrementing number of events received */
            hourly_events++;


            /***  Running decoders ***/

            /* Integrity check from syscheck */
            if(msg[0] == SYSCHECK_MQ)
            {
                hourly_syscheck++;

                if(!DecodeSyscheck(lf))
                {
                    /* We don't process syscheck events further */
                    goto CLMEM;
                }

                /* Getting log size */
                lf->size = strlen(lf->log);
            }

            /* Rootcheck decoding */
            else if(msg[0] == ROOTCHECK_MQ)
            {
                if(!DecodeRootcheck(lf))
                {
                    /* We don't process rootcheck events further */
                    goto CLMEM;
                }
                lf->size = strlen(lf->log);
            }

            /* Host information special decoder */
            else if(msg[0] == HOSTINFO_MQ)
            {
                if(!DecodeHostinfo(lf))
                {
                    /* We don't process hostinfo events further */
                    goto CLMEM;
                }
                lf->size = strlen(lf->log);
            }

            /* Run the general Decoders  */
            else
            {
                /* Getting log size */
                lf->size = strlen(lf->log);

                DecodeEvent(lf);
            }


            /* Firewall event */
            if(lf->decoder_info->type == FIREWALL)
            {
                /* If we could not get any information from
                 * the log, just ignore it
                 */
                hourly_firewall++;
                if(Config.logfw)
                {
                    if(!FW_Log(lf))
                    {
                        goto CLMEM;
                    }
                }
            }


            /* We only check if the last message is
             * duplicated on syslog.
             */
            else if(lf->decoder_info->type == SYSLOG)
            {
                /* Checking if the message is duplicated */
                if(LastMsg_Stats(lf->full_log) == 1)
                    goto CLMEM;
                else
                    LastMsg_Change(lf->full_log);
            }


            /* Stats checking */
            if(Config.stats)
            {
                if(Check_Hour(lf) == 1)
                {
                    void *saved_rule = lf->generated_rule;
                    char *saved_log;

                    /* Saving previous log */
                    saved_log = lf->full_log;

                    lf->generated_rule = stats_rule;
                    lf->full_log = __stats_comment;


                    /* alert for statistical analysis */
                    if(stats_rule->alert_opts & DO_LOGALERT)
                    {
                        __crt_ftell = ftell(_aflog);
                        if(Config.custom_alert_output)
                        {
                          OS_CustomLog(lf,Config.custom_alert_output_format);
                        }
                        else
                        {
                          OS_Log(lf);
                        }

                    }


                    /* Set lf to the old values */
                    lf->generated_rule = saved_rule;
                    lf->full_log = saved_log;
                }
            }


            /* Checking the rules */
            DEBUG_MSG("%s: DEBUG: Checking the rules - %d ",
                           ARGV0, lf->decoder_info->type);


            /* Looping all the rules */
            rulenode_pt = OS_GetFirstRule();
            if(!rulenode_pt)
            {
                ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                        ARGV0);
            }


            do
            {
                if(lf->decoder_info->type == OSSEC_ALERT)
                {
                    if(!lf->generated_rule)
                    {
                        goto CLMEM;
                    }

                    /* We go ahead in here and process the alert. */
                    currently_rule = lf->generated_rule;
                }

                /* The categories must match */
                else if(rulenode_pt->ruleinfo->category !=
                        lf->decoder_info->type)
                {
                    continue;
                }

                /* Checking each rule. */
                else if((currently_rule = OS_CheckIfRuleMatch(lf, rulenode_pt))
                        == NULL)
                {
                    continue;
                }


                /* Ignore level 0 */
                if(currently_rule->level == 0)
                {
                    break;
                }


                /* Checking ignore time */
                if(currently_rule->ignore_time)
                {
                    if(currently_rule->time_ignored == 0)
                    {
                        currently_rule->time_ignored = lf->time;
                    }
                    /* If the currently time - the time the rule was ignored
                     * is less than the time it should be ignored,
                     * leave (do not alert again).
                     */
                    else if((lf->time - currently_rule->time_ignored)
                            < currently_rule->ignore_time)
                    {
                        break;
                    }
                    else
                    {
                        currently_rule->time_ignored = lf->time;
                    }
                }


                /* Pointer to the rule that generated it */
                lf->generated_rule = currently_rule;


                /* Checking if we should ignore it */
                if(currently_rule->ckignore && IGnore(lf))
                {
                    /* Ignoring rule */
                    lf->generated_rule = NULL;
                    break;
                }


                /* Checking if we need to add to ignore list */
                if(currently_rule->ignore)
                {
                    AddtoIGnore(lf);
                }


                /* Log the alert if configured to ... */
                if(currently_rule->alert_opts & DO_LOGALERT)
                {
                    __crt_ftell = ftell(_aflog);

                    if(Config.custom_alert_output)
                    {
                      OS_CustomLog(lf,Config.custom_alert_output_format);
                    }
                    else
                    {
                      OS_Log(lf);
                    }
                }


                /* Log to prelude */
                #ifdef PRELUDE
                if(Config.prelude)
                {
                    if(Config.prelude_log_level <= currently_rule->level)
                    {
                        OS_PreludeLog(lf);
                    }
                }
                #endif

                /* Log to zeromq */
                #ifdef ZEROMQ_OUTPUT 
                if(Config.zeromq_output) 
                {
                    zeromq_output_event(lf);
                }
                #endif


                /* Log to Picviz */
                if (Config.picviz)
                {
                    OS_PicvizLog(lf);
                }


                /* Execute an active response */
                if(currently_rule->ar)
                {
                    int do_ar;
                    active_response **rule_ar;

                    rule_ar = currently_rule->ar;

                    while(*rule_ar)
                    {
                        do_ar = 1;
                        if((*rule_ar)->ar_cmd->expect & USERNAME)
                        {
                            if(!lf->dstuser ||
                                !OS_PRegex(lf->dstuser,"^[a-zA-Z._0-9@?-]*$"))
                            {
                                if(lf->dstuser)
                                    merror(CRAFTED_USER, ARGV0, lf->dstuser);
                                do_ar = 0;
                            }
                        }
                        if((*rule_ar)->ar_cmd->expect & SRCIP)
                        {
                            if(!lf->srcip ||
                                !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$"))
                            {
                                if(lf->srcip)
                                    merror(CRAFTED_IP, ARGV0, lf->srcip);
                                do_ar = 0;
                            }
                        }

                        if(do_ar)
                        {
                            OS_Exec(&execdq, &arq, lf, *rule_ar);
                        }
                        rule_ar++;
                    }
                }


                /* Copy the structure to the state memory of if_matched_sid */
                if(currently_rule->sid_prev_matched)
                {
                    if(!OSList_AddData(currently_rule->sid_prev_matched, lf))
                    {
                        merror("%s: Unable to add data to sig list.", ARGV0);
                    }
                    else
                    {
                        lf->sid_node_to_delete =
                            currently_rule->sid_prev_matched->last_node;
                    }
                }
                /* Group list */
                else if(currently_rule->group_prev_matched)
                {
                    i = 0;

                    while(i < currently_rule->group_prev_matched_sz)
                    {
                        if(!OSList_AddData(
                                currently_rule->group_prev_matched[i],
                                lf))
                        {
                           merror("%s: Unable to add data to grp list.",ARGV0);
                        }
                        i++;
                    }
                }

                OS_AddEvent(lf);

                break;

            }while((rulenode_pt = rulenode_pt->next) != NULL);


            /* If configured to log all, do it */
            if(Config.logall)
                OS_Store(lf);


            /* Cleaning the memory */	
            CLMEM:


            /* Only clear the memory if the eventinfo was not
             * added to the stateful memory
             * -- message is free inside clean event --
             */
            if(lf->generated_rule == NULL)
                Free_Eventinfo(lf);

        }
        else
        {
            free(lf);
        }
    }
    return;
}


/* CheckIfRuleMatch v0.1
 * Will check if the currently_rule matches the event information
 */
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
    RuleInfo *currently_rule = curr_node->ruleinfo;


    /* Can't be null */
    if(!currently_rule)
    {
        merror("%s: Inconsistent state. currently rule NULL", ARGV0);
        return(NULL);
    }


    #ifdef TESTRULE
    if(full_output && !alert_only)
    print_out("    Trying rule: %d - %s", currently_rule->sigid,
                                          currently_rule->comment);
    #endif


    /* Checking if any decoder pre-matched here */
    if(currently_rule->decoded_as &&
       currently_rule->decoded_as != lf->decoder_info->id)
    {
        return(NULL);
    }


    /* Checking program name */
    if(currently_rule->program_name)
    {
        if(!lf->program_name)
            return(NULL);

        if(!OSMatch_Execute(lf->program_name,
                            lf->p_name_size,
                            currently_rule->program_name))
                        return(NULL);
    }


    /* Checking for the id */
    if(currently_rule->id)
    {
        if(!lf->id)
        {
            return(NULL);
        }

        if(!OSMatch_Execute(lf->id,
                            strlen(lf->id),
                            currently_rule->id))
            return(NULL);
        #ifdef CDBLOOKUP

        #endif
    }


    /* Checking if any word to match exists */
    if(currently_rule->match)
    {
        if(!OSMatch_Execute(lf->log, lf->size, currently_rule->match))
            return(NULL);
    }	   	



    /* Checking if exist any regex for this rule */
    if(currently_rule->regex)
    {
        if(!OSRegex_Execute(lf->log, currently_rule->regex))
            return(NULL);
    }


    /* Checking for actions */
    if(currently_rule->action)
    {
        if(!lf->action)
            return(NULL);

        if(strcmp(currently_rule->action,lf->action) != 0)
            return(NULL);
    }


    /* Checking for the url */
    if(currently_rule->url)
    {
        if(!lf->url)
        {
            return(NULL);
        }

        if(!OSMatch_Execute(lf->url, strlen(lf->url), currently_rule->url))
        {
            return(NULL);
        }
        #ifdef CDBLOOKUP

        #endif
    }



    /* Getting tcp/ip packet information */
    if(currently_rule->alert_opts & DO_PACKETINFO)
    {
        /* Checking for the srcip */
        if(currently_rule->srcip)
        {
            if(!lf->srcip)
            {
                return(NULL);
            }

            if(!OS_IPFoundList(lf->srcip, currently_rule->srcip))
            {
                return(NULL);
            }
            #ifdef CDBLOOKUP

            #endif
        }

        /* Checking for the dstip */
        if(currently_rule->dstip)
        {
            if(!lf->dstip)
            {
                return(NULL);
            }

            if(!OS_IPFoundList(lf->dstip, currently_rule->dstip))
            {
                return(NULL);
            }
            #ifdef CDBLOOKUP

            #endif
        }

        if(currently_rule->srcport)
        {
            if(!lf->srcport)
            {
                return(NULL);
            }

            if(!OSMatch_Execute(lf->srcport,
                                strlen(lf->srcport),
                                currently_rule->srcport))
            {
                return(NULL);
            }
            #ifdef CDBLOOKUP

            #endif
        }
        if(currently_rule->dstport)
        {
            if(!lf->dstport)
            {
                return(NULL);
            }

            if(!OSMatch_Execute(lf->dstport,
                                strlen(lf->dstport),
                                currently_rule->dstport))
            {
                return(NULL);
            }
            #ifdef CDBLOOKUP

            #endif
        }
    } /* END PACKET_INFO */


    /* Extra information from event */
    if(currently_rule->alert_opts & DO_EXTRAINFO)
    {
        /* Checking compiled rule. */
        if(currently_rule->compiled_rule)
        {
            if(!currently_rule->compiled_rule(lf))
            {
                return(NULL);
            }
        }


        /* Checking if exist any user to match */
        if(currently_rule->user)
        {
            if(lf->dstuser)
            {
                if(!OSMatch_Execute(lf->dstuser,
                            strlen(lf->dstuser),
                            currently_rule->user))
                    return(NULL);
            }
            else if(lf->srcuser)
            {
                if(!OSMatch_Execute(lf->srcuser,
                            strlen(lf->srcuser),
                            currently_rule->user))
                    return(NULL);
            }
            else
            #ifdef CDBLOOKUP

            #endif
            {
                /* no user set */
                return(NULL);
            }
        }


        /* Checking if any rule related to the size exist */
        if(currently_rule->maxsize)
        {
            if(lf->size < currently_rule->maxsize)
                return(NULL);
        }


        /* Checking if we are in the right time */
        if(currently_rule->day_time)
        {
            if(!OS_IsonTime(lf->hour, currently_rule->day_time))
            {
                return(NULL);
            }
        }


        /* Checking week day */
        if(currently_rule->week_day)
        {
            if(!OS_IsonDay(__crt_wday, currently_rule->week_day))
            {
                return(NULL);
            }
        }


        /* Getting extra data */
        if(currently_rule->extra_data)
        {
            if(!lf->data)
                return(NULL);

            if(!OSMatch_Execute(lf->data,
                        strlen(lf->data),
                        currently_rule->extra_data))
                return(NULL);
        }


        /* Checking hostname */
        if(currently_rule->hostname)
        {
            if(!lf->hostname)
                return(NULL);

            if(!OSMatch_Execute(lf->hostname,
                        strlen(lf->hostname),
                        currently_rule->hostname))
                return(NULL);
        }


        /* Checking for status */
        if(currently_rule->status)
        {
            if(!lf->status)
                return(NULL);

            if(!OSMatch_Execute(lf->status,
                        strlen(lf->status),
                        currently_rule->status))
                return(NULL);
        }


        /* Do diff check. */
        if(currently_rule->context_opts & SAME_DODIFF)
        {
            if(!doDiff(currently_rule, lf))
            {
                return(NULL);
            }
        }
    }

    /* Checking for the FTS flag */
    if(currently_rule->alert_opts & DO_FTS)
    {
        /** FTS CHECKS **/
        if(lf->decoder_info->fts)
        {
            if(lf->decoder_info->fts & FTS_DONE)
            {
                /* We already did the fts in here. */
            }
            else if(!FTS(lf))
            {
                return(NULL);
            }
        }
        else
        {
            return(NULL);
        }
    }

    /* List lookups */
    if(currently_rule->lists != NULL)
    {
        ListRule *list_holder=currently_rule->lists;
        while(list_holder)
        {
            switch(list_holder->field)
            {
                case RULE_SRCIP:
                    if(!lf->srcip)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->srcip))
                        return(NULL);
                    break;
                case RULE_SRCPORT:
                    if(!lf->srcport)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->srcport))
                        return(NULL);
                    break;
                case RULE_DSTIP:
                    if(!lf->dstip)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->dstip))
                        return(NULL);
                    break;
                case RULE_DSTPORT:
                    if(!lf->dstport)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->dstport))
                        return(NULL);
                    break;
                case RULE_USER:
                    if(lf->srcuser)
                    {
                        if(!OS_DBSearch(list_holder,lf->srcuser))
                            return(NULL);
                    }
                    else if(lf->dstuser)
                    {
                        if(!OS_DBSearch(list_holder,lf->dstuser))
                            return(NULL);
                    }
                    else
                    {
                        return(NULL);
                    }
                    break;
                case RULE_URL:
                    if(!lf->url)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->url))
                        return(NULL);
                    break;
                case RULE_ID:
                    if(!lf->id)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->id))
                        return(NULL);
                    break;
                case RULE_HOSTNAME:
                    if(!lf->hostname)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->hostname))
                        return(NULL);
                    break;
                case RULE_PROGRAM_NAME:
                    if(!lf->program_name)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->program_name))
                        return(NULL);
                    break;
                case RULE_STATUS:
                    if(!lf->status)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->status))
                        return(NULL);
                    break;
                case RULE_ACTION:
                    if(!lf->action)
                        return(NULL);
                    if(!OS_DBSearch(list_holder,lf->action))
                        return(NULL);
                    break;
                default:
                    return(NULL);
            }

            list_holder = list_holder->next;
        }
    }


    /* If it is a context rule, search for it */
    if(currently_rule->context == 1)
    {
        if(!currently_rule->event_search(lf, currently_rule))
            return(NULL);
    }

    #ifdef TESTRULE
    if(full_output && !alert_only)
    print_out("       *Rule %d matched.", currently_rule->sigid);
    #endif


    /* Search for dependent rules */
    if(curr_node->child)
    {
        RuleNode *child_node = curr_node->child;
        RuleInfo *child_rule = NULL;

        #ifdef TESTRULE
        if(full_output && !alert_only)
        print_out("       *Trying child rules.");
        #endif

        while(child_node)
        {
            child_rule = OS_CheckIfRuleMatch(lf, child_node);
            if(child_rule != NULL)
            {
                return(child_rule);
            }

            child_node = child_node->next;
        }
    }


    /* If we are set to no alert, keep going */
    if(currently_rule->alert_opts & NO_ALERT)
    {
        return(NULL);
    }


    hourly_alerts++;
    currently_rule->firedtimes++;

    return(currently_rule);  /* Matched */
}


/** void LoopRule(RuleNode *curr_node);
 *  Update each rule and print it to the logs.
 */
void LoopRule(RuleNode *curr_node, FILE *flog)
{
    if(curr_node->ruleinfo->firedtimes)
    {
        fprintf(flog, "%d-%d-%d-%d\n",
                thishour,
                curr_node->ruleinfo->sigid,
                curr_node->ruleinfo->level,
                curr_node->ruleinfo->firedtimes);
        curr_node->ruleinfo->firedtimes = 0;
    }

    if(curr_node->child)
    {
        RuleNode *child_node = curr_node->child;

        while(child_node)
        {
            LoopRule(child_node, flog);
            child_node = child_node->next;
        }
    }
    return;
}


/** void DumpLogstats();
 *  Dump the hourly stats about each rule.
 */
void DumpLogstats()
{
    RuleNode *rulenode_pt;
    char logfile[OS_FLSIZE +1];
    FILE *flog;

    /* Opening log file */
    snprintf(logfile, OS_FLSIZE, "%s/%d/", STATSAVED, prev_year);
    if(IsDir(logfile) == -1)
        if(mkdir(logfile,0770) == -1)
        {
            merror(MKDIR_ERROR, ARGV0, logfile);
            return;
        }

    snprintf(logfile,OS_FLSIZE,"%s/%d/%s", STATSAVED, prev_year,prev_month);

    if(IsDir(logfile) == -1)
        if(mkdir(logfile,0770) == -1)
        {
            merror(MKDIR_ERROR,ARGV0,logfile);
            return;
        }


    /* Creating the logfile name */
    snprintf(logfile,OS_FLSIZE,"%s/%d/%s/ossec-%s-%02d.log",
            STATSAVED,
            prev_year,
            prev_month,
            "totals",
            today);

    flog = fopen(logfile, "a");
    if(!flog)
    {
        merror(FOPEN_ERROR, ARGV0, logfile);
        return;
    }

    rulenode_pt = OS_GetFirstRule();

    if(!rulenode_pt)
    {
        ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                ARGV0);
    }

    /* Looping on all the rules and printing the stats from them */
    do
    {
        LoopRule(rulenode_pt, flog);
    }while((rulenode_pt = rulenode_pt->next) != NULL);


    /* Print total for the hour */
    fprintf(flog, "%d--%d--%d--%d--%d\n\n",
                thishour,
                hourly_alerts, hourly_events, hourly_syscheck,hourly_firewall);
    hourly_alerts = 0;
    hourly_events = 0;
    hourly_syscheck = 0;
    hourly_firewall = 0;

    fclose(flog);
}



/* EOF */

