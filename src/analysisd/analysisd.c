/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.4(2005/09/08): Multiple additions.
 * v0.1:
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef ARGV0
   #define ARGV0 "ossec-analysisd"
#endif

#include "shared.h"

#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "os_execd/execd.h"

#include "os_regex/os_regex.h"
#include "os_net/os_net.h"


/* local headers */
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "eventinfo.h"
#include "analysisd.h"



/* execd queue */
int execdq = 0;

/* active response queue */
int arq = 0;


/* Internal Functions */
void OS_ReadMSG(int m_queue);
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node);


/** External functions prototypes (only called here) **/

/* For config  */
int GlobalConf(char * cfgfile);


/* For rules */
void Rules_OP_CreateRules();
int Rules_OP_ReadRules(char * cfgfile);
int _setlevels(RuleNode *node, int nnode);


/* For cleanmsg */
int OS_CleanMSG(char *msg, Eventinfo *lf);


/* for FTS */
int FTS_Init();
int FTS(Eventinfo *lf);
int AddtoIGnore(Eventinfo *lf);
int IGnore(Eventinfo *lf);


/* For decoders */
void DecodeEvent(Eventinfo *lf);
void DecodeSyscheck(Eventinfo *lf);
void DecodeRootcheck(Eventinfo *lf);
void DecodeHostinfo(Eventinfo *lf);
 

/* For Decoder Plugins */
void ReadDecodeXML(char *file);


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


/* Main function v0.2: 2005/03/22 */
int main(int argc, char **argv)
{
    int c = 0, m_queue = 0, test_config = 0;
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

    while((c = getopt(argc, argv, "Vtdhu:g:D:c:")) != -1){
        switch(c){
	    case 'V':
		print_version();
		break;
            case 'h':
                help();
                break;
            case 'd':
                nowDebug();
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
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;    
                break;
            default:
                help();
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
    AS_Init();
    debug1(ASINIT, ARGV0);
    
    
    /* Reading configuration file */
    if(GlobalConf(cfg) < 0)
        ErrorExit(CONFIG_ERROR,ARGV0);
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
    if(!test_config)
    {
        nowDaemon();
        goDaemon();
    }
    
    
    
    /* Setting the group */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* Chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);


    nowChroot();
    
    

    /* Reading decoders */
    ReadDecodeXML(XML_DECODER);

    
    /* Creating the rules list */
    Rules_OP_CreateRules();

   
    /* Reading the rules */
    {
        char **rulesfiles;
        rulesfiles = Config.includes;
        while(rulesfiles && *rulesfiles)
        {
            if(!test_config)
                verbose("%s: Reading rules file: '%s'", ARGV0, *rulesfiles);
            if(Rules_OP_ReadRules(*rulesfiles) < 0)
                ErrorExit(RULES_ERROR, ARGV0, *rulesfiles);
                
            free(*rulesfiles);    
            rulesfiles++;    
        }

        free(Config.includes);
        Config.includes = NULL;
    }
    
    
    /* Fixing the levels/accuracy */
    {
        int total_rules;
        RuleNode *tmp_node = OS_GetFirstRule();

        total_rules = _setlevels(tmp_node, 0);
        if(!test_config)
            verbose("%s: Total rules enabled: '%d'", ARGV0, total_rules);    
    }
   
   
    /* Ignored files on syscheck */
    {
        char **files;
        files = Config.syscheck_ignore;
        while(files && *files)
        {
            if(!test_config)
                verbose("%s: Ignoring file: '%s'", ARGV0, *files);
            files++;    
        }
    }


    /* Success on the configuration test */
    if(test_config)
        exit(0);

        
    /* Verbose message */
    debug1(PRIVSEP_MSG,ARGV0,dir,user);


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
        ErrorExit(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);


    /* White list */
    if(Config.white_list == NULL)
    {
        if(Config.ar)
            verbose("%s: No IP in the white list for active reponse.", ARGV0);
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
                verbose("%s: White listing IP: '%s'",ARGV0, (*wl)->ip);
                wl++;wlc++;
            }
            verbose("%s: %d IPs in the white list for active response.",
                    ARGV0, wlc);
        }
    }

   
    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());

    
    /* Going to main loop */	
    OS_ReadMSG(m_queue);


    exit(0);
    
}



/* OS_ReadMSG: v0.2: 2005/03/22
 * Receive the message from the queue and
 * forward to the necessary plugins/actions 
 */
void OS_ReadMSG(int m_queue)
{
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


    /* Getting currently time before starting */
    c_time = time(NULL);


    /* Starting the hourly/weekly stats */
    if(Start_Hour() < 0)
        Config.stats = 0;
    else
    {
        /* Initializing stats rules */
        stats_rule = zerorulemember(
                STATS_PLUGIN,
                Config.stats,
                0,0,0,0,0);

        if(!stats_rule)
        {
            ErrorExit(MEM_ERROR, ARGV0);
        }
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
            ErrorExit("%s: Error alocating log files", ARGV0);
        }

        Free_Eventinfo(lf);
    }
    
    
    debug1("%s: DEBUG: Startup completed. Waiting for new messages..",ARGV0);
    

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
        if(OS_RecvUnix(m_queue, OS_MAXSTR, msg))
        {
            RuleNode *rulenode_pt;

            /* Getting the time we received the event */
            c_time = time(NULL);


            /* Default values for the log info */
            Zero_Eventinfo(lf);


            /* Message before extracting header */
            DEBUG_MSG("%s: DEBUG: Received msg: %s ", ARGV0, msg);

            
            /* Clean the msg appropriately */
            if(OS_CleanMSG(msg, lf) < 0)
            {
                merror(IMSG_ERROR,ARGV0,msg);

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
                        ErrorExit("%s: Error alocating log files", ARGV0);
                    }

                    today = lf->day;
                    strncpy(prev_month, lf->mon, 3);
                    prev_year = lf->year;
                }
            }


            /***  Running plugins/decoders ***/

            /* Integrity check from syscheck */
            if(msg[0] == SYSCHECK_MQ)
            {
                DecodeSyscheck(lf);
            }

            /* Rootcheck decoding */
            else if(msg[0] == ROOTCHECK_MQ)
            {
                DecodeRootcheck(lf);
            }

            /* Host information special decoder */
            else if(msg[0] == HOSTINFO_MQ)
            {
                DecodeHostinfo(lf);
            }

            /* Run the Decoder plugins */
            else
            {
                /* Getting log size */
                lf->size = strlen(lf->log);

                DecodeEvent(lf);
            }
            

            /* Dont need to go further if syscheck/rootcheck message */
            if((lf->type == SYSCHECK) || (lf->type == ROOTCHECK))
            {
                /* We don't process syscheck/rootcheck events
                 * any further.
                 */
                goto CLMEM;
            }


            /* Firewall event */
            else if(lf->type == FIREWALL)
            {
                /* If we could not get any information from
                 * the log, just ignore it
                 */
                if(!FW_Log(lf))
                {
                    goto CLMEM;
                }
            }


            /* We only check if the last message is
             * duplicated on syslog
             */
            else if(lf->type == SYSLOG)
            {
                /* Checking if the message is duplicated */
                if(LastMsg_Stats(lf->log) == 1)
                    goto CLMEM;
                else
                    LastMsg_Change(lf->log);
            }


            /* Stats checking */
            if(Config.stats)
            {
                if(Check_Hour(lf) == 1)
                {
                    lf->generated_rule = stats_rule;
                    lf->generated_rule->comment = __stats_comment;

                    /* alert for statistical analysis */
                    if(stats_rule->alert_opts & DO_LOGALERT)
                        OS_Log(lf);

                    lf->generated_rule = NULL;
                }
            }


            /** FTS CHECKS **/
            if(lf->fts)
            {
                if(!FTS(lf))
                {
                    lf->fts = 0;
                }
            }


            /* Checking the rules */
            DEBUG_MSG("%s: DEBUG: Checking the rules - %d ", ARGV0, lf->type);

            
            /* Looping all the rules */
            rulenode_pt = OS_GetFirstRule();
            if(!rulenode_pt) 
            {
                ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                        ARGV0);
            }

            do
            {
                /* The categories must match */
                if(rulenode_pt->ruleinfo->category != lf->type)
                {
                    continue;
                }

                /* Checking each rule. */
                if((currently_rule = OS_CheckIfRuleMatch(lf, rulenode_pt)) 
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
                        currently_rule->time_ignored = 0;
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
                    OS_Log(lf);
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
                            if(!lf->user)
                                do_ar = 0;
                        }
                        if((*rule_ar)->ar_cmd->expect & SRCIP)
                        {
                            if(!lf->srcip)
                                do_ar = 0;
                        }

                        if(do_ar)
                        {
                            /* Verifying the IP and username */
                            if((lf->srcip)&&
                                    !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$"))
                            {
                                merror(CRAFTED_IP, ARGV0, lf->srcip);
                                break;
                            }
                            else if((lf->user)&&
                                    !OS_PRegex(lf->user, "^[a-zA-Z._0-9@-]*$")) 
                            {
                                merror(CRAFTED_USER, ARGV0, lf->user);
                                break;
                            }
                            else
                            {
                                OS_Exec(&execdq, &arq, lf, *rule_ar);
                            }
                        }
                        rule_ar++;
                    }
                }

                /* Copy the strucuture to the state memory */
                if(currently_rule->prev_matched)
                {
                    if(!OSList_AddData(currently_rule->prev_matched, lf))
                    {
                        merror("%s: Unable to add data to sig list.", ARGV0);
                    }
                    else
                    {
                        lf->node_to_delete = 
                            currently_rule->prev_matched->last_node;
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
    }
    return;
}


/* CheckIfRuleMatch v0.1
 * Will check if the currently_rule matches the event information
 */
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node)
{
    /* We must check for a decoded,
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
     */
    RuleInfo *currently_rule = curr_node->ruleinfo;
   
    
    /* Can't be null */
    if(!currently_rule)
    {
        merror("%s: Inconsistent state. currently rule NULL", ARGV0);
        return(NULL);
    }
   
     
    /* Checking if any plugin pre-matched here */
    if(currently_rule->plugin_decoded)
    {
        /* Must have the log tag decoded */
        if(!lf->log_tag)
            return(NULL);
            
        if(strcmp(currently_rule->plugin_decoded,
                  lf->log_tag) != 0)
            return(NULL);  
    }
   
    
    /* Checking for th FTS flag */
    if((currently_rule->alert_opts & DO_FTS) && (!lf->fts))
    {
        return(NULL);
    }

    
    /* Checking if any word to match exists */
    if(currently_rule->match)
    {
        if(!OSMatch_Execute(lf->log,lf->size,currently_rule->match))
            return(NULL);
    }	   	   

    
    /* Checking if exist any regex for this rule */
    if(currently_rule->regex)
    {
        if(!OSRegex_Execute(lf->log,currently_rule->regex))
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
        else if(lf->user)
        {
            if(!OSMatch_Execute(lf->user,
                                strlen(lf->user),
                                currently_rule->user))
                return(NULL);
        }
        else
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
   
    /* Checking for the srcip */
    if(currently_rule->srcip)
    {
        if(!lf->srcip)
        {
            return(NULL);
        }
        
        if(!OS_IPFound(lf->srcip, currently_rule->srcip))
        {
            return(NULL);
        }
    }
    
    /* Checking for the dstip */
    if(currently_rule->dstip)
    {
        if(!lf->dstip)
        {
            return(NULL);
        }
        
        if(!OS_IPFound(lf->dstip, currently_rule->dstip))
        {
            return(NULL);
        }
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
        
    /* If it is a context rule, search for it */
    if(currently_rule->context == 1)
    {
        if(!Search_LastEvents(lf, currently_rule))
        {
            return(NULL);
        }
    }


    /* Incrementing hourly fired times */
    currently_rule->firedtimes++;


    /* Search for dependent rules */
    if(curr_node->child)
    {
        RuleNode *child_node = curr_node->child;
        RuleInfo *child_rule = NULL;
        
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
    return(currently_rule);  /* Matched */
}


/** void LoopRule(RuleNode *curr_node);
 *  Update each rule and print it to the logs.
 */
void LoopRule(RuleNode *curr_node, FILE *flog)
{
    if(curr_node->ruleinfo->firedtimes)
    {
        fprintf(flog, "%d-%d-%d\n", 
                thishour, 
                curr_node->ruleinfo->sigid,
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
    fprintf(flog, "Alerts for:%d:%d\n\n",
                thishour,
                hourly_alerts);
    hourly_alerts = 0;
   
    fclose(flog);
}



/* EOF */
