/*   $OSSEC, analysisd.c, v0.4, 2005/09/08, Daniel B. Cid$   */

/* Copyright (C) 2003, 2004, 2005 Daniel B. Cid <dcid@ossec.net>
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
#include "os_maild/maild.h"
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



/* mail queue */
int mailq = 0;

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


/* For cleanmsg */
int OS_CleanMSG(char *msg, Eventinfo *lf);


/* for FTS */
int FTS_Init();
int FTS(Eventinfo *lf);


/* For decoders */
void DecodeEvent(Eventinfo *lf);
void DecodeSyscheck(Eventinfo *lf);
void DecodeRootcheck(Eventinfo *lf);
 

/* For Decoder Plugins */
void ReadDecodeXML(char *file);


/* For syscheckd (integrity checking) */
void SyscheckInit();


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
    int c = 0, m_queue = 0;
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
    prev_month[0] = '\0';
    prev_month[1] = '\0';
    prev_month[2] = '\0';
    prev_month[3] = '\0';
    hourly_alerts = 0;

    while((c = getopt(argc, argv, "dhu:g:D:c:")) != -1){
        switch(c){
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
            default:
                help();
                break;
        }

    }


    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    
    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);


    /* Reading configuration file */
    if(GlobalConf(cfg) < 0)
        ErrorExit(CONFIG_ERROR,ARGV0);


    /* Reading the active response config */
    AS_Init();

   
    if(AS_GetActiveResponseCommands(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0);
    }
    if(AS_GetActiveResponses(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0);
    }

    
    /* going on Daemon mode */
    nowDaemon();
    goDaemon();
    
    
    
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
        while(*rulesfiles)
        {
            verbose("%s: Reading rules file: '%s'", ARGV0, *rulesfiles);
            if(Rules_OP_ReadRules(*rulesfiles) < 0)
                ErrorExit(RULES_ERROR,ARGV0);
                
            free(*rulesfiles);    
            rulesfiles++;    
        }

        free(Config.includes);
        Config.includes = NULL;
    }


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
            verbose("%s: No IP in the white list for active reponse.");
    }
    else
    {
        if(Config.ar)
        {
            char **wl;
            int wlc = 0;
            wl = Config.white_list;
            while(*wl)
            {
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
    
    /* Null to global currently pointers */
    currently_rule = NULL;

    /* Initiating the logs */
    OS_InitLog();


    /* Initiating the integrity database */
    SyscheckInit();
   
    
    /* Creating the event list */
    OS_CreateEventList(Config.memorysize);


    /* Initiating the FTS list */
    if(!FTS_Init())
    {
        ErrorExit(FTS_LIST_ERROR, ARGV0);
    }
    

    /* Starting the mail queue (if configured to) */
    if(Config.mailnotify == 1)
    {
        if((mailq = StartMQ(MAILQUEUE,WRITE)) < 0)
        {
            merror(MAILQ_ERROR,ARGV0,MAILQUEUE);
            Config.mailnotify = 0;
        }
        else
        {
            verbose(CONN_TO, ARGV0, MAILQUEUE, "mail");
        }
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


    /* Doing some cleanup */
    memset(msg, '\0', OS_MAXSTR +1);
    
    /* Initializing the logs */
    {
        lf = (Eventinfo *)calloc(1,sizeof(Eventinfo));
        if(!lf)
            ErrorExit(MEM_ERROR, ARGV0);
        lf->year = prev_year;
        os_strdup(prev_month, lf->mon);
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
        /* Msg to be received and the event info structure */
        Eventinfo *lf;
        
        lf = (Eventinfo *)calloc(1,sizeof(Eventinfo));
        
        /* This shouldn't happen .. */
        if(lf == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }
    
        #ifdef DEBUG
        debug2("%s: DEBUG:  Waiting new message.\n",ARGV0);
        #endif
        
        
        /* Receive message from queue */
        if(OS_RecvUnix(m_queue, OS_MAXSTR, msg))
        {
            RuleNode *rulenode_pt;

            /* Getting the time we received the event */
            c_time = time(NULL);


            /* Default values for the log info */
            Zero_Eventinfo(lf);


            /* Clean the msg appropriately */
            if(OS_CleanMSG(msg, lf) < 0)
            {
                merror(IMSG_ERROR,ARGV0,msg);

                Free_Eventinfo(lf);

                continue;
            }


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
            }

            /* Check if the date has changed */
            if(today != lf->day)
            {
                if(Config.stats)
                    Update_Hour();  /* Update the hourly stats (done daily) */

                if(OS_GetLogLocation(lf) < 0)
                {
                    ErrorExit("%s: Error alocating log files", ARGV0);
                }

                today = lf->day;
                prev_month[0] = lf->mon[0];
                prev_month[1] = lf->mon[1];
                prev_month[2] = lf->mon[2];
                prev_year = lf->year;
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

            /* Run the Decoder plugins */
            else
            {
                DecodeEvent(lf);
            }
            

            /* Dont need to go further if syscheck/rootcheck message */
            if((lf->type == SYSCHECK) || (lf->type == ROOTCHECK))
            {
                /* if level != -1, syscheck/rootcheck event fired */
                if(lf->level > 0)
                {
                    OS_AddEvent(lf);
                }
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


            /* Stats checking */
            if(Config.stats)
            {
                if(Check_Hour(lf) == 1)
                {
                    lf->level = Config.stats;

                    /* alert for statistical analysis */
                    if(Config.logbylevel <= Config.stats)
                        OS_Log(lf);
                    if(Config.mailbylevel <= Config.stats)
                        OS_Createmail(&mailq, lf);

                    lf->level = -1;
                }
            }


            /* Checking if the message is duplicated */	
            if(LastMsg_Stats(lf->log) == 1)
                goto CLMEM;
            else
                LastMsg_Change(lf->log);


            /** FTS CHECKS **/
            if(!FTS(lf))
            {
                lf->fts = 0;
            }


            #ifdef DEBUG
            debug2("%s: DEBUG: Starting rule checks\n",ARGV0);
            #endif


            lf->size = strlen(lf->log);


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


                /* Checking ignore time */ 
                if(currently_rule->ignore_time)
                {
                    if(currently_rule->time_ignored == 0)
                    {
                        currently_rule->time_ignored = lf->time;
                    }
                    /* If the currently time - the time the rule was ignore
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


                /* Copying the rule values to here */
                lf->level    = currently_rule->level;
                lf->sigid    = currently_rule->sigid;


                /* Getting the group */
                lf->group    = currently_rule->group;

                lf->comment = currently_rule->comment;


                /* Setting the last events if specified */
                lf->lasts_lf = currently_rule->last_events;


                /* Execute an action if specified */

                /* Level 0 rules are to be ignored. 
                 * However, they will be kept in memory
                 * as fired. 
                 */
                if(currently_rule->level == 0)
                {
                    OS_AddEvent(lf);
                    break;
                }

                /* Log the alert if configured to ... */
                if(currently_rule->logalert == 1)
                {

#ifdef DEBUG
                    debug2("%s: DEBUG: Logging ...",ARGV0);
#endif

                    OS_Log(lf);
                }

                /* Send an email alert */
                if(currently_rule->emailalert == 1)
                {
#ifdef DEBUG
                    debug2("%s: DEBUG: Mailling ... ", ARGV0);
#endif

                    OS_Createmail(&mailq,lf);
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
                                    !OS_PRegex(lf->user, "^[a-zA-Z._0-9-]*$")) 
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

                /* Copy the strucuture to the state structure */
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
            if(lf->level < 0)
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
     * dstport
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
    if((currently_rule->fts) && (!lf->fts))
    {
        return(NULL);
    }

    
    /* Checking if any word to match exists */
    if(currently_rule->match)
    {
        if(!OS_Match(currently_rule->match,
                    lf->log))
            return(NULL);
    }	   	   

    
    /* Checking if exist any regex for this rule */
    if(currently_rule->regex)
    {
        if(!OSRegex_Execute(lf->log,currently_rule->regex))
            return(NULL);
    }
    
    
    /* Checking for the url */
    if(currently_rule->url)
    {
        if(!OSRegex_Execute(lf->url,currently_rule->url))
        {
            return(NULL);
        }
    }

    
    /* Checking for the id */
    if(currently_rule->id)
    {
        if(!OS_Match(currently_rule->id, lf->id))
        {
            return(NULL);
        }
    }
    

    
    /* Checking if exist any user to match */
    if(currently_rule->user)
    {
        if(lf->dstuser)
        {
            if(!OS_Match(currently_rule->user,lf->dstuser))
                return(NULL);
        }
        else if(lf->user)
        {
            if(!OS_Match(currently_rule->user,lf->user))
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
        if(!OS_IPFound(lf->srcip, currently_rule->srcip))
        {
            return(NULL);
        }
    }
    
    /* Checking for the dstip */
    if(currently_rule->dstip)
    {
        if(!OS_IPFound(lf->dstip, currently_rule->dstip))
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
    if(currently_rule->noalert)
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

    /* We need to have year and month set */
    if(prev_year == 0)
        return;


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
