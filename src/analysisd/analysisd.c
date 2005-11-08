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


/* For hourly stats */
int __crt_hour;
int __crt_wday;


/* Internal Functions */
void OS_ReadMSG(int m_queue);
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node);


/** External functions prototypes (only called here) **/

/* From config .. */
int GlobalConf(char * cfgfile);
char **GetRulesFiles(char * cfg);


/* From rules */
void Rules_OP_CreateRules();
int Rules_OP_ReadRules(char * cfgfile);


/* From cleanmsg */
int OS_CleanMSG(char *msg, Eventinfo *lf);


/* from FTS */
int Snort_FTS(Eventinfo *lf);
int FTS(Eventinfo *lf);


/* From Decoder Plugins */
void ReadDecodeXML(char *file);


/* From syscheckd (integrity checking) */
void SyscheckInit();
void SyscheckUpdateDaily();


/* From stats */
int Start_Hour(int *today,int *thishour);
int Check_Hour(Eventinfo *lf);
void Update_Hour();


/* Main function v0.2: 2005/03/22 */
int main(int argc, char **argv)
{
    int c = 0, m_queue = 0;
    char *dir = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    int uid = 0,gid = 0;

    char **rulesfiles;
    char *cfg = DEFAULTCPATH;

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


    /* Getting the rules files */
    if(!(rulesfiles = GetRulesFiles(cfg)))
        ErrorExit(RULESLOAD_ERROR,ARGV0);

        
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

    
    
    /* Setting the group */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* Chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);


    nowChroot();


    /* Setting the user */ 
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);
    

    /* Reading decoders */
    ReadDecodeXML(XML_DECODER);


    
    /* Creating the rules list */
    Rules_OP_CreateRules();

    
    
    /* Reading the rules */
    {
        char **tmp_rules = rulesfiles;
        while(*rulesfiles)
        {
            if(Rules_OP_ReadRules(*rulesfiles) < 0)
                ErrorExit(RULES_ERROR,ARGV0);
                
            free(*rulesfiles);    
            rulesfiles++;    
        }

        free(tmp_rules);
    }


    /* Verbose message */
    debug1(PRIVSEP_MSG,ARGV0,dir,user);


    /* Setting the queue */
    if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
        ErrorExit(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);


    /* Signal manipulation	*/
    StartSIG(ARGV0);


    /* going on Daemon mode */
    nowDaemon();
    goDaemon();

    
    /* Creating the PID file */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


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

    /* Time structures */
    int today = 0;
    int thishour = 0;

    int mt_now = 0;
    
    /* Null to global currently pointers */
    currently_lf = NULL;
    currently_rule = NULL;

    /* Starting the getloglocation */
    debug1("%s: DEBUG: Starting the log process...\n",ARGV0);


    /* Initiating the logs */
    OS_InitLog();


    /* Initiating the integrity database */
    SyscheckInit();
   
    
    /* Creating the event list */
    OS_CreateEventList(Config.memorysize);


    /* Starting the mail queue (if configured to */
    if(Config.mailnotify == 1)
    {
        if((mailq = StartMQ(MAILQUEUE,WRITE)) < 0)
        {
            merror(MAILQ_ERROR,ARGV0,MAILQUEUE);
            Config.mailnotify = 0;
        }
    }


    /* Starting the active response queues */
    if(Config.ar == 1)
    {
        if(Config.remote_ar)
        {
            if((arq = StartMQ(ARQUEUE, WRITE)) < 0)
            {
                merror(ARQ_ERROR, ARGV0);
                Config.remote_ar = 0;
            }
        }
        if(Config.local_ar)
        {
            if((execdq = StartMQ(EXECQUEUE, WRITE)) < 0)
            {
                merror(ARQ_ERROR, ARGV0);
                Config.local_ar = 0;   
            }
        }

        if(!Config.local_ar && !Config.remote_ar)
        {
            Config.ar = 0;
        }
    }


    /* Getting currently time before starting */
    c_time = time(NULL);


    /* Starting the hourly/weekly stats */
    if(Start_Hour(&today,&thishour) < 0)
        Config.stats=0;


    debug1("%s: DEBUG: Startup completed. Waiting for new messages..",ARGV0);
    

    /* Daemon loop */
    while(1)
    {
        /* Msg to be received and the event info structure */
        Eventinfo *lf;
        char *msg;
        
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
        if((msg = OS_RecvUnix(m_queue, OS_MAXSTR)) != NULL)
        {
            RuleNode *rulenode_pt;
                        
            /* Getting the time we received the event */
            c_time = time(NULL);


            /* Default values for the log info */
            Zero_Eventinfo(lf);

            merror("msg received is: %s",msg);

            /* Clean the msg appropriately */
            if(OS_CleanMSG(msg,lf) < 0)
            {
                merror(IMSG_ERROR,ARGV0,msg);
                
                free(msg);
                
                Free_Eventinfo(lf);
                
                msg = NULL;
                continue;
            }

            /* Currently rule must be null in here */
            currently_rule = NULL;

            #ifdef DEBUG
            verbose("%s: DEBUG:  Received message: %s\n",ARGV0,lf->log);
            #endif


            /* Dont need to go further if syscheck/rootcheck message */
            if((lf->type == SYSCHECK) || (lf->type == ROOTCHECK))
            {
                /* if level != -1, syscheck event fired */
                if(lf->level > 0)
                {
                    OS_AddEvent(lf);
                }
                goto CLMEM;
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
                    lf->comment = NULL;
                }
            }


            /* Check if the date has changed */
            if(today != lf->day)
            {
                if(Config.stats)
                    Update_Hour();  /* Update the hour stats (done daily) */
                
                /* Syscheck Update */
                SyscheckUpdateDaily();    
                today = lf->day;
            }

            /* Update the hour */
            if(thishour != __crt_hour)
            {
                thishour = __crt_hour;
            }


            /* Checking if the message is duplicated */	
            if(LastMsg_Stats(lf->log) == 1)
                goto CLMEM;
            else
                LastMsg_Change(lf->log);


            /** FTS CHECKS **/

            /* FTS for Snort */	
            if((Config.fts != 0) && (lf->type == SNORT))
            {
                /* If FTS, alert on that */
                if(Snort_FTS(lf) == 1)
                {
                    lf->level = Config.fts;
                    
                    if(Config.logbylevel <= Config.fts)
                        OS_Log(lf);
                    if(Config.mailbylevel <= Config.fts)
                        OS_Createmail(&mailq,lf);
                    
                    lf->level = -1;
                    lf->comment = NULL;
                }

                /* dont need to process snort packet further */
                goto CLMEM;
            }
            
            
            /* FTS for others */
            else if((Config.fts != 0) && (FTS(lf) == 1))
            {
                lf->level = Config.fts;
                
                if(Config.logbylevel <= Config.fts)
                    OS_Log(lf);
                if(Config.mailbylevel <= Config.fts)
                    OS_Createmail(&mailq,lf);
                
                lf->level = -1;

                /* Clearing the comment */
                lf->comment = NULL;
            }


            #ifdef DEBUG
            debug2("%s: DEBUG: Starting rule checks\n",ARGV0);
            #endif

            /* Currently lf always pointing to lf */
            currently_lf = lf;

            
            /* Looping all the rules */
            rulenode_pt = OS_GetFirstRule();
           
            if(!rulenode_pt) 
            {
                ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                                                               ARGV0);
            }

            do
            {
                /* Checking each rule. */
                if((currently_rule = OS_CheckIfRuleMatch(lf, rulenode_pt)) 
                        == NULL)
                {
                    continue;
                }

                /* Checking ignore time */ 
                if(currently_rule->ignore_time && 
                        (currently_rule->time_ignored == 0))
                {
                    currently_rule->time_ignored = lf->time;
                    mt_now = 1;
                }
                
                /* Rule fired (if reached here) */
                currently_rule->firedtimes++;


                /* If not alert set, keep going */
                if(currently_rule->noalert)
                    continue;
                
                
                /* Checking if rule is supposed to be ignored */
                if(currently_rule->time_ignored)
                {
                    if(mt_now)
                        mt_now = 0;
                    else if((lf->time - currently_rule->time_ignored) < 
                            currently_rule->ignore_time)
                        break;
                    else
                        currently_rule->time_ignored = 0;
                }
                
                
                /* Copying the rule values to here */
                lf->level    = currently_rule->level;
                lf->sigid    = currently_rule->sigid;


                /* Copying the group */
                if(lf->group)
                    free(lf->group);
                    
                lf->group    = strdup(currently_rule->group);
                
                if(!lf->group)
                {
                    merror(MEM_ERROR,ARGV0);
                }
                 
                #ifdef DEBUG
                debug2("%s: DEBUG: rule %d triggered (level:%d)\n",ARGV0,
                        currently_rule->sigid,
                        currently_rule->level);
                #endif
            

                lf->comment = currently_rule->comment;

                
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
                if(currently_rule->logresponse == 1)
                {

                    #ifdef DEBUG
                    debug2("%s: DEBUG: Logging ...",ARGV0);
                    #endif

                    OS_Log(lf);
                }

                /* Send an email alert */
                if(currently_rule->mailresponse == 1)
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
                    active_response **rule_ar = currently_rule->ar;

                    merror("ar entering");
                    
                    while(*rule_ar)
                    {
                        do_ar = 1;
                        if((*rule_ar)->ar_cmd->expect & USERNAME)
                        {
                            merror("user -> %s", lf->user);
                            if(!lf->user)
                                do_ar = 0;
                        }
                        if((*rule_ar)->ar_cmd->expect & SRCIP)
                        {
                            merror("srcip -> %s", lf->srcip);
                            if(!lf->srcip)
                                do_ar = 0;
                        }

                        if(do_ar)
                        {
                            merror("exec");
                            OS_Exec(&execdq, &arq, lf, *rule_ar);
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
             */
            if(lf->level < 0)
                Free_Eventinfo(lf);

            /* msg is free inside clean event */
        }
    }
    return;
}


/* CheckIfRuleMatch v0.1
 * Will check if the currently_rule matches the event information
 */
RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node)
{
    RuleInfo *currently_rule = curr_node->ruleinfo;
    
    /* Can't be null */
    if(!currently_rule)
    {
        merror("%s: Inconsistent state. currently rule NULL", ARGV0);
        return(NULL);
    }
    
    /* Group checking */
    if(!OS_Match(lf->group,currently_rule->group)
            && !OS_Match("all",lf->group))
        return(NULL);


    /* Checking if any plugin pre-matched is here */
    if(currently_rule->plugin_decoded)
    {
        merror("decoded: %s",currently_rule->plugin_decoded);
        
        /* Must have the log tag decoded */
        if(!lf->log_tag)
            return(NULL);
            
        if(strcmp(currently_rule->plugin_decoded,
                  lf->log_tag) != 0)
            return(NULL);  
        merror("OK!");
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
        if(!OS_Regex(currently_rule->regex,lf->log))
            return(NULL);
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
        if(strlen(lf->log) < currently_rule->maxsize)
            return(NULL);
    }
   
   
     
    /* If it is a context rule, search for it */
    if(currently_rule->context == 1)
    {
        Eventinfo *found_lf;

        #ifdef DEBUG
        verbose("%s: DEBUG: Context rule. Checking last msgs",
                ARGV0);
        #endif

        found_lf = Search_LastEvents(lf, currently_rule);
        if(found_lf)
        {
            /* Found Event */
            #ifdef DEBUG
            verbose("%s: Previous event found", ARGV0);
            #endif
            
        }
        
        else
        {
            /* Didn't match... */
            return(NULL);
        }

    }

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
    
    return(currently_rule);  /* Matched */
}

/* EOF */
