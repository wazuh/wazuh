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

#include "headers/defs.h"

#include "headers/mq_op.h"
#include "headers/sig_op.h"
#include "headers/file_op.h"
#include "headers/debug_op.h"
#include "headers/help.h"
#include "headers/privsep_op.h"

#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "os_maild/maild.h"
#include "os_execd/execd.h"

#include "os_regex/os_regex.h"
#include "os_net/os_net.h"

#include "error_messages/error_messages.h"

/* local headers */
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "eventinfo.h"
#include "analysisd.h"


short int dbg_flag=0;
short int chroot_flag=0;

/* Alert queues */
int mailq = 0;
int execq = 0;


/* For hourly stats */
int __crt_hour;
int __crt_wday;


/* Internal Functions */
void OS_ReadMSG(int m_queue);
int OS_CheckIfRuleMatch(Eventinfo *lf);


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
    int c=0,m_queue=0;
    char *dir=DEFAULTDIR;
    char *user=USER;
    char *group=GROUPGLOBAL;
    int uid=0,gid=0;

    char **rulesfiles;
    char *cfg=DEFAULTCPATH;

    while((c = getopt(argc, argv, "dhu:g:D:c:")) != -1){
        switch(c){
            case 'h':
                help();
                break;
            case 'd':
                dbg_flag++;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg=optarg;
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

        
    /* Setting the group */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* Chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    chroot_flag=1; /* Inside chroot now */


    /* Setting the user */ 
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);
    

    /* Reading decoders */
    ReadDecodeXML(XML_DECODER);


    /* Creating the rule list */
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

    debug1("%s: Started queue at %s",ARGV0,DEFAULTQUEUE);	

    /* Signal manipulation	*/
    StartSIG(ARGV0);

    /* Forking and going to the background */
    if(dbg_flag == 0)
    {               
        int pid=0;
        if((pid = fork()) < 0)
            ErrorExit(FORK_ERROR,ARGV0);
        else if(pid == 0)
        {     
            /* Creating the PID file */
            if(CreatePID(ARGV0, getpid()) < 0)
                ErrorExit(PID_ERROR,ARGV0);
        }             
        else                    
            exit(0);
    }

    /* Going to read the messages */	
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
    int today=0;
    int thishour=0;

    /* Null to global currently pointers */
    currently_lf = NULL;
    currently_rule = NULL;

    /* Starting the getloglocation */
    #ifdef DEBUG
    printf("%s: DEBUG: Starting the log process...\n",ARGV0);
    #endif


    /* Initiating the logs */
    OS_InitLog();

    /* Initiating the integrity database */
    SyscheckInit();
   
    
    /* Creating the event list */
    OS_CreateEventList(Config.memorysize);


    /* Starting the mail queue (if configured to */
    if(Config.mailnotify == 1)
        if((mailq = StartMQ(MAILQUEUE,WRITE)) < 0)
        {
            merror(MAILQ_ERROR,ARGV0,MAILQUEUE);
            Config.mailnotify=0;
        }

    /* Starting exec queue */
    if(Config.exec == 1)
    {
        if((execq = StartMQ(EXECQUEUE,WRITE)) < 0)
        {
            merror(EXECQ_ERROR,ARGV0,EXECQUEUE);
            Config.exec=0;   
        }
    }

    /* Getting currently time before starting */
    c_time = time(NULL);


    /* Starting the hourly/weekly stats */
    if(Start_Hour(&today,&thishour) < 0)
        Config.stats=0;


    #ifdef DEBUG
    verbose("%s: DEBUG: Started completed. Waiting for new messages..",ARGV0);
    #endif

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
        verbose("%s: DEBUG:  Waiting new message.\n",ARGV0);
        #endif
        
        /* Receive message from queue */
        if((msg = OS_RecvUnix(m_queue, OS_MAXSTR)) != NULL)
        {
            int chld_node_matched = 0;

            RuleNode *rulenode_pt;
                        
            /* Getting the time we received the event */
            c_time = time(NULL);


            /* Default values for the log info */
            Zero_Eventinfo(lf);


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


            /* Dont need to go further if syscheck message */
            if(lf->type == SYSCHECK)
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
            verbose("%s: DEBUG: Starting rule checks\n",ARGV0);
            #endif

            /* Currently lf always pointing to lf */
            currently_lf = lf;

            
            /* Looping all the rules */
            rulenode_pt = OS_GetFirstRule();
           
            if(!rulenode_pt) 
            {
                ErrorExit("%s: Rules in an inconsistent state. Exiting",ARGV0);
            }

            do
            {
                currently_rule = rulenode_pt->ruleinfo;
          
                if(!OS_CheckIfRuleMatch(lf)) /* 0 = didn't match */
                {
                    continue;
                }

                /* Checking any dependent rule */
                if(rulenode_pt->child)
                {
                    RuleNode *child_node = rulenode_pt->child;

                    #ifdef DEBUG
                    verbose("%s: DEBUG: Checking for the child rule",ARGV0);
                    #endif
                    
                    chld_node_matched = 0;

                    while(child_node)
                    {
                        currently_rule = child_node->ruleinfo;
                        if(OS_CheckIfRuleMatch(lf))
                        {
                            #ifdef DEBUG
                            verbose("%s: DEBUG: Found child",ARGV0);
                            #endif

                            chld_node_matched = 1;
                            break;
                        }
                        child_node = child_node->next;
                    }

                    /* If the child node didn't match */
                    if(chld_node_matched == 0)
                    {
                        currently_rule = rulenode_pt->ruleinfo;
                        
                        if(currently_rule->ignore_time)
                        {
                            currently_rule->time_ignored = lf->time;
                        }
                    }
                
                    else
                    {
                        /* If the children rule matched and has a ignore
                         * time set, ignore the parent rule also
                         */
                        if(currently_rule->ignore_time)
                        {
                            currently_rule->time_ignored = lf->time;
                            rulenode_pt->ruleinfo->time_ignored = lf->time; 
                        }
                    } 
                } 
                
                /* If no child rule */
                else
                {
                    if(currently_rule->ignore_time)
                    {
                        currently_rule->time_ignored = lf->time;
                    }
                }
                
                /* Rule fired (if reached here) */
                currently_rule->firedtimes++;


                /* If not alert set, keep going */
                if(currently_rule->noalert)
                    continue;
                
                /* Checking if rule is supposed to be ignored */
                if(currently_rule->time_ignored)
                {
                    if((lf->time - currently_rule->time_ignored) < 
                            currently_rule->ignore_time)
                        continue;
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
                printf("%s: DEBUG: rule %d triggered (level:%d)\n",ARGV0,
                        currently_rule->sigid,
                        currently_rule->level);
                #endif
            

                lf->comment = currently_rule->comment;

                
                /* Execute an action if specified */

                /* Level 0 rules are to be ignored */
                /* however, they will be kept on the memory */
                if(currently_rule->level == 0)
                {
                    OS_AddEvent(lf);
                    break;
                }

                /* Log the alert if configured to ... */
                if(currently_rule->logresponse == 1)
                {

                    #ifdef DEBUG
                    verbose("%s: DEBUG: Logging ...",ARGV0);
                    #endif

                    OS_Log(lf);
                }

                /* Send an email alert */
                if(currently_rule->mailresponse == 1)
                {
                    #ifdef DEBUG
                    verbose("%s: DEBUG: Mailling ... ", ARGV0);
                    #endif
                    
                    OS_Createmail(&mailq,lf);
                }


                /* Copy the strucuture to the state structure */
                OS_AddEvent(lf);
                
                /* Execute an external command */

                /*
                   if((rules.userresponse[i] == 1)&&
                   (rules.external[i] != NULL))
                   {
                   OS_Exec(&execq,&(Config.exec),i,&lf,NULL,rules);    
                   }
                   else if(Config.externcmdbylevel[rules.level[i]] != NULL)
                   {
                   OS_Exec(&execq,&(Config.exec),i,&lf,NULL);    
                   }
                 */
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
int OS_CheckIfRuleMatch(Eventinfo *lf)
{

    if(!OS_Match(lf->group,currently_rule->group)
            && !OS_Match("all",lf->group))
        return(0);


    /* Checking if any word to match exist */
    if(currently_rule->match)
    {
        if(!OS_Match(currently_rule->match,
                    lf->log))
            return(0);
    }	   	   

    
    /* Checking if exist any regex for this rule */
    if(currently_rule->regex)
    {
        if(!OS_Regex(currently_rule->regex,lf->log))
            return(0);
    }

    /* Checking if exist any regex for this rule */
    if(currently_rule->user)
    {
        if(lf->dstuser)
        {
            if(!OS_Match(currently_rule->user,lf->dstuser))
                return(0);
        }
        else if(lf->user)
        {
            if(!OS_Match(currently_rule->user,lf->user))
                return(0);
        }
        else
        {
            /* no user set */
            return(0);
        }
    }

    
    /* Checking if any rule related to the size exist */
    if(currently_rule->maxsize)
    {
        if(strlen(lf->log) < currently_rule->maxsize)
            return(0);
    }
   
   
     
    /* If it is a context rule, search for it */
    if(currently_rule->context == 1)
    {
        Eventinfo *found_lf;

        #ifdef DEBUG
        verbose("%s: DEBUG: Context rule. Checking last msgs",
                ARGV0);
        #endif

        found_lf = Search_LastEvents(lf);
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
            return(0);
        }

    }

    return(1);  /* Matched */
}

/* EOF */
