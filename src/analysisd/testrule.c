/* @(#) $Id: ./src/analysisd/testrule.c, 2012/07/23 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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


/** Local headers **/
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"

#include "eventinfo.h"
#include "analysisd.h"



/** Internal Functions **/
void OS_ReadMSG(int m_queue, char *ut_str);
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
int AddtoIGnore(Eventinfo *lf);
int IGnore(Eventinfo *lf);


/* For decoders */
void DecodeEvent(Eventinfo *lf);


/* For Decoders */
int ReadDecodeXML(char *file);
int SetDecodeXML();


void logtest_help(const char *prog)
{
    print_out(" ");
    print_out("%s %s - %s (%s)", __ossec_name, __version, __author, __contact);
    print_out("%s", __site);
    print_out(" ");
    print_out("  %s: -[Vatfdh] [-U ut_str] [-u user] [-g group] [-c config] [-D dir]", prog);
    print_out("    -V          Version and license message");
    print_out("    -a          Alerts output");
    print_out("    -t          Test configuration");
    print_out("    -v          Verbose (full) output/rule debugging");
    print_out("    -d          Execute in debug mode");
    print_out("    -h          This help message");
    print_out("    -U <rule:alert:decoder>   Unit test. Refer to contrib/ossec-testing/runtests.py");
    print_out("    -u <user>   Run as 'user'");
    print_out("    -g <group>  Run as 'group'");
    print_out("    -c <config> Read the 'config' file");
    print_out("    -D <dir>    Chroot to 'dir'");
    print_out(" ");
    exit(1);
}



/** int main(int argc, char **argv)
 */
int main(int argc, char **argv)
{
    int t_config = 0;
    int c = 0, m_queue = 0;
    char *ut_str = NULL;

    char *dir = DEFAULTDIR;
    // TODO: delete or implement
    char *user __attribute__((unused)) = USER;
    // TODO: delete or implement
    char *group __attribute__((unused)) = GROUPGLOBAL;

    char *cfg = DEFAULTCPATH;

    /* Setting the name */
    OS_SetName(ARGV0);

    thishour = 0;
    today = 0;
    prev_year = 0;
    full_output = 0;
    alert_only = 0;

    active_responses = NULL;
    memset(prev_month, '\0', 4);

    while((c = getopt(argc, argv, "VatvdhU:u:g:D:c:")) != -1){
        switch(c){
	    case 'V':
		print_version();
		break;
            case 't':
                t_config = 1;
                break;
            case 'h':
                logtest_help(ARGV0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'U':
                if(!optarg)
                    ErrorExit("%s: -U needs an argument",ARGV0);
                ut_str = optarg;
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
            case 'a':
                alert_only = 1;
                break;
            case 'v':
                full_output = 1;
                break;
            default:
                logtest_help(ARGV0);
                break;
        }

    }




    /* Reading configuration file */
    if(GlobalConf(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR,ARGV0, cfg);
    }

    debug1(READ_CONFIG, ARGV0);



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



    if(chdir(dir) != 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);


    /*
     * Anonymous Section: Load rules, decoders, and lists
     *
     * As lists require two pass loading of rules that make use of list lookups
     * are created with blank database structs, and need to be filled in after
     * completion of all rules and lists.
     */
    {
        { /* Lad decders */
            /* Initializing the decoders list */
            OS_CreateOSDecoderList();

            if(!Config.decoders)
            { /* Legacy loading */
                /* Reading decoders */
                if(!ReadDecodeXML("etc/decoder.xml"))
                {
                    ErrorExit(CONFIG_ERROR, ARGV0,  XML_DECODER);
                }

                /* Reading local ones. */
                c = ReadDecodeXML("etc/local_decoder.xml");
                if(!c)
                {
                    if((c != -2))
                        ErrorExit(CONFIG_ERROR, ARGV0,  XML_LDECODER);
                }
                else
                {
                    verbose("%s: INFO: Reading local decoder file.", ARGV0);
                }
            }
            else
            { /* New loaded based on file speified in ossec.conf */
                char **decodersfiles;
                decodersfiles = Config.decoders;
                while( decodersfiles && *decodersfiles)
                {

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
                    verbose("%s: INFO: Reading the lists file: '%s'", ARGV0, *listfiles);
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
                    debug1("%s: INFO: Reading rules file: '%s'", ARGV0, *rulesfiles);
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
        debug1("%s: INFO: Total rules enabled: '%d'", ARGV0, total_rules);
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


    if(t_config == 1)
    {
        exit(0);
    }


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());


    /* Going to main loop */
    OS_ReadMSG(m_queue, ut_str);


    exit(0);

}



/* OS_ReadMSG.
 * Main function. Receives the messages(events)
 * and analyze them all.
 */
void OS_ReadMSG(int m_queue, char *ut_str)
{
    int i;
    char msg[OS_MAXSTR +1];
    int exit_code = 0;
    char *ut_alertlevel = NULL;
    char *ut_rulelevel = NULL;
    char *ut_decoder_name = NULL;

    if(ut_str)
    {
        /* XXX Break apart string */
        ut_rulelevel = ut_str;
        ut_alertlevel =  strchr(ut_rulelevel, ':');
        if(!ut_alertlevel)
        {
            ErrorExit("%s: -U requires the matching format to be "
                      "\"<rule_id>:<alert_level>:<decoder_name>\"", ARGV0);
        }
        else
        {
            *ut_alertlevel = '\0';
            ut_alertlevel++;
        }
        ut_decoder_name = strchr(ut_alertlevel, ':');
        if(!ut_decoder_name)
        {
            ErrorExit("%s: -U requires the matching format to be "
                      "\"<rule_id>:<alert_level>:<decoder_name>\"", ARGV0);
        }
        else
        {
            *ut_decoder_name = '\0';
            ut_decoder_name++;
        }
    }

    RuleInfoDetail *last_info_detail;
    Eventinfo *lf;


    /* Null to global currently pointers */
    currently_rule = NULL;


    /* Creating the event list */
    OS_CreateEventList(Config.memorysize);


    /* Initiating the FTS list */
    if(!FTS_Init())
    {
        ErrorExit(FTS_LIST_ERROR, ARGV0);
    }


    __crt_ftell = 1;


    /* Getting currently time before starting */
    c_time = time(NULL);


    /* Doing some cleanup */
    memset(msg, '\0', OS_MAXSTR +1);


    if(!alert_only)
    print_out("%s: Type one log per line.\n", ARGV0);


    /* Daemon loop */
    while(1)
    {
        lf = (Eventinfo *)calloc(1,sizeof(Eventinfo));

        /* This shouldn't happen .. */
        if(lf == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }


        /* Fixing the msg. */
        snprintf(msg, 15, "1:stdin:");



        /* Receive message from queue */
        if(fgets(msg +8, OS_MAXSTR -8, stdin))
        {
            RuleNode *rulenode_pt;

            /* Getting the time we received the event */
            c_time = time(NULL);


            /* Removing new line. */
            if(msg[strlen(msg) -1] == '\n')
                msg[strlen(msg) -1] = '\0';


            /* Make sure we ignore blank lines. */
            if(strlen(msg) < 10)
            {
                continue;
            }


            if(!alert_only)print_out("\n");


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


            /***  Running decoders ***/

            /* Getting log size */
            lf->size = strlen(lf->log);


            /* Decoding event. */
            DecodeEvent(lf);


            /* Looping all the rules */
            rulenode_pt = OS_GetFirstRule();
            if(!rulenode_pt)
            {
                ErrorExit("%s: Rules in an inconsistent state. Exiting.",
                        ARGV0);
            }


            #ifdef TESTRULE
            if(full_output && !alert_only)
                print_out("\n**Rule debugging:");
            #endif


            do
            {
                if(lf->decoder_info->type == OSSEC_ALERT)
                {
                    if(!lf->generated_rule)
                    {
                        break;
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

                #ifdef TESTRULE
                if(!alert_only)
                {
                  char *(ruleinfodetail_text[])={"Text","Link","CVE","OSVDB","BUGTRACKID"};
                  print_out("\n**Phase 3: Completed filtering (rules).");
                  print_out("       Rule id: '%d'", currently_rule->sigid);
                  print_out("       Level: '%d'", currently_rule->level);
                  print_out("       Description: '%s'",currently_rule->comment);
                  for (last_info_detail = currently_rule->info_details; last_info_detail != NULL; last_info_detail = last_info_detail->next)
                  {
                      print_out("       Info - %s: '%s'", ruleinfodetail_text[last_info_detail->type], last_info_detail->data);
                  }
                }
                #endif



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
                    if(alert_only)
                    {
                        OS_LogOutput(lf);
                        __crt_ftell++;
                    }
                    else
                    {
                        print_out("**Alert to be generated.\n\n");
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

            if(ut_str)
            {
                /*setup exit code if we are doing unit testing*/
                char holder[1024];
                holder[1] = '\0';
                exit_code = 3;
                if(lf->decoder_info->name != NULL && strcasecmp(ut_decoder_name, lf->decoder_info->name) == 0)
                {
                    exit_code--;
                    snprintf(holder, 1023, "%d", currently_rule->sigid);
                    if(strcasecmp(ut_rulelevel, holder) == 0)
                    {
                        exit_code--;
                        snprintf(holder, 1023, "%d", currently_rule->level);
                        if(strcasecmp(ut_alertlevel, holder) == 0)
                        {
                            exit_code--;
                            printf("%d\n",exit_code);
                        }
                    }
                }
            }


            /* Only clear the memory if the eventinfo was not
             * added to the stateful memory
             * -- message is free inside clean event --
             */
            if(lf->generated_rule == NULL)
                Free_Eventinfo(lf);

        }
        else
        {
            exit(exit_code);
        }
    }
    exit(exit_code);
    return;
}



/* EOF */

