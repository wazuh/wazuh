/*   $OSSEC, config.c, v0.1, 2005/04/02, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle the configuration files
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "headers/defs.h"
#include "headers/os_err.h"

#include "headers/file_op.h"
#include "headers/config_op.h"
#include "headers/debug_op.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "analysisd.h"
#include "config.h"

#include "error_messages/error_messages.h"

extern short int dbg_flag;

#define GetS(x) (x+48)
/* GlobalConf vv0.2: 2005/03/03
 * v0.2: Changing to support the new OS_XML
 */
int GlobalConf(char * cfgfile)
{
    OS_XML xml;

    char *str=NULL;

    /* XML definitions */
    /* Global */
    char *(xml_global_mailnotify[])={xml_global, "mail-notify",NULL};
    char *(xml_global_logall[])={xml_global,"logall",NULL};
    char *(xml_global_fts[])={xml_global,"fts",NULL};
    char *(xml_global_integrity[])={xml_global,"integrity_checking",NULL};
    char *(xml_global_stats[])={xml_global,"stats",NULL};
    char *(xml_global_memorysize[])={xml_global,"memory_size",NULL};
    char *(xml_global_keeplogdate[])={xml_global,"keep_log_date",NULL};
    char *(xml_global_accuracy[])={xml_global,"only_accurates",NULL};
    char *(xml_global_syscheck_ignore[])={xml_global,"syscheck_ignore",NULL};
    char *(xml_global_syscheck_threshold[])={xml_global,"syscheck_threshold",NULL};

    /* From Response */	
    char *(xml_response_mail[])={xml_response,"mail-notification",NULL};
    char *(xml_response_log[])={xml_response,"log",NULL};
    char *(xml_response_extern[])={xml_response,"extern",NULL};

    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror("config_op: XML Error: %s",xml.err);
        return(OS_INVALID);
    }

    /* Default values */
    Config.logall = 0;
    Config.fts = 4;
    Config.stats = 4;
    Config.integrity = 4;
    Config.memorysize = 1024;
    Config.mailnotify = 0;
    Config.accuracy = 0;
    Config.keeplogdate = 0;
    Config.exec = 0;
    Config.syscheck_threshold = 3;

    Config.syscheck_ignore = NULL;
    
    /* Default actions -- only log above level 3 */
    Config.mailbylevel = 99;
    Config.logbylevel  = 1;
    Config.externbylevel = 0;

    
    /* Checking if the e-mail notification is enable */
    if(OS_ElementExist(&xml,xml_global_mailnotify))
    {
        str = OS_GetOneContentforElement(&xml, xml_global_mailnotify);
        if(str != NULL)
        {
            if(str[0] == 'y')
                Config.mailnotify=1;
            free(str);
            str=NULL;
        }
    }

    /* getting the information about logging all */
    str=OS_GetOneContentforElement(&xml, xml_global_logall);
    if(str != NULL)
    {
        if(str[0] == 'y')
            Config.logall=1;
        free(str);
        str=NULL;
    }

    /* getting the information about the fts */
    str=OS_GetOneContentforElement(&xml, xml_global_fts);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid level \"%s\" for the FTS (must be int).",
                    str);
        else
            Config.fts=atoi(str);
        free(str);
        str=NULL;
    }
   
    /* Getting the information for the integrity checking alerting */
    str = OS_GetOneContentforElement(&xml, xml_global_integrity);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid alert level '%s' for the integrity "
                    "checking (must be int).", str);
        else
            Config.integrity = atoi(str); 

        free(str);
        str = NULL;
    }
    /* Getting the syscheck threshold */
    str = OS_GetOneContentforElement(&xml, xml_global_syscheck_threshold);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid syscheck threshold value. Must be integer");
        else
            Config.syscheck_threshold = atoi(str);
            
        free(str);
        str = NULL;        
    }
     
    /* Getting the syscheck ignore */
    str = OS_GetOneContentforElement(&xml, xml_global_syscheck_ignore);
    if(str != NULL)
    {
        Config.syscheck_ignore = OS_StrBreak(',', str , 32); /* max of 32 */
        if(Config.syscheck_ignore == NULL)
        {
            merror(MEM_ERROR,ARGV0);
        }
        
        free(str);
        str = NULL;
    }
     
    /* getting the information about the stats */
    str=OS_GetOneContentforElement(&xml, xml_global_stats);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid level \"%s\" for the stats (must be int).",
                    str);
        else
            Config.stats=atoi(str);
        free(str);
        str=NULL;
    }

    /* getting the information about the memory size */
    str=OS_GetOneContentforElement(&xml, xml_global_memorysize);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid value \"%s\" for the memory size (must be int).",
                    str);
        else
            Config.memorysize=atoi(str);
        free(str);
        str=NULL;
    }

    /* Getting the information about if we should use the
     * date provided from the logs
     */
    str=OS_GetOneContentforElement(&xml, xml_global_keeplogdate);
    if(str != NULL)
    {
        if(str[0] == 'y')
            Config.keeplogdate=1;
        free(str);
        str=NULL;
    }

    /* If we should use non accurate rules
     */
    str=OS_GetOneContentforElement(&xml, xml_global_accuracy);
    if(str != NULL)
    {
        if(str[0] == 'y')
            Config.accuracy=1;
        free(str);
        str=NULL;
    }
    
    /**  Getting specific responses per alert level **/
    /* Mail response */
    str = OS_GetOneContentforElement(&xml, xml_response_mail);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid level \"%s\" for the mail response (must be int).",
                    str);
        else
            Config.mailbylevel = atoi(str);
        free(str);
        str=NULL;
    }
    
    /* logging */
    str = OS_GetOneContentforElement(&xml, xml_response_log);
    if(str != NULL)
    {
        if(!OS_StrIsNum(str))
            merror("Invalid level \"%s\" for logging (must be int).",
                    str);
        else
            Config.logbylevel = atoi(str);
        free(str);
        str=NULL;
    }
     
    /* external command execution */
    str=OS_GetOneContentforElement(&xml, xml_response_extern);
    if(str != NULL)
    {
        if(OS_StrIsNum(str))
            merror("Invalid level \"%s\" for the external command "
                   "execuation  (must be int).", str);
        else
            Config.externbylevel=atoi(str);
        free(str);
        str=NULL;
    }
     

    OS_ClearXML(&xml);	
    return(0);
}



/* GetRulesFiles, v0.2, 2005/03/03
 * v0.2: Changed for the new OS_XML
 */
char **GetRulesFiles(char * cfg)
{
    char **files;
    
    OS_XML xml;

    /* XML Definition */
    char *(xml_rules_include[])={xml_rules, "include",NULL};

    if(OS_ReadXML(cfg,&xml) < 0)
    {
        merror("config_op: XML Error: %s",xml.err);
        return(NULL);
    }


    if(!OS_ElementExist(&xml, xml_rules_include))
    {
        merror("config_op: No rules file specified");
        return(NULL);
    }

    files = OS_GetElementContent(&xml, xml_rules_include);
    
    if(files == NULL)
    {
        merror("config_op: Error getting the rules files");
    }
    
    OS_ClearXML(&xml);
    
    return(files);
}


/* EOF */
