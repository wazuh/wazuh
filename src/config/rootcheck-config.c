/*   $OSSEC, rootcheck-config.c, v0.1, 2005/09/30, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "rootcheck-config.h"


/* Read_Rootcheck: Reads the rootcheck config
 */
int Read_Rootcheck(XML_NODE node, void *configp, void *mailp) 
{
    int i = 0;
    
    rkconfig *rootcheck;
    
    /* XML Definitions */
    char *xml_rootkit_files = "rootkit_files";
    char *xml_rootkit_trojans = "rootkit_trojans";
    char *xml_winaudit = "windows_audit";
    char *xml_unixaudit = "system_audit";
    char *xml_winapps = "windows_apps";
    char *xml_winmalware = "windows_malware";
    char *xml_scanall = "scanall";
    char *xml_readall = "readall";
    char *xml_time = "frequency";
    char *xml_disabled = "disabled";
    char *xml_base_dir = "base_directory";
    char *xml_ignore = "ignore";
    char *xml_disable_check = "disable_check";

    debug2("Entering Read_Rootcheck()");

    rootcheck = (rkconfig *)configp;
    
    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }

        /* Getting frequency */
        else if(strcmp(node[i]->element,xml_time) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            rootcheck->time = atoi(node[i]->content);
        }
        /* getting scan all */
        else if(strcmp(node[i]->element,xml_scanall) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                rootcheck->scanall = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                rootcheck->scanall = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_disabled) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                rootcheck->disabled = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                rootcheck->disabled = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_readall) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                rootcheck->readall = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                rootcheck->readall = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_rootkit_files) == 0)
        {
            os_strdup(node[i]->content, rootcheck->rootkit_files);
        }
        else if(strcmp(node[i]->element,xml_rootkit_trojans) == 0)
        {
            os_strdup(node[i]->content, rootcheck->rootkit_trojans);
        }
        else if(strcmp(node[i]->element, xml_winaudit) == 0)
        {
            os_strdup(node[i]->content, rootcheck->winaudit);
        }
        else if(strcmp(node[i]->element, xml_unixaudit) == 0)
        {
            int j = 0;
            while(rootcheck->unixaudit && rootcheck->unixaudit[j])
                j++;
            
            os_realloc(rootcheck->unixaudit, sizeof(char *)*(j+2), 
                       rootcheck->unixaudit);
            rootcheck->unixaudit[j] = NULL;
            rootcheck->unixaudit[j + 1] = NULL;
                
            os_strdup(node[i]->content, rootcheck->unixaudit[j]);
        }
        else if(strcmp(node[i]->element, xml_ignore) == 0)
        {
            int j = 0;
            while(rootcheck->ignore && rootcheck->ignore[j])
                j++;
            
            os_realloc(rootcheck->ignore, sizeof(char *)*(j+2), 
                       rootcheck->ignore);
            rootcheck->ignore[j] = NULL;
            rootcheck->ignore[j + 1] = NULL;
                
            os_strdup(node[i]->content, rootcheck->ignore[j]);
        }
        else if(strcmp(node[i]->element, xml_winmalware) == 0)
        {
            os_strdup(node[i]->content, rootcheck->winmalware);
        }
        else if(strcmp(node[i]->element, xml_winapps) == 0)
        {
            os_strdup(node[i]->content, rootcheck->winapps);
        }
        else if(strcmp(node[i]->element, xml_base_dir) == 0)
        {
            os_strdup(node[i]->content, rootcheck->basedir);
        }
        else if(strcmp(node[i]->element, xml_disable_check) == 0)
        {
           char **disabled_checks;
           char *tmp_str;

           debug2("before OS_Strbreak. content = [%s]", node[i]->content);
           /* break the comma separated content into values */
           disabled_checks=OS_StrBreak(',', node[i]->content, 
                                       strlen(node[i]->content)+1);

           char *d;
           
           debug2("after OS_Strbreak");

           /* check values against allowed list */
           char *str_dev = "/dev";
           char *str_sys = "system";
           char *str_proc = "processes";
           char *str_allports = "allports";
           char *str_openports = "openports";
           char *str_interfaces = "interfaces";

           
           /* Doing it for each check */
           while(*disabled_checks)
           {
               int i = 0;
               char *tmp_dcheck;
       
               debug2("Staring while loop. disabled_check = [%s]", *disabled_checks);
               tmp_dcheck = *disabled_checks;
               debug2("Before Trim: tmp_dcheck = [%s]", tmp_dcheck);
       
               /* Removing spaces at the beginning */
               while(*tmp_dcheck == ' ')
               {
                   tmp_dcheck++;
               }
       
               /* Removing spaces, tab, \n and \r at the begining */
               tmp_str = tmp_dcheck;
               while (*tmp_str == ' '  || *tmp_str == '	' ||
                      *tmp_str == '\n' || *tmp_str == '\r' )
               {
                   tmp_str++;
               }

               tmp_dcheck = tmp_str;
               debug2("After Trimming spaces in beginning: tmp_dcheck = [%s]", tmp_dcheck);

               /* Trim at the end */
               while (*tmp_str != ' '  && *tmp_str != '	' && *tmp_str != '\0' &&
                      *tmp_str != '\n' && *tmp_str != '\r')
               {
                   debug2("tmpstr [%c]", *tmp_str);
                   tmp_str++;
               }
               /* At this point, tmp_str is either at the end of the string
                  or at the first space, tab, \n or \r in the string.
                  Terminate the string here, since space/tab is not allowed
                */
               *tmp_str = '\0';

               /* Now tmp_dcheck points to the first non-null value of the 
                  contents which has been trimmed at the beginning and end
                */

               debug2("After Trimming spaces at the end: tmp_dcheck = [%s]", tmp_dcheck);
       
               if (strcasecmp(tmp_dcheck, str_dev) == 0)
               {
                   debug2("if dev");
                   rootcheck->check_dev_disabled = TRUE;
               } 
               else if (strcasecmp(tmp_dcheck, str_sys) == 0)
               {
                   debug2("if sys");
                   rootcheck->check_sys_disabled = TRUE;
               } 
               else if (strcasecmp(tmp_dcheck, str_proc) == 0)
               {
                   debug2("if proc");
                   rootcheck->check_proc_disabled = TRUE;
               } 
               else if (strcasecmp(tmp_dcheck, str_allports) == 0)
               {
                   debug2("if all ports");
                   rootcheck->check_allports_disabled = TRUE;
               } 
               else if (strcasecmp(tmp_dcheck, str_openports) == 0)
               {
                   debug2("if open ports");
                   rootcheck->check_openports_disabled = TRUE;
               } 
               else if (strcasecmp(tmp_dcheck, str_interfaces) == 0)
               {
                   debug2("if interfaces");
                   rootcheck->check_intf_disabled = TRUE;
               } 
               else
               {
                   debug2("nothing matches - throw error");
                   /* raise error if unknown value */
                   merror(XML_VALUEERR, ARGV0, node[i]->element, tmp_dcheck);
                   return(OS_INVALID);
               }

               debug2("After if check loop: tmp_dcheck = [%s]", tmp_dcheck);

               /* Next entry */
               disabled_checks++;    
           }

           debug2("read rootkit check config: dev_disabled = %d", 
                  rootcheck->check_dev_disabled);
           debug2("read rootkit check config: sys_disabled = %d", 
                  rootcheck->check_sys_disabled);
           debug2("read rootkit check config: proc_disabled = %d", 
                  rootcheck->check_proc_disabled);
           debug2("read rootkit check config: allports_disabled = %d", 
                  rootcheck->check_allports_disabled);
           debug2("read rootkit check config: openports_disabled = %d", 
                  rootcheck->check_openports_disabled);
           debug2("read rootkit check config: interfaces_disabled = %d", 
                  rootcheck->check_intf_disabled);
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }
    return(0);
}

/* EOF */
