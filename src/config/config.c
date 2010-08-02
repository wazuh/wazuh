/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Unified function to read the config.
 *
 */


#include "shared.h"
#include "os_xml/os_xml.h"
#include "config.h"


/* Read the main elements of the configuration.
 */
int read_main_elements(OS_XML xml, int modules, 
                                   XML_NODE node, 
                                   void *d1, 
                                   void *d2)
{
    int i = 0;
    char *osglobal = "global";
    char *osrules = "rules";
    char *ossyscheck = "syscheck";
    char *osrootcheck = "rootcheck";
    char *osalerts = "alerts";
    char *osemailalerts = "email_alerts";
    char *osdbd = "database_output";
    char *oscsyslogd = "syslog_output";
    char *oscagentless = "agentless";
    char *oslocalfile = "localfile";
    char *osremote = "remote";
    char *osclient = "client";
    char *oscommand = "command";
    char *osreports = "reports";
    char *osactive_response = "active-response";

    
    while(node[i])
    {
        XML_NODE chld_node = NULL;
        
        chld_node = OS_GetElementsbyNode(&xml,node[i]);

        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!chld_node)
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osglobal) == 0)
        {
            if(((modules & CGLOBAL) || (modules & CMAIL)) 
                && (Read_Global(chld_node, d1, d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osemailalerts) == 0)
        {
            if((modules & CMAIL) && (Read_EmailAlerts(chld_node, d1, d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osdbd) == 0)
        {
            if((modules & CDBD) && (Read_DB(chld_node, d1, d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, oscsyslogd) == 0)
        {
            if((modules & CSYSLOGD) && (Read_CSyslog(chld_node, d1, d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, oscagentless) == 0)
        {
            if((modules & CAGENTLESS) && (Read_CAgentless(chld_node, d1, d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osrules) == 0)
        {
            if((modules & CRULES) && (Read_Rules(chld_node, d1, d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, ossyscheck) == 0)
        {
            if((modules & CSYSCHECK) && (Read_Syscheck(chld_node, d1,d2) < 0))
                return(OS_INVALID);
            if((modules & CGLOBAL) && (Read_GlobalSK(chld_node, d1, d2) < 0))
                return(OS_INVALID);    
        }
        else if(strcmp(node[i]->element, osrootcheck) == 0)
        {
            if((modules & CROOTCHECK) && (Read_Rootcheck(chld_node, d1,d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osalerts) == 0)
        {
            if((modules & CALERTS) && (Read_Alerts(chld_node, d1,d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, oslocalfile) == 0)
        {
            if((modules & CLOCALFILE) && (Read_Localfile(chld_node, d1,d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osremote) == 0)
        {
            if((modules & CREMOTE) && (Read_Remote(chld_node, d1,d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osclient) == 0)
        {
            if((modules & CCLIENT) && (Read_Client(chld_node, d1,d2) < 0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, oscommand) == 0)
        {
            if((modules & CAR)&&(ReadActiveCommands(chld_node, d1, d2)<0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osactive_response) == 0)
        {
            if((modules & CAR)&&(ReadActiveResponses(chld_node, d1, d2)<0))
                return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, osreports) == 0)
        {
            if((modules & CREPORTS)&&(Read_CReports(chld_node, d1, d2)<0))
                return(OS_INVALID);
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        
        //printf("before\n");
        OS_ClearNode(chld_node);
        //printf("after\n");
        i++;
    }

    return(0);
}


/* ReadConfig(int modules, char *cfgfile)
 * Read the config files
 */
int ReadConfig(int modules, char *cfgfile, void *d1, void *d2) 
{
    int i;
    OS_XML xml;
    XML_NODE node;


    /** XML definitions **/
    /* Global */
    char *xml_start_ossec = "ossec_config";
    char *xml_start_agent = "agent_config";

    char *xml_agent_name = "name";
    char *xml_agent_os = "os";
    char *xml_agent_overwrite = "overwrite";
    

    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        if(modules & CAGENT_CONFIG)
        {
            #ifndef CLIENT
            merror(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
            #endif
        }
        else
        {
            merror(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
        }
        return(OS_INVALID);
    }
    

    node = OS_GetElementsbyNode(&xml, NULL);
    if(!node)
    {
        return(0);
    }


    /* Reading the main configuration */
    i = 0;
    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!(modules & CAGENT_CONFIG) &&
                (strcmp(node[i]->element, xml_start_ossec) == 0))
        {
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml,node[i]);

            /* Main element does not need to have any child */
            if(chld_node)
            {
                if(read_main_elements(xml, modules, chld_node, d1, d2) < 0)
                {
                    merror(CONFIG_ERROR, ARGV0, cfgfile);
                    return(OS_INVALID);
                }

                OS_ClearNode(chld_node);    
            }
        }
        else if((modules & CAGENT_CONFIG) &&
                (strcmp(node[i]->element, xml_start_agent) == 0))
        {
            int passed_agent_test = 1;
            int attrs = 0;
            XML_NODE chld_node = NULL;
            chld_node = OS_GetElementsbyNode(&xml,node[i]);


            /* Checking if this is specific to any agent. */
            if(node[i]->attributes && node[i]->values)
            {    
                while(node[i]->attributes[attrs] && node[i]->values[attrs])
                {
                    if(strcmp(xml_agent_name, node[i]->attributes[attrs]) == 0)
                    {
                        #ifdef CLIENT
                        char *agentname = os_read_agent_name();

                        if(!agentname)
                        {
                            passed_agent_test = 0;
                        }
                        else
                        {
                            if(!OS_Match2(node[i]->values[attrs], agentname))
                            {
                                passed_agent_test = 0;
                            }
                            free(agentname);
                        }
                        #endif
                    }
                    else if(strcmp(xml_agent_os, node[i]->attributes[attrs]) == 0)
                    {
                        #ifdef CLIENT
                        char *agentos = getuname();

                        if(agentos)
                        {
                            if(!OS_Match2(node[i]->values[attrs], agentos))
                            {
                                passed_agent_test = 0;
                            }
                            free(agentos);
                        }
                        else
                        {
                            passed_agent_test = 0;
                            merror("%s: ERROR: Unable to retrieve uname.", ARGV0);
                        }
                        #endif
                    }
                    else if(strcmp(xml_agent_overwrite, node[i]->attributes[attrs]) == 0)
                    {
                    }
                    else
                    {
                        merror(XML_INVATTR, ARGV0, node[i]->attributes[attrs],
                                cfgfile);
                    }
                    attrs++;
                }
            }

            
            /* Main element does not need to have any child */
            if(chld_node)
            {
                if(passed_agent_test && read_main_elements(xml, modules, chld_node, d1, d2) < 0)
                {
                    merror(CONFIG_ERROR, ARGV0, cfgfile);
                    return(OS_INVALID);
                }

                OS_ClearNode(chld_node);    
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }
    
    /* Clearing node and xml */
    OS_ClearNode(node);
    OS_ClearXML(&xml);	
    return(0);
}



/* EOF */
