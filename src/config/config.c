/* @(#) $Id$ */

/* Copyright (C) 2003-2008 Third Brigade, Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
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
    char *oslocalfile = "localfile";
    char *osremote = "remote";
    char *osclient = "client";
    char *oscommand = "command";
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
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        
        OS_ClearNode(chld_node);
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
    

    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
        return(OS_INVALID);
    }
    

    node = OS_GetElementsbyNode(&xml, NULL);


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
