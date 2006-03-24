/*   $OSSEC, config.c, v0.1, 2006/03/24, Daniel B. Cid$   */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h" 



/* ExecdConfig v0.1, 2006/03/24
 * Read the config file
 */
int ExecdConfig(char * cfgfile)
{
    int i = 0,j = 0;
    OS_XML xml;
    XML_NODE node = NULL;


    /* XML Definitions */
    char *xml_ar_disabled = "disabled";


    /* Reading XML file */
    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror("%s: XML error: %s", ARGV0, xml.err);
        exit(1);
    }


    node = OS_GetElementsbyNode(&xml,NULL);
    if(node == NULL)
    {
        merror("%s: Error reading the XML.", ARGV0);
        OS_ClearXML(&xml);
        exit(1);
    }

    
    /* Searching for entries related to files */
    while(node[i])
    {
        if(node[i]->element)
        {
            if(strcmp(node[i]->element,xml_ar) == 0)
            {
                XML_NODE chld_node = NULL;
                
                j = 0;
 
                while(chld_node[j])
                {
                    if((!chld_node[j]->element)||(!chld_node[j]->content))
                    {
                        merror("%s: Error reading XML child nodes",ARGV0);
                        OS_ClearXML(&xml);
                        exit(1);
                    }

                    else if(strcmp(chld_node[j]->element,
                            xml_ar_disabled) == 0)
                    {
                        if(chld_node[j]->content[0] == 'y')
                        {
                            verbose("%s: Active response disabled. Exiting.", ARGV0);
                            exit(0);
                        }
                    }
                    
                    j++;
                }
            }
        }
        i++;
    }                    
                        
    OS_ClearXML(&xml);
    return(0);
}

/* EOF */
