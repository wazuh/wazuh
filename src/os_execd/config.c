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
        ErrorExit(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
    }


    node = OS_GetElementsbyNode(&xml,NULL);
    if(node == NULL)
    {
        ErrorExit(XML_READ_ERROR, ARGV0);
    }

    
    /* Searching for entries related to files */
    while(node[i])
    {
        if(node[i]->element)
        {
            if(strcmp(node[i]->element,xml_ar) == 0)
            {
                XML_NODE chld_node = NULL;
                chld_node = OS_GetElementsbyNode(&xml,node[i]);
                
                j = 0;
 
                while(chld_node[j])
                {
                    if((!chld_node[j]->element)||(!chld_node[j]->content))
                    {
                        merror(XML_INVELEM, ARGV0, xml_ar);
                        return(-1);
                    }

                    else if(strcmp(chld_node[j]->element,
                            xml_ar_disabled) == 0)
                    {
                        if(strcmp(chld_node[j]->content,"yes") == 0)
                        {
                            return(1);
                        }
                        else if(strcmp(chld_node[j]->content,"no") == 0)
                        {
                        }
                        else
                        {
                            merror(XML_VALUEERR, ARGV0, 
                                                 chld_node[j]->element,
                                                 chld_node[j]->content); 
                            return(-1);
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
