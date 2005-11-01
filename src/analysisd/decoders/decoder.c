/*   $OSSEC, decoder.c, v0.1, 2005/06/21, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.1: 2005/06/21
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"

#include "shared.h"

#include "eventinfo.h"
#include "decoder.h"




/* DecodeEvent.
 * Will use the plugins to decode the received event.
 */
void DecodeEvent(Eventinfo *lf)
{
    PluginNode *node;
   
    node = OS_GetFirstPlugin();
    
    /* Return if no node...
     * This shouldn't happen here anyways
     */
    if(!node)
        return;
  
     
    do 
    {
        if(node->plugin)
        {
            PluginInfo *nnode = node->plugin;
            
            /* If prematch fails, go to the next plugin in the list */
            if(nnode->prematch && !OS_Regex(nnode->prematch,lf->log))
                continue;
    
            /* Check if we have any child plugin */
            while(node->child)
            {
                nnode = node->child->plugin;

                if(nnode->prematch && OS_Regex(nnode->prematch,lf->log))
                {
                    break;
                }
                
                node->child = node->child->next;
                nnode = NULL;
            }
           
            if(!nnode)
                return;

            
            /* Getting the regex */
            if(nnode->regex)
            {
                int i = 0;
                char **fields;
                
                fields = OS_RegexStr(nnode->regex,lf->log);
                if(!fields)
                    return;

                while(fields[i])
                {
                    if(nnode->order[i])
                    {
                        /* DstUser field */
                        if(strcmp(nnode->order[i],"dstuser") == 0)
                        {
                            lf->dstuser = fields[i];
                            i++;
                            continue;
                        }
                         /* User field */
                        else if(strstr(nnode->order[i],"user") != NULL)
                        {
                            lf->user = fields[i];
                            i++;
                            continue;
                        }
                        /* srcip */
                        else if(strstr(nnode->order[i],"srcip") != NULL)
                        {
                            lf->srcip = fields[i];
                            i++;
                            continue;
                        }
                        /* desip */
                        else if(strstr(nnode->order[i],"dstip") != NULL)
                        {
                            lf->dstip = fields[i];
                            i++;
                            continue;
                        }
                        /* ID */
                        else if(strstr(nnode->order[i],"id") != NULL)
                        {
                            lf->id = fields[i];
                            i++;
                            continue;
                        }
                        
                        /* We do not free any memory used above */
                    }
                    
                    free(fields[i]);
                    i++;
                }

                free(fields);
                    
            }
           
            
            /* Checking if the FTS is set */
            if(nnode->fts)
            {
                lf->fts = nnode->fts;

                /* the comment we need to duplicate */
                if(nnode->ftscomment)
                    lf->comment = nnode->ftscomment;
            }

            /* Getting the name */
            if(nnode->name)
            {
                /* We just need to point at it */
                lf->log_tag = nnode->name;
            }
            
            /* Matched the pre match */
            return;         
        }
        
    }while((node=node->next) != NULL);
}
    

/* EOF */
