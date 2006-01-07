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
    PluginNode *child_node;
    PluginInfo *nnode;

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
            nnode = node->plugin;

            merror("checking against: %s", nnode->prematch->patterns[0]);
            
            /* If prematch fails, go to the next plugin in the list */
            if(!nnode->prematch || !OSRegex_Execute(lf->log,nnode->prematch))
                continue;

            merror("ok");
            lf->log_tag = nnode->name;

            child_node = node->child;


            /* Setting the type */
            if(nnode->type)
            {
                lf->type = nnode->type;
                merror("type set");
            }


            /* Check if we have any child plugin */
            while(child_node)
            {
                nnode = child_node->plugin;


                if(nnode->prematch && OSRegex_Execute(lf->log,nnode->prematch))
                {
                    break;
                }

                child_node = child_node->next;
                nnode = NULL;
            }

            if(!nnode)
                return;


            merror("going to regex");
            /* Getting the regex */
            if(nnode->regex)
            {
                int i = 0;

                merror("we do have regex: '%s',\nlog:'%s'",
                                            nnode->regex->patterns[0], lf->log);
                /* If Regex does not match, return */
                if(!OSRegex_Execute(lf->log, nnode->regex))
                {
                    return;
                }
               
                if(nnode->regex->sub_strings)
                {
                    merror("field returned ok");
                }
                
                while(nnode->regex->sub_strings[i])
                {
                    if(nnode->order[i])
                    {
                        merror("setting fields..");
                        nnode->order[i](lf, nnode->regex->sub_strings[i]);
                        i++;
                        continue;
                    }

                    /* We do not free any memory used above */
                    free(nnode->regex->sub_strings[i]);
                    nnode->regex->sub_strings[i] = NULL;
                    i++;
                }
            }


            /* Checking if the FTS is set */
            if(nnode->fts)
            {
                lf->fts = nnode->fts;

                /* the comment we need to duplicate too */
                if(nnode->ftscomment)
                    lf->comment = nnode->ftscomment;
            }


            /* Matched  */
            return;         
        }

    }while((node=node->next) != NULL);
}


/*** Event decoders ****/
void *DstUser_FP(Eventinfo *lf, char *field)
{
    lf->dstuser = field;
    return(NULL);
}
void *User_FP(Eventinfo *lf, char *field)
{
    lf->user = field;
    return(NULL);
}
void *SrcIP_FP(Eventinfo *lf, char *field)
{
    lf->srcip = field;
    return(NULL);
}
void *DstIP_FP(Eventinfo *lf, char *field)
{
    lf->dstip = field;
    return(NULL);
}
void *SrcPort_FP(Eventinfo *lf, char *field)
{
    lf->srcport = field;
    return(NULL);
}
void *DstPort_FP(Eventinfo *lf, char *field)
{
    lf->dstport = field;
    return(NULL);
}
void *Protocol_FP(Eventinfo *lf, char *field)
{
    lf->protocol = field;
    return(NULL);
}
void *Action_FP(Eventinfo *lf, char *field)
{
    lf->action = field;
    return(NULL);
}
void *ID_FP(Eventinfo *lf, char *field)
{
    lf->id = field;
    return(NULL);
}
void *None_FP(Eventinfo *lf, char *field)
{
    free(field);
    return(NULL);
}


/* EOF */
