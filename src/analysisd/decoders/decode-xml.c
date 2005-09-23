/*   $OSSEC, decode-xml.c, v0.1, 2005/06/21, Daniel B. Cid$   */

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

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "decoder.h"

#include "error_messages/error_messages.h"

extern short int dbg_flag;

/* Internal functions */
char *_loadmemory(char *at, char *str);


/* ReaddecodeXML */
void ReadDecodeXML(char *file)
{
    
    OS_XML xml;
    XML_NODE node=NULL;

    /* XML variables */ 
    /* These are the available options for the rule configuration */
    
    char *xml_decoder="decoder";
    char *xml_decoder_name="name";
    char *xml_prematch="prematch";
    char *xml_regex="regex";
    char *xml_order="order";
    char *xml_fts="fts";
    char *xml_ftscomment="ftscomment";
    
   
    /* Allowed Fields */
    char *(allowed_fields[]) = {"user","dstuser","srcip","dstip","id",
                                "location",NULL};
    
    int i = 0;
    
     
    /* Reading the XML */       
    if(OS_ReadXML(file,&xml) < 0)
    {
        ErrorExit("decode-xml: XML error: %s",xml.err);
    }

    
    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        ErrorExit("decode-xml: Impossible to apply the variables.");
    }


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror("decode-xml: Bad formated decode.xml file");
        OS_ClearXML(&xml);
        ErrorExit("decode-xml: Cannot proceed from here");
    }


    /* Initializing the list */
    OS_CreatePluginList(); 
    
    while(node[i])
    {
        XML_NODE elements=NULL;
        PluginInfo *pi;

        int j=0;

        
        if(!node[i]->element || 
            strcasecmp(node[i]->element,xml_decoder) != 0)
        {
            ErrorExit("decode-xml: Invalid decode option: '%s'",
                                   node[i]->element);
        }
       
        if((!node[i]->attributes) || (!node[i]->values)||
           (!node[i]->values[0])  || (!node[i]->attributes[0])||
           (strcasecmp(node[i]->attributes[0],xml_decoder_name)!= 0)||
           (node[i]->attributes[1]))
        {
            ErrorExit("decode-xml: Invalid decoder. The only attribute "
                      "acceptable is the decoder name");
        }

         
        /* Getting decoder options */
        elements = OS_GetElementsbyNode(&xml,node[i]);
        if(elements == NULL)
        {
            ErrorExit("decode-xml: Decoder '%s' without any option",
                    node[i]->element);
        }

        /* Creating the PluginInfo */
        pi = (PluginInfo *)calloc(1,sizeof(PluginInfo));
        if(pi == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }
        
        
        /* Default values to the list */
        pi->name = strdup(node[i]->values[0]);
        pi->regex = NULL;
        pi->order = NULL;
        pi->prematch = NULL;
        pi->fts = NULL;
        pi->ftscomment = NULL;
        
        
        /* Looping on all the element */
        while(elements[j])
        {
            /* Checking if the rule name is correct */
            if((!elements[j]->element)||(!elements[j]->content))
            {
                merror("decode-xml: Invalid element on '%s'",
                        node[i]->element);
                OS_ClearXML(&xml);
                ErrorExit("decode-xml: Leaving..");
            }

            /* Getting the regex */
            else if(strcasecmp(elements[j]->element,xml_regex) == 0)
            {
                /* Assign regex */
                pi->regex =
                    _loadmemory(pi->regex,
                            elements[j]->content);
            }
            
            /* Getting the pre match */
            else if(strcasecmp(elements[j]->element,xml_prematch)==0)
            {
                pi->prematch =
                    _loadmemory(pi->prematch,
                            elements[j]->content);
            }

             /* Getting the fts comment */
            else if(strcasecmp(elements[j]->element,xml_ftscomment)==0)
            {
                pi->ftscomment =
                    _loadmemory(pi->ftscomment,
                            elements[j]->content);
            }
                         
            /* Getting the order */
            else if(strcasecmp(elements[j]->element,xml_order)==0)
            {
                char **norder;
                /* Maximum number is 8 for the order */
                pi->order = OS_StrBreak(',',elements[j]->content, 8);

                norder = pi->order;

                /* Checking the values from the order */
                while(*norder)
                {
                    int f_allowed = 0;
                    int k = 0;
                   
                    while(allowed_fields[k])
                    {
                        if(strstr(*norder,allowed_fields[k]) != NULL)
                        {
                            /* Location is not acceptable here */
                            if(strstr(*norder,"location") == NULL)
                                f_allowed = 1;
                        }
                        
                        k++;
                    }

                    if(f_allowed == 0)
                    {
                        ErrorExit("decode-xml: Wrong field '%s' in the order"
                                  " of decoder '%s'",*norder,pi->name);
                    }

                    norder++;
                }
            }
            
             /* Getting the order */
            else if(strcasecmp(elements[j]->element,xml_fts)==0)
            {
                char **norder;
                char **s_norder;
                
                /* Maximum number is 8 for the fts */
                norder = OS_StrBreak(',',elements[j]->content, 8);
                if(norder == NULL)
                    ErrorExit(MEM_ERROR,ARGV0);
                
                pi->fts =
                    _loadmemory(pi->fts,
                            elements[j]->content);
                
                /* Saving the initial point to free later */
                s_norder = norder;
                    
                /* Checking the values from the fts */
                while(*norder)
                {
                    int f_allowed = 0;
                    int k = 0;
                   
                    while(allowed_fields[k])
                    {
                        if(strstr(*norder,allowed_fields[k]) != NULL)
                        {
                            f_allowed = 1;
                        }
                        
                        k++;
                    }

                    /* Name is also allowed for the fts */
                    if(strstr(*norder,"name") != NULL)
                        f_allowed = 1;
                        
                    if(f_allowed == 0)
                    {
                        ErrorExit("decode-xml: Wrong field '%s' in the fts"
                                  " decoder '%s'",*norder,pi->name);
                    }

                    free(*norder);
                    norder++;
                }

                /* Clearing the memory here */
                free(s_norder);
            }
            else
            {
                merror("decode-xml: Invalid element '%s' for "
                        "decoder %s",elements[j]->element,
                        node[i]->element);
                OS_ClearXML(&xml);
                ErrorExit("decode-xml: Bad Configuration");
            }

            /* NEXT */
            j++;
            
        } /* while(elements[j]) */
        
        OS_ClearNode(elements);
        
        /* Adding plugin to the list */
        OS_AddPlugin(pi);

        i++;
    } /* while (node[i]) */

    /* Cleaning  node and XML structures */
    OS_ClearNode(node);
    
    OS_ClearXML(&xml);

    /* Done over here */
    return;
}


/* _loadmemory: v0.1
 * Allocate memory at "*at" and copy *str to it.
 * If *at already exist, realloc the memory and cat str
 * on it.
 * It will return the new string
 */
char *_loadmemory(char *at, char *str)
{
    if(at == NULL)
    {
        int strsize=0;
        if((strsize = strlen(str)) < OS_RULESIZE)
        {
            at = calloc(strsize+1,sizeof(char));
            if(at == NULL)
            {
                merror(MEM_ERROR,ARGV0);
                return(NULL);
            }
            strncpy(at,str,strsize);
            return(at);
        }
        else
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }
    }
    else /*at is not null. Need to reallocat its memory and copy str to it*/
    {
        int strsize = strlen(str);
        int atsize = strlen(at);
        int finalsize = atsize+strsize+1;
        if((atsize > OS_RULESIZE) || (strsize > OS_RULESIZE))
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }
        at = realloc(at, (finalsize)*sizeof(char));
        if(at == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }
        strncat(at,str,strsize-1);
        at[finalsize-1]='\0';
        return(at);
    }
    return(NULL);
}

/* EOF */
