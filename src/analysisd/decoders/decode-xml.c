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

#include "shared.h"

#include "eventinfo.h"
#include "decoder.h"



/* Internal functions */
char *_loadmemory(char *at, char *str);


/* Read attributes */
int ReadDecodeAttrs(char **names, char **values)
{
    if(!names || !values)
        return(0);

    if(!names[0] || !values[0])
    {
        return(0);
    }
    
    if(strcmp(names[0], "offset") == 0)
    {
        int offset = 0;
        
        /* Offsets can be: after_parent, after_prematch
         * or after_regex.
         */
        if(strcmp(values[0],"after_parent") == 0)
        {
            offset |= AFTER_PARENT;
        }
        else if(strcmp(values[0],"after_prematch") == 0)
        {
            offset |= AFTER_PREMATCH;
        }
        else if(strcmp(values[0],"after_regex") == 0)
        {
            offset |= AFTER_PREVREGEX;
        }
        else
        {
            merror(INV_OFFSET, ARGV0, values[0]);
            offset |= AFTER_ERROR;
        }
        
        return(offset);
    }

    /* Invalid attribute */
    merror(INV_ATTR, ARGV0, names[0]);
    return(AFTER_ERROR);
}


/* ReaddecodeXML */
void ReadDecodeXML(char *file)
{
    
    OS_XML xml;
    XML_NODE node = NULL;

    /* XML variables */ 
    /* These are the available options for the rule configuration */
    
    char *xml_decoder = "decoder";
    char *xml_decoder_name = "name";
    char *xml_usename = "use_own_name";
    char *xml_parent = "parent";
    char *xml_prematch = "prematch";
    char *xml_regex = "regex";
    char *xml_order = "order";
    char *xml_type = "type";
    char *xml_fts = "fts";
    char *xml_ftscomment = "ftscomment";
    
   
    int i = 0;
    
     
    /* Reading the XML */       
    if(OS_ReadXML(file,&xml) < 0)
    {
        ErrorExit("decode-xml: XML error: %s",xml.err);
    }

    
    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        ErrorExit("decode-xml: Unable to apply the variables.");
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
        XML_NODE elements = NULL;
        PluginInfo *pi;

        int j = 0;
        char *regex;
        char *prematch;

        
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
        pi->parent = NULL;
        pi->name = strdup(node[i]->values[0]);
        pi->order = NULL;
        pi->ftscomment = NULL;
        pi->fts = 0;
        pi->type = SYSLOG;
        pi->prematch = NULL;
        pi->regex = NULL;
        pi->use_own_name = 0;
        pi->get_next = 0;
        pi->regex_offset = 0;
        pi->prematch_offset = 0;
        
        regex = NULL;
        prematch = NULL;
       
        if(!pi->name)
        {
            ErrorExit(MEM_ERROR, ARGV0);
        }
        
        
        /* Looping on all the elements */
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

            /* Checking if it is a child of a rule */
            else if(strcasecmp(elements[j]->element, xml_parent) == 0)
            {
                pi->parent = _loadmemory(pi->parent, elements[j]->content);
            }
            
            /* Getting the regex */
            else if(strcasecmp(elements[j]->element,xml_regex) == 0)
            {
                int r_offset;
                r_offset = ReadDecodeAttrs(elements[j]->attributes,
                                           elements[j]->values);
                
                if(r_offset & AFTER_ERROR)
                {
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
                }
                
                /* Only the first regex entry may have an offset */ 
                if(regex && r_offset)
                {
                    merror(DUP_REGEX, ARGV0, pi->name);
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
                }
                
                /* regex offset */
                if(r_offset)
                {
                    pi->regex_offset = r_offset;
                }
                
                /* Assign regex */
                regex =
                    _loadmemory(regex,
                            elements[j]->content);
            }
            
            /* Getting the pre match */
            else if(strcasecmp(elements[j]->element,xml_prematch)==0)
            {
                pi->prematch_offset = ReadDecodeAttrs(
                                      elements[j]->attributes,
                                      elements[j]->values);

                if(pi->prematch_offset & AFTER_ERROR)
                {
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
                }

                /* Only the first regex entry may have an offset */
                if(prematch && pi->prematch_offset)
                {
                    merror(DUP_REGEX, ARGV0, pi->name);
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
                }

                prematch =
                    _loadmemory(prematch,
                            elements[j]->content);
            }

            /* Getting the fts comment */
            else if(strcasecmp(elements[j]->element,xml_ftscomment)==0)
            {
                pi->ftscomment =
                    _loadmemory(pi->ftscomment,
                            elements[j]->content);
            }

            else if(strcasecmp(elements[j]->element,xml_usename)==0)
            {
                if(strcmp(elements[j]->content,"true") == 0)
                    pi->use_own_name = 1;
            }
                                                                                
            
            /* Getting the type */
            else if(strcmp(elements[j]->element, xml_type) == 0)
            {
                if(strcmp(elements[j]->content, "firewall") == 0)
                    pi->type = FIREWALL;
                else if(strcmp(elements[j]->content, "ids") == 0)
                    pi->type = IDS;
                else if(strcmp(elements[j]->content, "web-log") == 0)
                    pi->type = WEBLOG;    
                else if(strcmp(elements[j]->content, "syslog") == 0)
                    pi->type = SYSLOG;
                else if(strcmp(elements[j]->content, "squid") == 0)
                    pi->type = SQUID;
                else if(strcmp(elements[j]->content, "windows") == 0)
                    pi->type = WINDOWS;        
                else if(strcmp(elements[j]->content, "host-information") == 0)
                    pi->type = HOST_INFO;
                else
                {
                    ErrorExit("decode-xml: Invalid decoder type '%s'.",
                               elements[j]->content);
                }
            }
                         
            /* Getting the order */
            else if(strcasecmp(elements[j]->element,xml_order)==0)
            {
                char **norder, **s_norder;
                int order_int = 0;
                
                /* Maximum number is 8 for the order */
                norder = OS_StrBreak(',',elements[j]->content, 8);
                s_norder = norder;
                os_calloc(8, sizeof(void *), pi->order);


                /* Initializing the function pointers */
                while(order_int < 8)
                {
                    pi->order[order_int] = NULL;
                    order_int++;
                }
                order_int = 0;
                

                /* Checking the values from the order */
                while(*norder)
                {
                    if(strstr(*norder, "dstuser") != NULL)
                    {
                        pi->order[order_int] = (void *)DstUser_FP;
                    }
                    else if(strstr(*norder, "user") != NULL)
                    {
                        pi->order[order_int] = (void *)User_FP;
                    }
                    else if(strstr(*norder, "srcip") != NULL)
                    {
                        pi->order[order_int] = (void *)SrcIP_FP;
                    }
                    else if(strstr(*norder, "dstip") != NULL)
                    {
                        pi->order[order_int] = (void *)DstIP_FP;
                    }
                    else if(strstr(*norder, "srcport") != NULL)
                    {
                        pi->order[order_int] = (void *)SrcPort_FP;
                    }
                    else if(strstr(*norder, "dstport") != NULL)
                    {
                        pi->order[order_int] = (void *)DstPort_FP;
                    }
                    else if(strstr(*norder, "protocol") != NULL)
                    {
                        pi->order[order_int] = (void *)Protocol_FP;
                    }
                    else if(strstr(*norder, "action") != NULL)
                    {
                        pi->order[order_int] = (void *)Action_FP;
                    }
                    else if(strstr(*norder, "id") != NULL)
                    {
                        pi->order[order_int] = (void *)ID_FP;
                    }
                    else if(strstr(*norder, "url") != NULL)
                    {
                        pi->order[order_int] = (void *)Url_FP;
                    }
                    else if(strstr(*norder, "data") != NULL)
                    {
                        pi->order[order_int] = (void *)Data_FP;
                    }
                    else if(strstr(*norder, "system_name") != NULL)
                    {
                        pi->order[order_int] = (void *)SystemName_FP;
                    }
                    else
                    {
                        ErrorExit("decode-xml: Wrong field '%s' in the order"
                                  " of decoder '%s'",*norder,pi->name);
                    }

                    free(*norder);
                    norder++;

                    order_int++;
                }

                free(s_norder);
            }
            
            /* Getting the fts order */
            else if(strcasecmp(elements[j]->element,xml_fts)==0)
            {
                char **norder;
                char **s_norder;
                
                /* Maximum number is 8 for the fts */
                norder = OS_StrBreak(',',elements[j]->content, 8);
                if(norder == NULL)
                    ErrorExit(MEM_ERROR,ARGV0);
                
                
                /* Saving the initial point to free later */
                s_norder = norder;
                
                    
                /* Checking the values from the fts */
                while(*norder)
                {
                    if(strstr(*norder, "dstuser") != NULL)
                    {
                        pi->fts|=FTS_DSTUSER;
                    }
                    else if(strstr(*norder, "user") != NULL)
                    {
                        pi->fts|=FTS_USER;
                    }
                    else if(strstr(*norder, "srcip") != NULL)
                    {
                        pi->fts|=FTS_SRCIP;
                    }
                    else if(strstr(*norder, "dstip") != NULL)
                    {
                        pi->fts|=FTS_DSTIP;
                    }
                    else if(strstr(*norder, "id") != NULL)
                    {
                        pi->fts|=FTS_ID;
                    }
                    else if(strstr(*norder, "location") != NULL)
                    {
                        pi->fts|=FTS_LOCATION;
                    }
                    else if(strstr(*norder, "name") != NULL)
                    {
                        pi->fts|=FTS_NAME;
                    }
                    else if(strstr(*norder, "data") != NULL)
                    {
                        pi->fts|=FTS_DATA;
                    }
                    else if(strstr(*norder, "system_name") != NULL)
                    {
                        pi->fts|=FTS_SYSTEMNAME;
                    }
                    else
                    {
                        ErrorExit("decode-xml: Wrong field '%s' in the fts"
                                  " decoder '%s'",*norder, pi->name);
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
        

        /* Prematch must be set */
        if(!prematch && !pi->parent)
        {
            ErrorExit(DECODE_NOPRE, ARGV0, pi->name);
            ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
        }

        /* If pi->regex is not set, fts must not be set too */
        if((!regex && (pi->fts || pi->order)) || (regex && !pi->order))
        {
            ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
        }
        

        /* For the offsets */
        if(pi->regex_offset & AFTER_PARENT && !pi->parent)
        {
            merror(INV_OFFSET, ARGV0, "after_parent");
            ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
        }
        
        if(pi->regex_offset & AFTER_PREMATCH)
        {
            /* If after_prematch is set, but rule have
             * no parent, set AFTER_PARENT and unset
             * pre_match.
             */
            if(!pi->parent)
            {
                pi->regex_offset = 0;
                pi->regex_offset|= AFTER_PARENT;
            }
            else if(!prematch)
            {
                merror(INV_OFFSET, ARGV0, "after_prematch");
                ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
            }
        }
        
        /* For the after_regex offset */
        if(pi->regex_offset & AFTER_PREVREGEX)
        {
            if(!pi->parent || !regex)
            {
                merror(INV_OFFSET, ARGV0, "after_regex");
                ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
            }
        }
        

        /* Checking the prematch offset */
        if(pi->prematch_offset)
        {
            /* Only the after parent is allowed */
            if(pi->prematch_offset & AFTER_PARENT)
            {
                if(!pi->parent)
                {
                    merror(INV_OFFSET, ARGV0, "after_parent");
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);

                }
            }
            else
            {
                ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
            }
        }

        
        /* Compiling the regex/prematch */
        if(prematch)
        {
            os_calloc(1, sizeof(OSRegex), pi->prematch);
            if(!OSRegex_Compile(prematch, pi->prematch, 0))
            {
                ErrorExit(REGEX_COMPILE, ARGV0, prematch, pi->prematch->error);
            }

            free(prematch);
        }
        
        
        /* We may not have the pi->regex */
        if(regex)
        {
            os_calloc(1, sizeof(OSRegex), pi->regex);
            if(!OSRegex_Compile(regex, pi->regex, OS_RETURN_SUBSTRING))
            {
                ErrorExit(REGEX_COMPILE, ARGV0, regex, pi->regex->error);
            }

            /* We must have the sub_strings to retrieve the nodes */
            if(!pi->regex->sub_strings)
            {
                ErrorExit(REGEX_SUBS, ARGV0, regex);
            }

            free(regex);
        }
        
        /* Adding plugin to the list */
        if(!OS_AddPlugin(pi))
        {
            ErrorExit(DECODER_ERROR, ARGV0);        
        }

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
        int strsize = 0;
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
    /* At is not null. Need to reallocat its memory and copy str to it */
    else
    {
        int strsize = strlen(str);
        int atsize = strlen(at);
        int finalsize = atsize+strsize+1;
        if(finalsize > OS_RULESIZE)
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }
        at = realloc(at, (finalsize +1)*sizeof(char));
        if(at == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }
        strncat(at,str,strsize);
        at[finalsize - 1] = '\0';

        return(at);
    }
    return(NULL);
}

/* EOF */
