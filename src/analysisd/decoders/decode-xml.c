/* @(#) $Id: ./src/analysisd/decoders/decode-xml.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "shared.h"
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"


#include "analysisd.h"
#include "eventinfo.h"
#include "decoder.h"
#include "plugin_decoders.h"


#ifdef TESTRULE
  #undef XML_LDECODER
  #define XML_LDECODER "etc/local_decoder.xml"
#endif


/* Internal functions */
char *_loadmemory(char *at, char *str);
OSStore *os_decoder_store = NULL;


/* Gets decoder id */
int getDecoderfromlist(char *name)
{
    if(os_decoder_store)
    {
        return(OSStore_GetPosition(os_decoder_store, name));
    }

    return(0);
}


/* Adds decoder id */
int addDecoder2list(char *name)
{
    if(os_decoder_store == NULL)
    {
        os_decoder_store = OSStore_Create();
        if(os_decoder_store == NULL)
        {
            merror(LIST_ERROR, ARGV0);
            return(0);
        }
    }

    /* Storing data */
    if(!OSStore_Put(os_decoder_store, name, NULL))
    {
        merror(LIST_ADD_ERROR, ARGV0);
        return(0);
    }

    return(1);
}


/* Set decoder ids */
int os_setdecoderids(char *p_name)
{
    OSDecoderNode *node;
    OSDecoderNode *child_node;
    OSDecoderInfo *nnode;


    node = OS_GetFirstOSDecoder(p_name);


    /* Return if no node...
     * This shouldn't happen here anyways.
     */
    if(!node)
        return(0);

    do
    {
        int p_id = 0;
        char *p_name;

        nnode = node->osdecoder;
        nnode->id = getDecoderfromlist(nnode->name);

        /* Id can noit be 0 */
        if(nnode->id == 0)
        {
            return(0);
        }

        child_node = node->child;

        if(!child_node)
        {
            continue;
        }


        /* Setting parent id */
        p_id = nnode->id;
        p_name = nnode->name;


        /* Also setting on the child nodes */
        while(child_node)
        {
            nnode = child_node->osdecoder;

            if(nnode->use_own_name)
            {
                nnode->id = getDecoderfromlist(nnode->name);
            }
            else
            {
                nnode->id = p_id;

                /* Setting parent name */
                nnode->name = p_name;
            }


            /* Id can noit be 0 */
            if(nnode->id == 0)
            {
                return(0);
            }
            child_node = child_node->next;
        }
    }while((node=node->next) != NULL);

    return(1);
}


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
int ReadDecodeXML(char *file)
{
    OS_XML xml;
    XML_NODE node = NULL;

    /* XML variables */
    /* These are the available options for the rule configuration */

    char *xml_plugindecoder = "plugin_decoder";
    char *xml_decoder = "decoder";
    char *xml_decoder_name = "name";
    char *xml_decoder_status = "status";
    char *xml_usename = "use_own_name";
    char *xml_parent = "parent";
    char *xml_program_name = "program_name";
    char *xml_prematch = "prematch";
    char *xml_regex = "regex";
    char *xml_order = "order";
    char *xml_type = "type";
    char *xml_fts = "fts";
    char *xml_ftscomment = "ftscomment";
    char *xml_accumulate = "accumulate";

    int i = 0;
    OSDecoderInfo *NULL_Decoder_tmp = NULL;


    /* Reading the XML */
    if((i = OS_ReadXML(file,&xml)) < 0)
    {
        if((i == -2) && (strcmp(file, XML_LDECODER) == 0))
        {
            return(-2);
        }

        merror(XML_ERROR, ARGV0, file, xml.err, xml.err_line);
        return(0);
    }


    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        merror(XML_ERROR_VAR, ARGV0, file, xml.err);
        return(0);
    }


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if(!node)
    {
        if(strcmp(file, XML_LDECODER) != 0)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(0);
        }

        return(-2);
    }


    /* Zeroing NULL_decoder */
    os_calloc(1, sizeof(OSDecoderInfo), NULL_Decoder_tmp);
    NULL_Decoder_tmp->id = 0;
    NULL_Decoder_tmp->type = SYSLOG;
    NULL_Decoder_tmp->name = NULL;
    NULL_Decoder_tmp->fts = 0;
    NULL_Decoder = (void *)NULL_Decoder_tmp;



    i = 0;
    while(node[i])
    {
        XML_NODE elements = NULL;
        OSDecoderInfo *pi;

        int j = 0;
        char *regex;
        char *prematch;
        char *p_name;


        if(!node[i]->element ||
            strcasecmp(node[i]->element, xml_decoder) != 0)
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(0);
        }


        /* Getting name */
        if((!node[i]->attributes) || (!node[i]->values)||
           (!node[i]->values[0])  || (!node[i]->attributes[0])||
           (strcasecmp(node[i]->attributes[0],xml_decoder_name)!= 0))
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(0);
        }


        /* Checking for additional entries */
        if(node[i]->attributes[1] && node[i]->values[1])
        {
            if(strcasecmp(node[i]->attributes[0],xml_decoder_status)!= 0)
            {
                merror(XML_INVELEM, ARGV0, node[i]->element);
                return(0);
            }

            if(node[i]->attributes[2])
            {
                merror(XML_INVELEM, ARGV0, node[i]->element);
                return(0);
            }
        }


        /* Getting decoder options */
        elements = OS_GetElementsbyNode(&xml,node[i]);
        if(elements == NULL)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(0);
        }

        /* Creating the OSDecoderInfo */
        pi = (OSDecoderInfo *)calloc(1,sizeof(OSDecoderInfo));
        if(pi == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(0);
        }


        /* Default values to the list */
        pi->parent = NULL;
        pi->id = 0;
        pi->name = strdup(node[i]->values[0]);
        pi->order = NULL;
        pi->plugindecoder = NULL;
        pi->fts = 0;
        pi->accumulate = 0;
        pi->type = SYSLOG;
        pi->prematch = NULL;
        pi->program_name = NULL;
        pi->regex = NULL;
        pi->use_own_name = 0;
        pi->get_next = 0;
        pi->regex_offset = 0;
        pi->prematch_offset = 0;

        regex = NULL;
        prematch = NULL;
        p_name = NULL;


        /* Checking if strdup worked */
        if(!pi->name)
        {
            merror(MEM_ERROR, ARGV0);
            return(0);
        }

        /* Add decoder */
        if(!addDecoder2list(pi->name))
        {
            merror(MEM_ERROR, ARGV0);
            return(0);
        }

        /* Looping on all the elements */
        while(elements[j])
        {
            if(!elements[j]->element)
            {
                merror(XML_ELEMNULL, ARGV0);
                return(0);
            }
            else if(!elements[j]->content)
            {
                merror(XML_VALUENULL, ARGV0, elements[j]->element);
                return(0);
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
                    merror(DEC_REGEX_ERROR, ARGV0, pi->name);
                    return(0);
                }

                /* Only the first regex entry may have an offset */
                if(regex && r_offset)
                {
                    merror(DUP_REGEX, ARGV0, pi->name);
                    merror(DEC_REGEX_ERROR, ARGV0, pi->name);
                    return(0);
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
                int r_offset;

                r_offset = ReadDecodeAttrs(
                                      elements[j]->attributes,
                                      elements[j]->values);

                if(r_offset & AFTER_ERROR)
                {
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
                }


                /* Only the first prematch entry may have an offset */
                if(prematch && r_offset)
                {
                    merror(DUP_REGEX, ARGV0, pi->name);
                    ErrorExit(DEC_REGEX_ERROR, ARGV0, pi->name);
                }

                if(r_offset)
                {
                    pi->prematch_offset = r_offset;
                }

                prematch =
                    _loadmemory(prematch,
                            elements[j]->content);
            }

            /* Getting program name */
            else if(strcasecmp(elements[j]->element,xml_program_name) == 0)
            {
                p_name = _loadmemory(p_name, elements[j]->content);
            }

            /* Getting the fts comment */
            else if(strcasecmp(elements[j]->element,xml_ftscomment)==0)
            {
            }

            else if(strcasecmp(elements[j]->element,xml_usename)==0)
            {
                if(strcmp(elements[j]->content,"true") == 0)
                    pi->use_own_name = 1;
            }

            else if(strcasecmp(elements[j]->element, xml_plugindecoder) == 0)
            {
                int ed_c = 0;
                for(ed_c = 0; plugin_decoders[ed_c] != NULL; ed_c++)
                {
                    if(strcmp(plugin_decoders[ed_c],
                              elements[j]->content) == 0)
                    {
                        /* Initializing plugin */
                        void (*dec_init)() = plugin_decoders_init[ed_c];

                        dec_init();
                        pi->plugindecoder = plugin_decoders_exec[ed_c];
                        break;
                    }
                }

                /* Decoder not found */
                if(pi->plugindecoder == NULL)
                {
                    merror(INV_DECOPTION, ARGV0, elements[j]->element,
                                          elements[j]->content);
                    return(0);
                }
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
                    pi->type = DECODER_WINDOWS;
                else if(strcmp(elements[j]->content, "host-information") == 0)
                    pi->type = HOST_INFO;
                else if(strcmp(elements[j]->content, "ossec") == 0)
                    pi->type = OSSEC_RL;
                else
                {
                    merror("%s: Invalid decoder type '%s'.",
                               ARGV0, elements[j]->content);
                    return(0);
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
                    else if(strstr(*norder, "srcuser") != NULL)
                    {
                        pi->order[order_int] = (void *)SrcUser_FP;
                    }
                    /* User is an alias to dstuser */
                    else if(strstr(*norder, "user") != NULL)
                    {
                        pi->order[order_int] = (void *)DstUser_FP;
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
                    else if(strstr(*norder, "extra_data") != NULL)
                    {
                        pi->order[order_int] = (void *)Data_FP;
                    }
                    else if(strstr(*norder, "status") != NULL)
                    {
                        pi->order[order_int] = (void *)Status_FP;
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

            else if(strcasecmp(elements[j]->element,xml_accumulate)==0)
            {
                /* Enable Accumulator */
                pi->accumulate = 1;
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
                    if(strstr(*norder, "user") != NULL)
                    {
                        pi->fts|=FTS_DSTUSER;
                    }
                    else if(strstr(*norder, "srcuser") != NULL)
                    {
                        pi->fts|=FTS_SRCUSER;
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
                    else if(strstr(*norder, "data") != NULL)
                    {
                        pi->fts|=FTS_DATA;
                    }
                    else if(strstr(*norder, "extra_data") != NULL)
                    {
                        pi->fts|=FTS_DATA;
                    }
                    else if(strstr(*norder, "system_name") != NULL)
                    {
                        pi->fts|=FTS_SYSTEMNAME;
                    }
                    else if(strstr(*norder, "name") != NULL)
                    {
                        pi->fts|=FTS_NAME;
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
                merror("%s: Invalid element '%s' for "
                        "decoder '%s'",
                        ARGV0,
                        elements[j]->element,
                        node[i]->element);
                return(0);
            }

            /* NEXT */
            j++;

        } /* while(elements[j]) */

        OS_ClearNode(elements);


        /* Prematch must be set */
        if(!prematch && !pi->parent && !p_name)
        {
            merror(DECODE_NOPRE, ARGV0, pi->name);
            merror(DEC_REGEX_ERROR, ARGV0, pi->name);
            return(0);
        }

        /* If pi->regex is not set, fts must not be set too */
        if((!regex && (pi->fts || pi->order)) || (regex && !pi->order))
        {
            merror(DEC_REGEX_ERROR, ARGV0, pi->name);
            return(0);
        }


        /* For the offsets */
        if((pi->regex_offset & AFTER_PARENT) && !pi->parent)
        {
            merror(INV_OFFSET, ARGV0, "after_parent");
            merror(DEC_REGEX_ERROR, ARGV0, pi->name);
            return(0);
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
                merror(DEC_REGEX_ERROR, ARGV0, pi->name);
                return(0);
            }
        }

        /* For the after_regex offset */
        if(pi->regex_offset & AFTER_PREVREGEX)
        {
            if(!pi->parent || !regex)
            {
                merror(INV_OFFSET, ARGV0, "after_regex");
                merror(DEC_REGEX_ERROR, ARGV0, pi->name);
                return(0);
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
                    merror(DEC_REGEX_ERROR, ARGV0, pi->name);
                    return(0);
                }
            }
            else
            {
                merror(DEC_REGEX_ERROR, ARGV0, pi->name);
                return(0);
            }
        }


        /* Compiling the regex/prematch */
        if(prematch)
        {
            os_calloc(1, sizeof(OSRegex), pi->prematch);
            if(!OSRegex_Compile(prematch, pi->prematch, 0))
            {
                merror(REGEX_COMPILE, ARGV0, prematch, pi->prematch->error);
                return(0);
            }

            free(prematch);
        }

        /* Compiling the p_name */
        if(p_name)
        {
            os_calloc(1, sizeof(OSMatch), pi->program_name);
            if(!OSMatch_Compile(p_name, pi->program_name, 0))
            {
                merror(REGEX_COMPILE, ARGV0, p_name, pi->program_name->error);
                return(0);
            }

            free(p_name);
        }

        /* We may not have the pi->regex */
        if(regex)
        {
            os_calloc(1, sizeof(OSRegex), pi->regex);
            if(!OSRegex_Compile(regex, pi->regex, OS_RETURN_SUBSTRING))
            {
                merror(REGEX_COMPILE, ARGV0, regex, pi->regex->error);
                return(0);
            }

            /* We must have the sub_strings to retrieve the nodes */
            if(!pi->regex->sub_strings)
            {
                merror(REGEX_SUBS, ARGV0, regex);
                return(0);
            }

            free(regex);
        }


        /* Validating arguments */
        if(pi->plugindecoder && (pi->regex || pi->order))
        {
            merror(DECODE_ADD, ARGV0, pi->name);
            return(0);
        }

        /* Adding osdecoder to the list */
        if(!OS_AddOSDecoder(pi))
        {
            merror(DECODER_ERROR, ARGV0);
            return(0);
        }

        i++;
    } /* while (node[i]) */


    /* Cleaning  node and XML structures */
    OS_ClearNode(node);


    OS_ClearXML(&xml);


    /* Done over here */
    return(1);
}



int SetDecodeXML()
{
    /* Adding rootcheck decoder to list */
    addDecoder2list(ROOTCHECK_MOD);
    addDecoder2list(SYSCHECK_MOD);
    addDecoder2list(SYSCHECK_MOD2);
    addDecoder2list(SYSCHECK_MOD3);
    addDecoder2list(SYSCHECK_NEW);
    addDecoder2list(SYSCHECK_DEL);
    addDecoder2list(HOSTINFO_NEW);
    addDecoder2list(HOSTINFO_MOD);


    /* Setting ids - for our two lists */
    if(!os_setdecoderids(NULL))
    {
        merror(DECODER_ERROR, ARGV0);
        return(0);
    }
    if(!os_setdecoderids(ARGV0))
    {
        merror(DECODER_ERROR, ARGV0);
        return(0);
    }


    /* Done over here */
    return(1);
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
        if((strsize = strlen(str)) < OS_SIZE_1024)
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
        if(finalsize > OS_SIZE_1024)
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
