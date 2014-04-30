/* @(#) $Id: ./src/os_xml/os_xml_node_access.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml C Library.
 * Available at http://www.ossec.net/
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_xml.h"
#include "os_xml_internal.h"


/* OS_ClearNode v0,1
 * Clear the Node structure
 */
void OS_ClearNode(xml_node **node)
{
    if(node)
    {
        int i=0;
        while(node[i])
        {
            if(node[i]->element)
            {
                free(node[i]->element);
            }
            if(node[i]->content)
            {
                free(node[i]->content);
            }
            if(node[i]->attributes)
            {
                int j=0;
                while(node[i]->attributes[j])
                {
                    free(node[i]->attributes[j]);
                    j++;
                }
                free(node[i]->attributes);
            }
            if(node[i]->values)
            {
                int j=0;
                while(node[i]->values[j])
                {
                    free(node[i]->values[j]);
                    j++;
                }
                free(node[i]->values);
            }

            node[i]->element=NULL;
            node[i]->content=NULL;
            node[i]->attributes=NULL;
            node[i]->values=NULL;
            free(node[i]);
            node[i]=NULL;
            i++;
        }
        free(node);
    }
}


/** xml_node **OS_GetElementsbyNode(OS_XML *_lxml, xml_node *node)
 * Get the elements by node.
 */
xml_node **OS_GetElementsbyNode(const OS_XML *_lxml, const xml_node *node)
{
    unsigned int i, k =0,m;
    xml_node **ret=NULL;
    xml_node **ret_tmp=NULL;

    if(node == NULL)
    {
        m = 0;
        i = 0;
    }
    else
    {
        i = node->key;
        m = _lxml->rl[i++] + 1;
    }


    for(;i<_lxml->cur;i++)
    {
        if(_lxml->tp[i] == XML_ELEM)
        {
            if((_lxml->rl[i] == m) && (_lxml->el[i] != NULL))
            {
                unsigned int l=i+1;
                /* Allocating for xml_node ** */
                ret_tmp = (xml_node**)realloc(ret,(k+2)*sizeof(xml_node*));
                if(ret_tmp == NULL)
                    goto fail;
                ret = ret_tmp;

                /* Allocating for the xml_node * */
                ret[k] = (xml_node *)calloc(1,sizeof(xml_node));
                ret[k+1] = NULL;
                if(ret[k] == NULL)
                    goto fail;

                ret[k]->element = NULL;
                ret[k]->content = NULL;
                ret[k]->attributes = NULL;
                ret[k]->values = NULL;

                /* Getting the element */
                ret[k]->element=strdup(_lxml->el[i]);
                if(ret[k]->element == NULL)
                {
                    goto fail;
                }

                /* Getting the content */
                if(_lxml->ct[i])
                {
                    ret[k]->content=strdup(_lxml->ct[i]);
                    if(ret[k]->content == NULL)
                        goto fail;
                }
                /* Assigning the key */
                ret[k]->key = i;

                /* Getting attributes */
                while(l < _lxml->cur)
                {
                    if((_lxml->tp[l] == XML_ATTR)&&(_lxml->rl[l] == m)&&
                        (_lxml->el[l]) && (_lxml->ct[l]))
                        {
                    		char **tmp;
                    		tmp = (char**)realloc(ret[k]->attributes, (l-i+1)*sizeof(char*));
                    		if(tmp == NULL)
                    			goto fail;
                    		ret[k]->attributes = tmp;
                    		ret[k]->attributes[l-i] = NULL;
                    		tmp = (char**)realloc(ret[k]->values, (l-i+1)*sizeof(char*));
                    		if(tmp == NULL)
                    			goto fail;
                            ret[k]->values = tmp;
                            ret[k]->values[l-i] = NULL;

                            ret[k]->attributes[l-i-1]=strdup(_lxml->el[l]);
                            ret[k]->values[l-i-1] = strdup(_lxml->ct[l]);
                            if(!(ret[k]->attributes[l-i-1]) ||
                                    !(ret[k]->values[l-i-1]))
                                goto fail;
                            l++;
                        }
                    else
                    {
                        break;
                    }
                }
                k++;
                continue;
            }
        }
        if((_lxml->tp[i] == XML_ELEM)&&(m > _lxml->rl[i]))
        {
            if(node == NULL)
                continue;
            else
                break;
        }
    }

    return(ret);

    fail:
    OS_ClearNode(ret);
	return (NULL);
}


/* EOF */
