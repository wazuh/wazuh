/*   $OSSEC, os_xml_node_access.c, v0.3, 2005/02/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml C Library.
 * Available at http://www.ossec.net/c/os_xml/
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_xml.h"


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
                free(node[i]->element);
            if(node[i]->content)
                free(node[i]->content);
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
        node=NULL;
    }
}


/* OS_GetElementsbyNode: v0.1: 2005/03/01
 * Get the elements by node
 */
xml_node **OS_GetElementsbyNode(OS_XML *_lxml, xml_node *node)
{
    int i,j,k=0;
    xml_node **ret=NULL;

    if(node == NULL)
    {
        j=-1;
        i=0;
    }
    else
    {
        i = node->key;
        j = _lxml->rl[i++];
    }
        
            
    for(;i<_lxml->cur;i++)
    {
        if(_lxml->tp[i] == XML_ELEM)
        {
            if((_lxml->rl[i] == j+1) && (_lxml->el[i] != NULL))
            {
                int l=i+1;
                /* Allocating for xml_node ** */
                ret = (xml_node**)realloc(ret,(k+1)*sizeof(xml_node*));
                if(ret == NULL)
                    return(NULL);
                    
                /* Allocating for the xml_node * */
                ret[k] = (xml_node *)calloc(1,sizeof(xml_node));
                if(ret[k] == NULL)
                    return(NULL);
    
                ret[k]->element=NULL;
                ret[k]->content=NULL;
                ret[k]->attributes=NULL;
                ret[k]->values=NULL;
                                
                /* Getting the element */
                ret[k]->element=strdup(_lxml->el[i]);
                if(ret[k]->element == NULL)
                {
                    free(ret);
                    return(NULL);
                }
                
                /* Getting the content */
                if(_lxml->ct[i])
                {
                    ret[k]->content=strdup(_lxml->ct[i]);
                    if(ret[k]->content == NULL)
                        return(NULL);
                }
                /* Assigning the key */
                ret[k]->key=i;

                /* Getting attributes */
                while(1)
                {
                    if((_lxml->tp[l] == XML_ATTR)&&(_lxml->rl[l] == j+1)&&
                        (_lxml->el[l]) && (_lxml->ct[l]))
                        {
                            ret[k]->attributes = 
                                (char**)realloc(ret[k]->attributes,
                                                (l-i+1)*sizeof(char*));
                            ret[k]->values = 
                                (char**)realloc(ret[k]->values,
                                                (l-i+1)*sizeof(char*));
                            if(!(ret[k]->attributes) || 
                                    !(ret[k]->values))
                                return(NULL);
                            ret[k]->attributes[l-i-1]=strdup(_lxml->el[l]);
                            ret[k]->values[l-i-1] = strdup(_lxml->ct[l]);
                            if(!(ret[k]->attributes[l-i-1]) ||
                                    !(ret[k]->values[l-i-1]))
                                return(NULL);
                            l++;                    
                        }
                    else
                        break;
                }
                if(ret[k]->attributes)
                {
                    ret[k]->attributes[l-i-1]=NULL;
                    ret[k]->values[l-i-1]=NULL;
                }
                k++;
                continue;
            }
        }
        if((_lxml->tp[i] == XML_ELEM)&&(j+1 > _lxml->rl[i]))
        {
            if(j == -1)
                continue;
            else
                break;
        }
    }
    
    if(ret ==NULL)
        return(NULL);

    ret = (xml_node **)realloc(ret,(k+1)*sizeof(xml_node *));
    if(ret == NULL)
        return(NULL);
    ret[k]=NULL;
    return(ret);
}

/* EOF */
