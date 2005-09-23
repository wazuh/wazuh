/*   $OSSEC, os_xml_node_variables.c, v0.3, 2005/04/12, Daniel B. Cid$   */

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

int OS_ApplyVariables(OS_XML *_lxml)
{
    int i = 0,j = 0,s = 0;
    char **var = NULL;
    char **value = NULL;

    for(;i<_lxml->cur;i++)
    {
        if(_lxml->tp[i] == XML_VARIABLE_BEGIN)
        {
            int _found_var = 0;
            j = i+1;
            for(;j<_lxml->cur;j++)
            {
                if(_lxml->rl[j] < _lxml->rl[i])
                    break;
                else if(_lxml->tp[j] == XML_ATTR)
                {
                    if((_lxml->el[j])&&(strcasecmp(_lxml->el[j],"name") == 0))
                    {
                        if(!_lxml->ct[j])
                            break;
                
                        /* If not used, it will be cleaned latter */        
                        sprintf(_lxml->err,"XML_ERR: Memory error");
                            
                        var = (char**)realloc(var,(s+1)*sizeof(char *));
                        if(var == NULL)
                            return (-1);
                        
                        var[s] = (char*)calloc(strlen(_lxml->ct[j])+1,
                                                            sizeof(char));
                        if(var[s] == NULL)
                            return (-1);
                        
                        strcpy(var[s],_lxml->ct[j]);
                       
                        /* Cleaning the lxml->err */ 
                        strcpy(_lxml->err," ");

                        _found_var = 1;
                        break;
                    }
                    else
                    {
                        sprintf(_lxml->err,"XML_ERR: Only \"name\" is allowed"
                                           " as an attribute for a variable");
                        return(-1);
                    }
                }
            } /* Attribute FOR */
            
            if((_found_var == 0)||(!_lxml->ct[i]))
            {
                sprintf(_lxml->err,"XML_ERR: Bad formed variable. No value "
                                   "set");
                return(-1);
            }
            
            sprintf(_lxml->err,"XML_ERR: Memory error");
        
            value = (char**)realloc(value,(s+1)*sizeof(char *));
            if (value == NULL)
                return(-1);
        
            value[s] = (char*)calloc(strlen(_lxml->ct[i])+1,sizeof(char));
            if(value[s] == NULL)
                return(-1);    
        
            strcpy(_lxml->err," ");
            strcpy(value[s],_lxml->ct[i]);    
            s++;
        }
    } /* initial FOR to get the variables  */
  
    /* No variable */
    if(s == 0)
        return(0);

             
    /* Looping again and modifying where found the variables */
    i = 0; 
    for(;i<_lxml->cur;i++)
    {
        if((_lxml->tp[i] == XML_ELEM)&&(_lxml->ct[i]))
        {
            int tp=0,init=0,final=0;
            char *p = NULL;
            char *p2= NULL;
            char lvar[256]; /* MAX Var size */
          
            if(strlen(_lxml->ct[i]) <= 2)
                continue;
            
            
            /* Duplicating string */     
            p = strdup(_lxml->ct[i]);
            p2= p;
            
            if(p == NULL)
            {
                sprintf(_lxml->err,"XML_ERR: Memory error");
                return(-1);
            }
            
            /* Reading the whole string */
            while(*p != '\0')
            {
                if(*p == XML_VARIABLE_BEGIN)
                {
                    p++;
                    memset(lvar,'\0',256);
                    
                    while(1)
                    {
                        if((*p == XML_VARIABLE_BEGIN)
                            ||(*p == '\0')
                            ||(*p == '.')
                            ||(*p == ' '))
                        {
                            lvar[tp]='\0';

                            final = init+tp;
                            
                            /* Looking for var */
                            for(j=0;j<s;j++)
                            {
                                if(var[j] == NULL)
                                    break;
                                if(strcasecmp(var[j],lvar) == 0)
                                {
                                    /* Found var */
                                    int l=0,m=0;
                                    int tsize= strlen(_lxml->ct[i])+
                                               strlen(value[j])-tp+1; 
                                    
                                    _lxml->ct[i] = (char*)
                                                    realloc(_lxml->ct[i],
                                                    tsize*sizeof(char));
                                    
                                    if(_lxml->ct[i] == NULL)
                                    {
                                        sprintf(_lxml->err,"XML_ERR: Memory "
                                                        "error");
                                        return(-1);
                                    }
                                    
                                    _lxml->ct[i][init]='\0';
                                    strncat(_lxml->ct[i], value[j],tsize-init);
                                    
                                    _lxml->ct[i][tsize-init-1]='\0';
                                    m=tsize-init-1;
                                    
                                    l=final+1;
                                    
                                    for(;l<strlen(p2);l++)
                                    {
                                        _lxml->ct[i][m]=p[l];
                                        if(m >= tsize)
                                        {
                                            break;
                                        }
                                        m++;
                                    }
                                    _lxml->ct[i][m]='\0';
                                    break;
                                }
                            }
                            tp = 0;
                            init = 0;
                            final = 0;
                            break;
                        }
                        lvar[tp] = *p;
                        tp++;
                        p++;
                    }
                } /* IF XML_VAR_BEGIN */
                p++;
                init++;
            } /* WHILE END */
            
            if(p2 != NULL)
            {
                free(p2);
                p2 = NULL;
                p = NULL;
            }
        }
    }

    /* Cleaning the variables */
    for(i=0;i<s;i++)
    {
        if((var)&&(var[i]))
        {
            free(var[i]);
            var[i] = NULL;
        }
        if((value)&&(value[i]))
        {
            free(value[i]);    
            value[i] = NULL;
        }
    }
    
    if(var != NULL)
    {
        free(var);
        var = NULL;
    }
    if(value != NULL)
    {
        free(value);    
        value = NULL;
    }
return(0);
}

/* UFA :) or EOF */
