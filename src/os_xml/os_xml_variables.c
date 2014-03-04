/*   $OSSEC, os_xml_node_variables.c, v0.3, 2005/04/12, Daniel B. Cid$   */

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

int OS_ApplyVariables(OS_XML *_lxml)
{
    int i = 0,j = 0,s = 0;
    char **var = NULL;
    char **value = NULL;


    /* No variables. */
    if(!_lxml->cur)
        return(0);


    /* Getting all variables */
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
                        snprintf(_lxml->err, 128, "XML_ERR: Memory error");

                        var = (char**)realloc(var,(s+1)*sizeof(char *));
                        if(var == NULL)
                            return (-1);

                        var[s] = strdup(_lxml->ct[j]);
                        if(var[s] == NULL)
                            return(-1);

                        /* Cleaning the lxml->err */
                        strncpy(_lxml->err," ", 3);

                        _found_var = 1;
                        break;
                    }
                    else
                    {
                        snprintf(_lxml->err, 128,
                                 "XML_ERR: Only \"name\" is allowed"
                                 " as an attribute for a variable");
                        return(-1);
                    }
                }
            } /* Attribute FOR */


            if((_found_var == 0)||(!_lxml->ct[i]))
            {
                snprintf(_lxml->err,128,
                         "XML_ERR: Bad formed variable. No value set");
                return(-1);
            }


            snprintf(_lxml->err,128, "XML_ERR: Memory error");

            value = (char**)realloc(value,(s+1)*sizeof(char *));
            if (value == NULL)
                return(-1);

            value[s] = strdup(_lxml->ct[i]);
            if(value[s] == NULL)
                return(-1);

            strncpy(_lxml->err," ", 3);
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
        if(((_lxml->tp[i] == XML_ELEM) || (_lxml->tp[i] == XML_ATTR))&&
            (_lxml->ct[i]))
        {
            int tp = 0,init = 0;
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
                snprintf(_lxml->err, 128, "XML_ERR: Memory error");
                return(-1);
            }


            /* Reading the whole string */
            while(*p != '\0')
            {
                if(*p == XML_VARIABLE_BEGIN)
                {
                    tp = 0;
                    p++;
                    memset(lvar, '\0', 256);

                    while(1)
                    {
                        if((*p == XML_VARIABLE_BEGIN)
                            ||(*p == '\0')
                            ||(*p == '.')
                            ||(*p == '|')
                            ||(*p == ',')
                            ||(*p == ' '))
                        {
                            lvar[tp]='\0';

                            /* Looking for var */
                            for(j=0; j<s; j++)
                            {
                                int tsize = 0;

                                /* Store everything up the variable name */
                                char *var_placeh;


                                if(var[j] == NULL)
                                    break;

                                if(strcasecmp(var[j], lvar) != 0)
                                {
                                    continue;
                                }


                                tsize = strlen(_lxml->ct[i]) +
                                        strlen(value[j]) - tp + 1;

                                var_placeh = strdup(_lxml->ct[i]);

                                free(_lxml->ct[i]);

                                _lxml->ct[i] = (char*)calloc(tsize +2,
                                                             sizeof(char));

                                if(_lxml->ct[i] == NULL || var_placeh == NULL)
                                {
                                    snprintf(_lxml->err,128, "XML_ERR: Memory "
                                                             "error");
                                    return(-1);
                                }


                                strncpy(_lxml->ct[i], var_placeh, tsize);


                                _lxml->ct[i][init] = '\0';
                                strncat(_lxml->ct[i], value[j],tsize - init);


                                init = strlen(_lxml->ct[i]);
                                strncat(_lxml->ct[i], p,
                                         tsize - strlen(_lxml->ct[i]));


                                free(var_placeh);

                                break;
                            }

                            /* Variale not found */
                            if((j == s) && (strlen(lvar) >= 1))
                            {
                                snprintf(_lxml->err,128,
                                                "XML_ERR: Unknown variable"
                                                ": %s", lvar);
                                return(-1);
                            }
                            else if(j == s)
                            {
                                init++;
                            }

                            goto go_next;
                        }

                        /* Maximum size for a variable */
                        if(tp >= 255)
                        {
                            snprintf(_lxml->err,128, "XML_ERR: Invalid "
                                                     "variable size.");
                            return(-1);

                        }

                        lvar[tp] = *p;
                        tp++;
                        p++;
                    }
                } /* IF XML_VAR_BEGIN */

                p++;
                init++;

                go_next:
                continue;

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
