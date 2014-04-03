/*   $OSSEC, os_regex_compile.c, v0.1, 2006/01/02, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "os_regex.h"
#include "os_regex_internal.h"


/** int OSRegex_Compile(char *pattern, OSRegex *reg, int flags) v0.1
 * Compile a regular expression to be used later.
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 *      - OS_RETURN_SUBSTRING
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSRegex_Compile(const char *pattern, OSRegex *reg, int flags)
{
    size_t i = 0;
    size_t count = 0;
    int end_of_string = 0;
    int parenthesis = 0;
    unsigned prts_size = 0;
    unsigned max_prts_size = 0;

    char *pt;
    char *new_str;
    char *new_str_free = NULL;


    /* Checking for references not initialized */
    if(reg == NULL)
    {
        return(0);
    }


    /* Initializing OSRegex structure */
    reg->error = 0;
    reg->patterns = NULL;
    reg->flags = NULL;
    reg->prts_closure = NULL;
    reg->prts_str = NULL;
    reg->sub_strings = NULL;



    /* The pattern can't be null */
    if(pattern == NULL)
    {
        reg->error = OS_REGEX_PATTERN_NULL;
        goto compile_error;
    }

    /* Maximum size of the pattern */
    if(strlen(pattern) > OS_PATTERN_MAXSIZE)
    {
        reg->error = OS_REGEX_MAXSIZE;
        goto compile_error;
    }


    /* Duping the pattern for our internal work */
    new_str = strdup(pattern);
    if(!new_str)
    {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }
    new_str_free = new_str;
    pt = new_str;


    /* Getting the number of sub patterns */
    do
    {
        if(*pt == BACKSLASH)
        {
            pt++;
            /* Giving the new values for each regex */
            switch(*pt)
            {
                case 'd': *pt = 1;break;
                case 'w': *pt = 2;break;
                case 's': *pt = 3;break;
                case 'p': *pt = 4;break;
                case '(': *pt = 5;break;
                case ')': *pt = 6;break;
                case '\\':*pt = 7;break;
                case 'D': *pt = 8;break;
                case 'W': *pt = 9;break;
                case 'S': *pt = 10;break;
                case '.': *pt = 11;break;
                case 't': *pt = 12;break;
                case '$': *pt = 13;break;
                case '|': *pt = 14;break;
                case '<': *pt = 15;break;
                default:
                    reg->error = OS_REGEX_BADREGEX;
                    goto compile_error;
            }
            pt++;

            continue;
        }
        else if(*pt == '(')
        {
            parenthesis++;
        }
        else if(*pt == ')')
        {
            /* Internally, open and closed are the same */
            *pt = '(';
            parenthesis--;
            prts_size++;
        }

        /* We only allow one level of parenthesis */
        if(parenthesis != 0 && parenthesis != 1)
        {
            reg->error = OS_REGEX_BADPARENTHESIS;
            goto compile_error;
        }

        /* The pattern must be always lower case if
         * case sensitive is set
         */
        if(!(flags & OS_CASE_SENSITIVE))
        {
            *pt = (char) charmap[(uchar)*pt];
        }

        if(*pt == OR)
        {
            /* Each sub pattern must be closed on parenthesis */
            if(parenthesis != 0)
            {
                reg->error = OS_REGEX_BADPARENTHESIS;
                goto compile_error;
            }
            count++;
        }
        pt++;
    }while(*pt != '\0');


    /* After the whole pattern is read, the parenthesis must all be closed */
    if(parenthesis != 0)
    {
        reg->error = OS_REGEX_BADPARENTHESIS;
        goto compile_error;
    }


    /* Allocating the memory for the sub patterns */
    count++;
    reg->patterns = (char **) calloc(count +1, sizeof(char *));
    reg->flags = (int *) calloc(count +1, sizeof(int));

    /* Memory allocation error check */
    if(!reg->patterns || !reg->flags)
    {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }


    /* For the substrings */
    if((prts_size > 0) && (flags & OS_RETURN_SUBSTRING))
    {
        reg->prts_closure = (const char ***) calloc(count +1, sizeof(const char **));
        reg->prts_str = (const char ***) calloc(count +1, sizeof(const char **));
        if(!reg->prts_closure || !reg->prts_str)
        {
            reg->error = OS_REGEX_OUTOFMEMORY;
            goto compile_error;
        }
    }


    /* Initializing each sub pattern */
    for(i = 0; i<=count; i++)
    {
        reg->patterns[i] = NULL;
        reg->flags[i] = 0;

        /* The parenthesis closure if set */
        if(reg->prts_closure)
        {
            reg->prts_closure[i] = NULL;
            reg->prts_str[i] = NULL;
        }
    }
    i = 0;


    /* Reassigning pt to the beginning of the string */
    pt = new_str;


    /* Getting the sub patterns */
    do
    {
        if((*pt == OR) || (*pt == '\0'))
        {
            if(*pt == '\0')
            {
                end_of_string = 1;
            }

            *pt = '\0';

            /* If string starts with ^, set the BEGIN SET flag */
            if(*new_str == BEGINREGEX)
            {
                new_str++;
                reg->flags[i]|=BEGIN_SET;
            }

            /* If string ends with $, set the END_SET flag */
            if(*(pt-1) == ENDREGEX)
            {
                *(pt-1) = '\0';
                reg->flags[i]|=END_SET;
            }

            reg->patterns[i] = strdup(new_str);

            if(!reg->patterns[i])
            {
                reg->error = OS_REGEX_OUTOFMEMORY;
                goto compile_error;

            }


            /* Setting the parenthesis closures */
            /* The parenthesis closure if set */
            if(reg->prts_closure)
            {
                unsigned tmp_int = 0;
                char *tmp_str;


                /* search the whole pattern for parenthesis */
                prts_size = 0;

                /* First loop we get the number of parenthesis.
                 * We allocate the memory and loop again setting
                 * the parenthesis closures.
                 */
                tmp_str = reg->patterns[i];
                while(*tmp_str != '\0')
                {
                    if(prts(*tmp_str))
                    {
                        prts_size++;
                    }
                    tmp_str++;
                }

                /* Getting the maximum number of parenthesis for
                 * all sub strings. We need that to set up the maximum
                 * number of substrings to be returned.
                 */
                if(max_prts_size < prts_size)
                {
                    max_prts_size = prts_size;
                }

                /* Allocating the memory */
                reg->prts_closure[i] = (const char **) calloc(prts_size + 1, sizeof(const char *));
                reg->prts_str[i] = (const char **) calloc(prts_size + 1, sizeof(const char *));
                if((reg->prts_closure[i] == NULL)||(reg->prts_str[i] == NULL))
                {
                    reg->error = OS_REGEX_OUTOFMEMORY;
                    goto compile_error;
                }

                /* Next loop to set the closures */
                tmp_str = reg->patterns[i];
                while(*tmp_str != '\0')
                {
                    if(prts(*tmp_str))
                    {
                        if(tmp_int >= prts_size)
                        {
                            reg->error = OS_REGEX_BADPARENTHESIS;
                            goto compile_error;
                        }

                        /* Setting to the pointer to the string */
                        reg->prts_closure[i][tmp_int] = tmp_str;
                        reg->prts_str[i][tmp_int] = NULL;

                        tmp_int++;
                    }

                    tmp_str++;
                }
            }


            if(end_of_string)
            {
                break;
            }

            new_str = ++pt;
            i++;
            continue;
        }
        pt++;

    }while(!end_of_string);

    /* Allocating sub string for the maximum number of parenthesis */
    reg->sub_strings = (char **) calloc(max_prts_size + 1, sizeof(char *));
    if(reg->sub_strings == NULL)
    {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }

    /* Success return */
    free(new_str_free);
    return(1);


    /* Error handling */
    compile_error:

    if(new_str_free)
    {
        free(new_str_free);
    }

    OSRegex_FreePattern(reg);

    return(0);
}


/* EOF */
