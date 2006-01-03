/*   $OSSEC, os_regex.c, v0.3, 2005/04/05, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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

#include "os_regex.h"
#include "os_regex_internal.h"


/** Internal prototypes **/
int _OS_Regex(char *pattern, char *str, char **prts_closure,
              char **prts_str, int flags);



/** int OSRegex_Execute(char *str, OSRegex *reg) v0.1
 * Compare an already compiled regular expression with
 * a not NULL string.
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSRegex_Execute(char *str, OSRegex *reg)
{
    int i = 0;
    
    /* The string can't be NULL */
    if(str == NULL)
    {
        reg->error = OS_REGEX_STR_NULL;
        return(0);
    }


    /* If we need the sub strings */
    if(reg->prts_closure)
    {
        int j = 0, k = 0, str_char = 0;

        /* Looping on all sub patterns */
        while(reg->patterns[i])
        {
            /* Cleaning the prts_str */
            while(reg->prts_closure[i][j])
            {
                reg->prts_str[i][j] = NULL;
                j++;
            }

            if(_OS_Regex(reg->patterns[i], str, reg->prts_closure[i],
                        reg->prts_str[i], reg->flags[i]))
            {
                j = 0;

                /* We must always have the open and the close */
                while(reg->prts_str[i][j] && reg->prts_str[i][j+1])
                {
                    str_char = reg->prts_str[i][j+1][0];

                    reg->prts_str[i][j+1][0] = '\0';

                    reg->sub_strings[k] = strdup(reg->prts_str[i][j]);
                    if(!reg->sub_strings[k])
                    {
                        OSRegex_FreeSubStrings(reg);
                        return(0);
                    }
                    
                    /* Set the next one to null */
                    reg->prts_str[i][j+1][0] = str_char;
                    k++;
                    reg->sub_strings[k] = NULL;

                    /* Go two by two */
                    j+=2;
                }

                return(1);
            }
            i++;
        }

        reg->error = OS_REGEX_NO_MATCH;
        return(0);

    }
   
    /* If we don't need the sub strings */
     
    /* Looping on all sub patterns */
    while(reg->patterns[i])
    {
        if(_OS_Regex(reg->patterns[i], str, NULL, NULL, reg->flags[i])) 
        {
            return(1);
        }
        i++;
    }

    reg->error = OS_REGEX_NO_MATCH;
    return(0);
}    



/** int _OS_Regex(char *pattern, char *str, char **prts_closure,
              char **prts_str, int flags) v0.1
 * Perform the pattern matching on the pattern/string provided.
 * Returns 1 on success and 0 on failure.
 * If prts_closure is set, the parenthesis locations will be
 * written on prts_str (which must not be NULL)
 */              
int _OS_Regex(char *pattern, char *str, char **prts_closure, 
              char **prts_str, int flags)
{
    int r_code = 0;
    
    int ok_here;
    int _regex_matched = 0;
    
    int prts_int;

    char *st = str;
    char *st_error = NULL;
    
    char *pt = pattern;
    char *next_pt;

    char *pt_error[4] = {NULL, NULL, NULL, NULL};
    char *pt_error_str[4] = {NULL, NULL, NULL, NULL};
    

    /* Will loop the whole string, trying to find a match */
    do
    {
        if(*pt == '\0')
        {
            return(r_code);
        }

        /* If it is a parenthesis do not match against the character */
        else if(prts(*pt))
        {
            /* Find the closure for the parenthesis */
            if(prts_closure)
            {
                prts_int = 0;
                while(prts_closure[prts_int])
                {
                    if(prts_closure[prts_int] == pt)
                    {
                        prts_str[prts_int] = st;
                    }
                    prts_int++;
                }
            }
            
            pt++;
            st--;

            continue;
        }

        /* If it starts on Backslash (future regex) */
        else if(*pt == BACKSLASH)
        {
            if(Regex(*(pt+1), *st))
            {
                next_pt = pt+2;
                
                /* If we don't have a '+' or '*', we should skip
                 * searching using this pattern.
                 */
                if(!isPlus(*next_pt))
                {
                    pt = next_pt;
                    if(!st_error)
                    {
                        /* If st_error is not set, we need to set it here.
                         * In case of error in the matching later, we need
                         * to continue from here (it will be incremented in
                         * the while loop)
                         */
                        st_error = st;
                    }
                    r_code = 1;
                    continue;
                }
                
                /* If it is a '*', we need to set the _regex_matched
                 * for the first pattern even.
                 */
                if(*next_pt == '*')
                {
                    _regex_matched = 1;
                }


                /* If our regex matches and we have a "+" set, we will
                 * try the next one to see if it matches. If yes, we 
                 * can jump to it, but saving our currently location
                 * in case of error.
                 * _regex_matched will set set to true after the first
                 * round of matches
                 */
                if(_regex_matched)
                {
                    next_pt++;
                    ok_here = -1;

                    /* If it is a parenthesis, jump to the next and write
                     * the location down if 'ok_here >= 0'
                     */
                    if(prts(*next_pt))
                    {
                        next_pt++;
                    }

                    if(*next_pt == BACKSLASH)
                    {
                        if(Regex(*(next_pt+1), *st))
                        {
                            /* If the next one does not have
                             * a '+' or '*', we can set it as
                             * being read anc continue.
                             */
                            if(!isPlus(*(next_pt+2)))
                            {
                                ok_here = 2;
                            }
                            else
                            {
                                ok_here = 0;
                            }
                        }
                    }
                    else if(*next_pt == '\0')
                    {
                        ok_here = 1;
                    }
                    else if(*next_pt == charmap[(uchar)*st])
                    {
                        _regex_matched = 0;
                        ok_here = 1;
                    }

                    /* If the next character matches in here */
                    if(ok_here >= 0)
                    {
                        if(prts(*(next_pt - 1)) && prts_closure)
                        {
                            prts_int = 0;
                            while(prts_closure[prts_int])
                            {
                                if(prts_closure[prts_int] == (next_pt -1))
                                {
                                    prts_str[prts_int] = st;
                                }
                                prts_int++;
                            }
                        }


                        /* If next_pt == \0, return the r_code */
                        if(*next_pt == '\0')
                            return(r_code);

                            
                        /* Each "if" will increment the amount
                         * necessary for the next pattern in ok_here
                         */
                        if(ok_here) 
                            next_pt+=ok_here;
                        
                        
                        if(!pt_error[0])
                        {
                            pt_error[0] = pt;
                            pt_error_str[0] = st;
                        }
                        else if(!pt_error[1])
                        {
                            pt_error[1] = pt;
                            pt_error_str[1] = st;
                        }
                        else if(!pt_error[2])
                        {
                            pt_error[2] = pt;
                            pt_error_str[2] = st;

                        }
                        else if(!pt_error[3])
                        {
                            pt_error[3] = pt;
                            pt_error_str[3] = st;
                        }

                        pt = next_pt;
                    }
                }
                else
                {
                    _regex_matched = 1;
                }
                
                r_code = 1;

                continue;
            }
            
            /* If we didn't match regex, but _regex_matched == 1, jump
             * to the next available pattern
             */
            else if(isPlus(*(pt+2)) && _regex_matched == 1)
            {
                pt+=3;
                st--;
                _regex_matched = 0;
                continue;
            }
            /* We may not match with '*' */
            else if(*(pt+2) == '*')
            {
                pt+=3;
                st--;
                r_code = 1;
                _regex_matched = 0;
                continue;
            }
            else
            {
                _regex_matched = 0;
            }
        }
        else if(*pt == charmap[(uchar)*st])
        {
            pt++;
            if(!st_error)
            {
                /* If st_error is not set, we need to set it here.
                 * In case of error in the matching later, we need
                 * to continue from here (it will be incremented in
                 * the while loop)
                 */
                st_error = st;
            }
            r_code = 1;
            continue;
        }


        /* Error Handling */
            if(pt_error[3])
            {
                pt = pt_error[3];
                st = pt_error_str[3];
                pt_error[3] = NULL;
                continue;
            }
            else if(pt_error[2])
            {
                pt = pt_error[2];
                st = pt_error_str[2];
                pt_error[2] = NULL;
                continue;
            }
            else if(pt_error[1])
            {
                pt = pt_error[1];
                st = pt_error_str[1];
                pt_error[1] = NULL;
                continue;
            }
            else if(pt_error[0])
            {
                pt = pt_error[0];
                st = pt_error_str[0];
                pt_error[0] = NULL;
                continue;
            }
            else if(flags & BEGIN_SET)
            {
                /* If we get an error and the "^" option is
                 * set, we can return "not matched" in here.
                 */
                return(0);
            }
            else if(st_error)
            {
                st = st_error;
                st_error = NULL;
            }
            pt = pattern;
            r_code = 0;
        
    }while(*(++st) != '\0');

    if((*pt == '\0')||
       (*pt == BACKSLASH && _regex_matched && 
       isPlus(*(pt+2)) && ((*(pt+3) == '\0')||(*(pt+3) == ENDREGEX)))||
       (*pt == ENDREGEX))
    {
        return(r_code);
    }
   
    return(0);
}


/* EOF */
