/*   $OSSEC, os_regex.c, v0.3, 2005/04/05, Daniel B. Cid$   */

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

#include "os_regex.h"
#include "os_regex_internal.h"


/** Internal prototypes **/
static const char *_OS_Regex(const char *pattern, const char *str, const char **prts_closure,
        const char **prts_str, int flags) __attribute__((nonnull(1,2)));



/** char *OSRegex_Execute(char *str, OSRegex *reg) v0.1
 * Compare an already compiled regular expression with
 * a not NULL string.
 * Returns the end of the string on success or NULL on error.
 * The error code is set on reg->error.
 */
const char *OSRegex_Execute(const char *str, OSRegex *reg)
{
    const char *ret;
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
        int k = 0;

        /* Looping on all sub patterns */
        while(reg->patterns[i])
        {
            /* Cleaning the prts_str */
            int j = 0;
            while(reg->prts_closure[i][j])
            {
                reg->prts_str[i][j] = NULL;
                j++;
            }

            if((ret = _OS_Regex(reg->patterns[i], str, reg->prts_closure[i],
                        reg->prts_str[i], reg->flags[i])))
            {
                j = 0;

                /* We must always have the open and the close */
                while(reg->prts_str[i][j] && reg->prts_str[i][j+1])
                {
                    size_t length = (size_t) (reg->prts_str[i][j+1] - reg->prts_str[i][j]);
                    reg->sub_strings[k] = (char *) malloc((length + 1) * sizeof(char));
                    if(!reg->sub_strings[k])
                    {
                        OSRegex_FreeSubStrings(reg);
                        return(NULL);
                    }
                    strncpy(reg->sub_strings[k], reg->prts_str[i][j], length);
                    reg->sub_strings[k][length] = '\0';

                    /* Set the next one to null */
                    k++;
                    reg->sub_strings[k] = NULL;

                    /* Go two by two */
                    j+=2;
                }

                return(ret);
            }
            i++;
        }

        return(0);

    }

    /* If we don't need the sub strings */

    /* Looping on all sub patterns */
    while(reg->patterns[i])
    {
        if((ret = _OS_Regex(reg->patterns[i], str, NULL, NULL, reg->flags[i])))
        {
            return(ret);
        }
        i++;
    }

    return(NULL);
}

#define PRTS(x) ((prts(*x) && x++) || 1)
#define ENDOFFILE(x) ( PRTS(x) && (*x == '\0'))

/** int _OS_Regex(char *pattern, char *str, char **prts_closure,
              char **prts_str, int flags) v0.1
 * Perform the pattern matching on the pattern/string provided.
 * Returns 1 on success and 0 on failure.
 * If prts_closure is set, the parenthesis locations will be
 * written on prts_str (which must not be NULL)
 */
static const char *_OS_Regex(const char *pattern, const char *str, const char **prts_closure,
        const char **prts_str, int flags)
{
    const char *r_code = NULL;

    int ok_here;
    int _regex_matched = 0;

    int prts_int;

    const char *st = str;
    const char *st_error = NULL;

    const char *pt = pattern;
    const char *next_pt;

    const char *pt_error[4] = {NULL, NULL, NULL, NULL};
    const char *pt_error_str[4] = {NULL, NULL, NULL, NULL};


    /* Will loop the whole string, trying to find a match */
    do
    {
        switch(*pt)
        {
            case '\0':
                if(!(flags & END_SET) || ((flags & END_SET) && (*st == '\0')))
                    return(r_code);
                break;

                /* If it is a parenthesis do not match against the character */
            case '(':
                /* Find the closure for the parenthesis */
                if(prts_closure)
                {
                    prts_int = 0;
                    while(prts_closure[prts_int])
                    {
                        if(prts_closure[prts_int] == pt)
                        {
                            prts_str[prts_int] = st;
                            break;
                        }
                        prts_int++;
                    }
                }

                pt++;
                if(*pt == '\0')
                {
                    if(!(flags & END_SET) || ((flags & END_SET) && (*st == '\0')))
                        return(r_code);
                }
                break;
            default:
                break; /* do nothing */
        }

        /* If it starts on Backslash (future regex) */
        if(*pt == BACKSLASH)
        {
            if(Regex((uchar)*(pt+1), (uchar)*st))
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
                    r_code = st;
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

                    if(*next_pt == '\0')
                    {
                        ok_here = 1;
                    }
                    else if(*next_pt == BACKSLASH)
                    {
                        if(Regex((uchar)*(next_pt+1), (uchar)*st))
                        {
                            /* If the next one does not have
                             * a '+' or '*', we can set it as
                             * being read and continue.
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
                    else if(*next_pt == charmap[(uchar)*st])
                    {
                        _regex_matched = 0;
                        ok_here = 1;
                    }

                    /* If the next character matches in here */
                    if(ok_here >= 0)
                    {
                        if(prts_closure && prts(*(next_pt - 1)))
                        {
                            prts_int = 0;
                            while(prts_closure[prts_int])
                            {
                                if(prts_closure[prts_int] == (next_pt -1))
                                {
                                    if(*(st+1) == '\0')
                                        prts_str[prts_int] = st+1;
                                    else
                                        prts_str[prts_int] = st;
                                    break;
                                }
                                prts_int++;
                            }
                        }


                        /* If next_pt == \0, return the r_code */
                        if(*next_pt == '\0')
                        {
                            continue;
                        }


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
                    next_pt++;

                    /* If it is a parenthesis, mark the location */
                    if(prts_closure && prts(*next_pt))
                    {
                        prts_int = 0;
                        while(prts_closure[prts_int])
                        {
                            if(prts_closure[prts_int] == next_pt)
                            {
                                if(*(st+1) == '\0')
                                    prts_str[prts_int] = st +1;
                                else
                                    prts_str[prts_int] = st;
                                break;
                            }
                            prts_int++;
                        }
                        next_pt++;
                    }

                    _regex_matched = 1;
                }

                r_code = st;
                continue;
            }

            else if((*(pt+3) == '\0') && (_regex_matched == 1)&&(r_code))
            {
                r_code = st;
                if(!(flags & END_SET) || ((flags & END_SET) && (*st == '\0')))
                    return(r_code);
            }

            /* If we didn't match regex, but _regex_matched == 1, jump
             * to the next available pattern
             */
            else if((*(pt+2) == '+') && (_regex_matched == 1))
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
                r_code = st;
                _regex_matched = 0;
                continue;
            }

            _regex_matched = 0;
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
            r_code = st;
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
                return(NULL);
            }
            else if(st_error)
            {
                st = st_error;
                st_error = NULL;
            }
            pt = pattern;
            r_code = NULL;

    }while(*(++st) != '\0');


    /* Matching for a possible last parenthesis */
    if(prts_closure)
    {
        while(!prts(*pt) && *pt != '\0')
        {
            if(*pt == BACKSLASH && *(pt+2) == '*')
                pt+=3;
            else
                break;
        }

        if(prts(*pt))
        {
            prts_int = 0;
            while(prts_closure[prts_int])
            {
                if(prts_closure[prts_int] == pt)
                {
                    prts_str[prts_int] = st;
                    break;
                }
                prts_int++;
            }
        }
    }

    /* Cleaning up */
    if(ENDOFFILE(pt) ||
        (*pt == BACKSLASH &&
        _regex_matched &&
        (pt+=2) &&
        isPlus(*pt) &&
        (pt++) &&
        ((ENDOFFILE(pt)) ||
        ((*pt == BACKSLASH) &&
        (pt+=2) &&
        (*pt == '*') &&
        (pt++) &&
        (ENDOFFILE(pt)) ))) ||
        (*pt == BACKSLASH &&
        (pt+=2) &&
        (*pt == '*') &&
        (pt++) &&
        ENDOFFILE(pt))
        )
    {
        return(r_code);
    }

    return(NULL);
}


/* EOF */
