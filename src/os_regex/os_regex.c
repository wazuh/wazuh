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
#include "os_regex_internal.h"

/** Prototypes **/
int _OS_Regex(char *jc, char *str, int *init, int last_char,
                        int *parenthesis);


int OS_Regex(char *pattern, char *str)
{
    int count = 0;

    char *pt = pattern;

    if((pattern == NULL) || (str == NULL))
        return(FALSE);
    
    do
    {
        if(*pt == OR)
        {
            if(_OS_Regex(pattern, str,NULL,*pt,NULL))
                return(TRUE);
            
            pattern = ++pt;
            count = 0;
            continue;    
            /*j=i+1;*/            
        }
        pt++;
        count++;
        
    }while(*pt != '\0');
   
    if(_OS_Regex(pattern,str, NULL, *pt,NULL))
    {
        return(TRUE);
    }
    
    return(FALSE);     
}

int _OS_Regex(char *pattern, char *str, int *init, int last_char,
              int  *parenthesis)
{
    uchar *st = (uchar *)str;
    uchar *pt = (uchar *)pattern;
   
    int tmp_pt = 0;
    
    int err_st = 0;
    int err_re = 0;
    int str_pt = 0;
     
    int pt_init = FALSE;

    /* Position in the strings */
    int _st = 0;
    int _pt = 0;
   
     
    /* Setting up the initial maching point */
    if(init)
    {
        *init = 0;
    }
    
    /* If start with '^', go to next char
     * and set pt_init to TRUE
     */
    if(*pt == BEGINREGEX)
    {
        pt_init = TRUE;
        pattern = (char *)++pt;
    }

    if(*st == '\0')
    {
        return(0);
    }    
    
    /* Will loop str, looking for the pattern */ 
    do
    {
        if(pt[_pt] == last_char)
        {
            return(_st);
        }
        
        else if(parenthesis && prts(pt[_pt]))
        {
            parenthesis[_pt] = _st;
            _pt++;
            _st--;
            continue;
        }
        
        else if(pt[_pt] == BACKSLASH)
        {
            /* If '\\' */
            _pt++;
            if(pt[_pt] == BACKSLASH)
            {
                if(st[_st] == BACKSLASH)
                {
                    _pt++;
                    continue;
                }
                goto error;
            }
            
            else if(pt[_pt] == last_char)
            {
                return(0); /* Bad formed regex */
            }
            
            /* Going to the regex checks */   
            else if(Regex(pt[_pt],st[_st]))
            {
                /* If we have nothing else, return TRUE */
                _pt++;    
                if(pt[_pt] == last_char)
                {
                    return(_st);
                }
                
                else if(parenthesis && prts(pt[_pt]))
                {
                    parenthesis[_pt] = _st+1;
                    _pt++;
                    goto new;
                }
                
                else if((pt[_pt] == '+')||(pt[_pt] == '*'))
                {
                    tmp_pt = _pt - 1;
                    _pt++;

                    do
                    {
                        _st++;

                        if(pt[_pt] == last_char)
                        {
                            return(--_st);
                        }

                        
                        else if(st[_st] == '\0')
                        {
                            /* If the string finished and
                             * the pattern is now '$', return true
                             */
                            if(pt[_pt] == ENDREGEX)
                            {
                                if(parenthesis && prts(pt[_pt-1]))
                                {
                                    parenthesis[_pt-1] = _st;
                                }
                                return(_st);
                            }
                            return(0);
                        }
                        
                        if(parenthesis)
                        {
                            if(prts(pt[_pt]))
                            {
                                parenthesis[_pt] = _st;
                                _pt++;
                            }
                            /* We can't use prts here. We don't know
                             * what was the previous character
                             */
                            else if(prts(pt[_pt-1]))
                            {
                                parenthesis[_pt-1] = _st;
                            }
                        }

                        if(pt[_pt] == BACKSLASH)
                        {
                            if(Regex(pt[_pt+1],st[_st]))
                            {
                                /* If the next regex matches the currently
                                 * word and the present one also, save the
                                 * present one in case of future error
                                 */
                                if(Regex(pt[tmp_pt],st[_st]))
                                {
                                    if(!(err_re) && !(err_st))
                                    {
                                        err_re = tmp_pt-1;
                                        err_st = _st+1;
                                    }
                                }

                                tmp_pt = ++_pt;
                                _pt++;
                                if((pt[_pt] == '+')||(pt[_pt] == '*'))
                                    _pt++;

                                else if(pt[_pt] == last_char)
                                {
                                    return(_st);   
                                } 

                                /* New regex has no + or *,
                                 * so we need to get out of this
                                 * loop.
                                 */
                                else
                                {
                                    goto new;
                                }
                            }
                           
                            else if(parenthesis && (pt[_pt-1] == '('))
                            {
                                _pt--;
                            }
                            
                            else if(pt[_pt+1] == last_char)
                            {
                                return(0);
                            }
                        }
                        else if(charmap[pt[_pt]] == charmap[st[_st]])
                        {
                            /* Leave regex */
                            if(Regex(pt[tmp_pt],st[_st]))
                            {
                                if(!(err_re) && !(err_st))
                                {
                                    err_re = tmp_pt-1;
                                    err_st = _st+1;
                                }
                            }

                            _pt++;
                            goto new;
                        }


                    }while(Regex(pt[tmp_pt],st[_st]));

                    if(pt[tmp_pt+1] == '*')
                    {
                        _st--;
                        /* Bug 1101 -- su\S*: not matching su: */
                        if(charmap[pt[_pt]] == charmap[st[_st]])
                        {
                            _pt++;
                        }
                        goto new;
                    }


                    goto error;
                }

                /* Going to next character */
                else 
                {
                    continue;
                }
            }
            else
            {
                if(pt[_pt+1] == '*')
                {
                    _pt+=2;
                    _st--;
                    continue;
                }
                
                /* _st--; */   
                goto error;
            }
        }
        
        /* If it is not a expression, check if matches the character */
        else if(charmap[st[_st]] == charmap[pt[_pt]])
        {
            _pt++;
            
            if(str_pt == 0)
            {
                str_pt = _st;
            }
            
            continue;
        }
        

        /* Leaving from regex */
        error:
            
                
            /* Regex related errors */
            if(err_st)
            {
                _st = err_st;
                err_st = 0;
                _st--;
            }
            if(err_re)
            {
                _pt = err_re;
                err_re = 0;

                continue;
            }
            
            
            /* If pt_init ('^') is set, we can skip looking.
             * Return FALSE
             */
            if(pt_init == TRUE)
            {
                return(0);
            }

            
            /* String matching related errors */
            if(str_pt)
            {
                _st = str_pt;
                str_pt = 0;
            }
            
            /* Setting the initial point */
            if(init)
                *init = _st;
            
            /* If we didn't have err_st or err_re  */
            _pt = 0;
            continue;
            
        new:
            continue;
                
    }while(st[++_st] != '\0');

    /* If the pattern also finished, return TRUE */
    if((pt[_pt] == last_char)||(pt[_pt] == ENDREGEX))
    {
        return(_st);
    }
    
    /* Didn't match if we reached here */     
    return(0);
    
}
/* EOF */
