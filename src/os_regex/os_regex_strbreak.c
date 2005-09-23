/*   $OSSEC, os_regex_strbreak.c, v0.3, 2005/04/05, Daniel B. Cid$   */

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
/* from os_regex.c */
char *_OS_Regex(char *jc, char *str, char **init, int last_char,
                          int *parenthesis);


char **OS_RegexStr(char *pattern, char *str)
{
    int count = 0;
    
    char **ret;

    char *pt = pattern;

    /* Parenthesis open/close */
    int opened = 0;

    /* Total number of parenthesis */
    int tp_sz  = 0;
    
    /* Invalid inputs. Shouldn't be NULL */
    if((pattern == NULL)||(str == NULL))
        return(NULL);

    /* Invalid pattern */
    if(*pt == '\0')
        return(NULL);
        
    while(1) 
    {
        if((*pt == OR)||(*pt == '\0'))
        {
            int parenthesis[count+1];
        
            int i = 0;
            int j = 0;
            
            for(;i<=count;i++)
            {
                parenthesis[i] = -1;
            }
    
                    
            /* Bad REGEX */         
            if(opened != 0)
                return(NULL);
            
            if((tp_sz == 0)||
                (!_OS_Regex(pattern, str,NULL,*pt,parenthesis)))
            {
                if(*pt == '\0')
                    return(NULL);
                    
                count = 0;
                tp_sz = 0;
                pattern = ++pt;
                continue;
            }
            
            /* If we go here, is because we matched */
            ret = (char **)calloc(tp_sz+1,sizeof(char *));
            
            if(ret == NULL)
            {
                return(NULL); /* Memory error */
            }
          
            /* Cleaning the memory */
            /* use of the 'i' is safe now.. */
            i = 0; 
            while(i<=tp_sz)
            {
                ret[i] = NULL;
                i++;
            }
            
            /* Copying the content to the return array */
            i = 0;
            while(i<=count)
            {
                if(parenthesis[i] != -1)
                {
                    if(opened != 0)
                    {
                        /* Copying the content to the ret */
                        int str_size = parenthesis[i] - opened;
                        char *nstr = str;
                        
                        ret[j] = (char *)calloc(str_size+1,sizeof(char));
                        
                        /* Exiting clean */
                        if(ret[j] == NULL)
                        {
                            while(j != 0)
                            {
                                free(ret[j]);
                                j--;
                            }
                            
                            free(ret);
                            return(NULL);
                        }
                        
                        ret[j][str_size] = '\0';
                          
                        nstr+=opened;
                        
                        strncpy(ret[j],nstr,str_size);
                        j++;
                          
                        opened = 0;
                        i++;
                        continue;
                    }
                    else
                    {
                        opened=parenthesis[i];
                        i++;
                        continue;
                    }
                }
                i++;
            }
            
            /* Returning from here */
            return(ret);
        }
    
        else if(*pt == '(')
        {
            /* We only support one level of parenthesis */
            if(opened != 0)
                return(NULL);
            
            opened++;    
        }

        else if(*pt == ')')
        {
            if(opened != 1)
            {
                return(NULL);
            }
            opened = 0;
            tp_sz++;
        }
        
        pt++;
        count++;


    }

    return(NULL); /* failed */
}



/* OS_StrIsNum v0.1
 * Checks if a specific string is numeric (like "129544")
 */
int OS_StrIsNum(char *str)
{
    if(str == NULL)
        return(FALSE);
        
    while(*str != '\0')
    {
        if(!_IsD(*str))
            return(FALSE); /* 0 */
        str++;    
    }

    return(TRUE);
}

/* Split a string into multiples pieces, divided by "match".
 * Returns a NULL terminated array or NULL in error.
 */
char **OS_StrBreak(char match, char *str, int size)
{
    int count = 0;
    int i = 0;
    
    char *tmp_str = str;

    char **ret;

    /* We can't do anything if str is null or size <= 0 */
    if((str == NULL)||(size <= 0))
        return(NULL);

    ret = (char **)calloc(size+1, sizeof(char *));

    if(ret == NULL)
    {
        /* Memory error. Should provice a better way to detect it */
        return(NULL);
    }
    
    /* Allocating memory to null */
    while(i <= size)
    {
        ret[i] = NULL;
        i++;
    }
    i = 0;

    /* */
    while(*str != '\0')
    {
        i++;
        if((count < size-1)&&(*str == match))
        {
            ret[count] = (char *)calloc(i,sizeof(char));

            if(ret[count] == NULL)
            {
                goto error;
            }

            /* Copying the string */   
            ret[count][i-1] = '\0';
            strncpy(ret[count],tmp_str,i-1);

            tmp_str = ++str;
            count++;
            i=0; 

            continue;
        }
        str++;
    } /* leave from here when *str == \0 */


    /* Just do it if count < size */
    if(count < size)
    {
        ret[count] = (char *)calloc(i+1,sizeof(char));

        if(ret[count] == NULL)
        {
            goto error;
        }

        /* Copying the string */
        ret[count][i] = '\0';
        strncpy(ret[count],tmp_str,i);

        count++;

        /* Making sure it is null terminated */
        ret[count] = NULL;

        return(ret);
    }

    /* We shouldn't get to this point
     * Just let "error" handle that
     */

    error:
        i = 0;

        /* Deallocating the memory whe can */
        while(i < count)
        {
            free(ret[i]);
            i++;
        }

        free(ret);
        return(NULL);

}

/* EOF */
