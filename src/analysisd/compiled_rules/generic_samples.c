/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "shared.h"
#include "eventinfo.h"
#include "config.h"



/** Note: If the rule fails to match it should return NULL. 
 * If you want processing to continue, return lf (the eventinfo structure).
 */
 


/* Example 1:
 * Comparing if the srcuser and dstuser are the same. If they are the same,
 * return true.
 * If any of them is not set, return true too.
 */
void *comp_srcuser_dstuser(Eventinfo *lf)
{
    if(!lf->srcuser || !lf->dstuser)
    {
        return(lf);
    }

    if(strcmp(lf->srcuser, lf->dstuser) == 0)
    {
        return(lf);
    }


    /* In here, srcuser and dstuser are present and are different. */
    return(NULL);
}



/* Example 2:
 * Checking if the size of the id field is larger than 10.
 */
void *check_id_size(Eventinfo *lf)
{
    if(!lf->id)
    {
        return(NULL);
    }

    if(strlen(lf->id) >= 10)
    {
        return(lf);
    }

    return(NULL);
}



/* Example 3:
 * Comparing the Target Account Name and Caller User Name
 * on Windows logs.
 * It will return NULL (not match) if any of these values
 * are not present or if they are the same.
 * This function will return TRUE if they are NOT the same.
 */
void *comp_mswin_targetuser_calleruser_diff(Eventinfo *lf)
{
    char *target_user;
    char *caller_user;


    target_user = strstr(lf->log, "Target Account Name");
    caller_user = strstr(lf->log, "Caller User Name");

    if(!target_user || !caller_user)
    {
        return(NULL);
    }


    /* We need to clear each user type and finish the string.
     * It looks like:
     * Target Account Name: account\t
     * Caller User Name: account\t
     */
    target_user = strchr(target_user, ':');
    caller_user = strchr(caller_user, ':');

    if(!target_user || !caller_user)
    {
        return(NULL);
    }


    target_user++;
    caller_user++;


    while(*target_user != '\0')
    {
        if(*target_user != *caller_user)
            return(lf);

        if(*target_user == '\t' || 
           (*target_user == ' '  && target_user[1] == ' '))
            break;    

        target_user++;caller_user++;           
    }


    /* If we got in here, the accounts are the same.
     * So, we return NULL since we only want to alert if they are different.
     */ 
    return(NULL);
}


/* END generic samples. */

