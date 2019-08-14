/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "eventinfo.h"
#include "shared.h"
#include "config.h"


/* Note: If the rule fails to match it should return NULL.
 * If you want processing to continue, return lf (the eventinfo structure).
 */

/* Example 1: Comparing if the srcuser and dstuser are the same
 * If they are the same, return true
 * If any of them is not set, return true too
 */
void *comp_srcuser_dstuser(Eventinfo *lf)
{
    if (!lf->srcuser || !lf->dstuser) {
        return (lf);
    }

    if (strcmp(lf->srcuser, lf->dstuser) == 0) {
        return (lf);
    }

    /* In here, srcuser and dstuser are present and are different */
    return (NULL);
}

/* Example 2: Checking if the size of the id field is larger than 10 */
void *check_id_size(Eventinfo *lf)
{
    if (!lf->id) {
        return (NULL);
    }

    if (strlen(lf->id) >= 10) {
        return (lf);
    }

    return (NULL);
}

/* Example 3: Comparing the Target Account Name and Caller User Name on Windows logs
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

    if (!target_user || !caller_user) {
        return (NULL);
    }

    /* We need to clear each user type and finish the string.
     * It looks like:
     * Target Account Name: account\t
     * Caller User Name: account\t
     */
    target_user = strchr(target_user, ':');
    caller_user = strchr(caller_user, ':');

    if (!target_user || !caller_user) {
        return (NULL);
    }

    target_user++;
    caller_user++;

    while (*target_user != '\0') {
        if (*target_user != *caller_user) {
            return (lf);
        }

        if (*target_user == '\t' ||
                (*target_user == ' '  && target_user[1] == ' ')) {
            break;
        }

        target_user++;
        caller_user++;
    }

    /* If we got in here, the accounts are the same.
     * So, we return NULL since we only want to alert if they are different.
     */
    return (NULL);
}

/* Example 4: Checking if a HTTP request is a simple GET/POST without a query
 * This avoid that we call the attack rules for no reason.
 */
void *is_simple_http_request(Eventinfo *lf)
{

    if (!lf->url) {
        return (NULL);
    }

    /* Simple GET / request */
    if (strcmp(lf->url, "/") == 0) {
        return (lf);
    }

    /* Simple request, no query */
    if (!strchr(lf->url, '?')) {
        return (lf);
    }

    /* In here, we have an additional query to be checked */
    return (NULL);
}

/* Example 5: Checking if the source IP is from a valid bot */
void *is_valid_crawler(Eventinfo *lf)
{
    if ((strncmp(lf->log, "66.249.", 7) == 0) || /* Google bot */
            (strncmp(lf->log, "72.14.", 6) == 0) || /* Feedfetcher-Google */
            (strncmp(lf->log, "209.85.", 7) == 0) || /* Feedfetcher-Google */
            (strncmp(lf->log, "65.55.", 6) == 0) || /* MSN/Bing */
            (strncmp(lf->log, "207.46.", 7) == 0) || /* MSN/Bing */
            (strncmp(lf->log, "74.6.", 5) == 0) || /* Yahoo */
            (strncmp(lf->log, "72.30.", 6) == 0) || /* Yahoo */
            (strncmp(lf->log, "67.195.", 7) == 0) /* Yahoo */
       ) {
        return (lf);
    }

    return (NULL);
}

