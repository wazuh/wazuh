/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Accumulator Functions which accumulate objects based on an ID */

#include <sys/time.h>

#include "shared.h"
#include "accumulator.h"
#include "eventinfo.h"

/* Global variables */
OSHash *acm_store = NULL;

/* Counters for Purging */
int  acm_lookups = 0;
int  acm_purge_ts = 0;


/* Start the Accumulator module */
int Accumulate_Init()
{
    struct timeval tp;

    /* Create store data */
    acm_store = OSHash_Create();
    if (!acm_store) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }
    if (!OSHash_setSize(acm_store, 2048)) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }

    /* Default Expiry */
    gettimeofday(&tp, NULL);
    acm_purge_ts = tp.tv_sec;

    debug1("%s: DEBUG: Accumulator Init completed.", ARGV0);
    return (1);
}

/* Accumulate data from events sharing the same ID */
Eventinfo *Accumulate(Eventinfo *lf)
{
    int result;
    int do_update = 0;

    char _key[OS_ACM_MAXKEY];
    OS_ACM_Store *stored_data = 0;

    int  current_ts;
    struct timeval tp;

    if ( lf == NULL ) {
        debug1("accumulator: DEBUG: Received NULL EventInfo");
        return lf;
    }
    if ( lf->id == NULL ) {
        debug2("accumulator: DEBUG: No id available");
        return lf;
    }
    if ( lf->decoder_info == NULL ) {
        debug1("accumulator: DEBUG: No decoder_info available");
        return lf;
    }
    if ( lf->decoder_info->name == NULL ) {
        debug1("accumulator: DEBUG: No decoder name available");
        return lf;
    }

    /* Purge the cache as needed */
    Accumulate_CleanUp();

    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    /* Accumulator Key */
    result = snprintf(_key, OS_FLSIZE, "%s %s %s",
                      lf->hostname,
                      lf->decoder_info->name,
                      lf->id
                     );
    if ( result < 0 || (unsigned) result >= sizeof(_key) ) {
        debug1("accumulator: DEBUG: error setting accumulator key, id:%s,name:%s", lf->id, lf->decoder_info->name);
        return lf;
    }

    /* Check if acm is already present */
    if ((stored_data = (OS_ACM_Store *)OSHash_Get(acm_store, _key)) != NULL) {
        debug2("accumulator: DEBUG: Lookup for '%s' found a stored value!", _key);

        if ( stored_data->timestamp > 0 && stored_data->timestamp < current_ts - OS_ACM_EXPIRE_ELM ) {
            if ( OSHash_Delete(acm_store, _key) != NULL ) {
                debug1("accumulator: DEBUG: Deleted expired hash entry for '%s'", _key);
                /* Clear this memory */
                FreeACMStore(stored_data);
                /* Reallocate what we need */
                stored_data = InitACMStore();
            }
        } else {
            /* Update the event */
            do_update = 1;
            if (acm_str_replace(&lf->dstuser, stored_data->dstuser) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->dstuser to %s", _key, lf->dstuser);
            }

            if (acm_str_replace(&lf->srcuser, stored_data->srcuser) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->srcuser to %s", _key, lf->srcuser);
            }

            if (acm_str_replace(&lf->dstip, stored_data->dstip) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->dstip to %s", _key, lf->dstip);
            }

            if (acm_str_replace(&lf->srcip, stored_data->srcip) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->srcip to %s", _key, lf->srcip);
            }

            if (acm_str_replace(&lf->dstport, stored_data->dstport) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->dstport to %s", _key, lf->dstport);
            }

            if (acm_str_replace(&lf->srcport, stored_data->srcport) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->srcport to %s", _key, lf->srcport);
            }

            if (acm_str_replace(&lf->data, stored_data->data) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->data to %s", _key, lf->data);
            }
        }
    } else {
        stored_data = InitACMStore();
    }

    /* Store the object in the cache */
    stored_data->timestamp = current_ts;
    if (acm_str_replace(&stored_data->dstuser, lf->dstuser) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstuser to %s", _key, stored_data->dstuser);
    }

    if (acm_str_replace(&stored_data->srcuser, lf->srcuser) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcuser to %s", _key, stored_data->srcuser);
    }

    if (acm_str_replace(&stored_data->dstip, lf->dstip) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstip to %s", _key, stored_data->dstip);
    }

    if (acm_str_replace(&stored_data->srcip, lf->srcip) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcip to %s", _key, stored_data->srcip);
    }

    if (acm_str_replace(&stored_data->dstport, lf->dstport) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstport to %s", _key, stored_data->dstport);
    }

    if (acm_str_replace(&stored_data->srcport, lf->srcport) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcport to %s", _key, stored_data->srcport);
    }

    if (acm_str_replace(&stored_data->data, lf->data) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->data to %s", _key, stored_data->data);
    }

    /* Update or Add to the hash */
    if ( do_update == 1 ) {
        /* Update the hash entry */
        if ( (result = OSHash_Update(acm_store, _key, stored_data)) != 1) {
            verbose("accumulator: ERROR: Update of stored data for %s failed (%d).", _key, result);
        } else {
            debug1("accumulator: DEBUG: Updated stored data for %s", _key);
        }
    } else {
        if ((result = OSHash_Add(acm_store, _key, stored_data)) != 2 ) {
            verbose("accumulator: ERROR: Addition of stored data for %s failed (%d).", _key, result);
        } else {
            debug1("accumulator: DEBUG: Added stored data for %s", _key);
        }
    }

    return lf;
}

void Accumulate_CleanUp()
{
    struct timeval tp;
    int current_ts = 0;
    int expired = 0;

    OSHashNode *curr;
    OS_ACM_Store *stored_data;
    char *key;
    unsigned int ti;

    /* Keep track of how many times we're called */
    acm_lookups++;

    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    /* Do we really need to purge? */
    if ( acm_lookups < OS_ACM_PURGE_COUNT && acm_purge_ts < current_ts + OS_ACM_PURGE_INTERVAL ) {
        return;
    }
    debug1("accumulator: DEBUG: Accumulator_CleanUp() running .. ");

    /* Yes, we do */
    acm_lookups = 0;
    acm_purge_ts = current_ts;

    /* Loop through the hash */
    for ( ti = 0; ti < acm_store->rows; ti++ ) {
        curr = acm_store->table[ti];
        while ( curr != NULL ) {
            /* Get the Key and Data */
            key  = (char *) curr->key;
            stored_data = (OS_ACM_Store *) curr->data;
            /* Increment to the next element */
            curr = curr->next;

            debug2("accumulator: DEBUG: CleanUp() evaluating cached key: %s ", key);
            /* Check for a valid element */
            if ( stored_data != NULL ) {
                /* Check for expiration */
                debug2("accumulator: DEBUG: CleanUp() elm:%d, curr:%d", stored_data->timestamp, current_ts);
                if ( stored_data->timestamp < current_ts - OS_ACM_EXPIRE_ELM ) {
                    debug2("accumulator: DEBUG: CleanUp() Expiring '%s'", key);
                    if ( OSHash_Delete(acm_store, key) != NULL ) {
                        FreeACMStore(stored_data);
                        expired++;
                    } else {
                        debug1("accumulator: DEBUG: CleanUp() failed to find key '%s'", key);
                    }
                }
            }
        }
    }
    debug1("accumulator: DEBUG: Expired %d elements", expired);
}

/* Initialize a storage object */
OS_ACM_Store *InitACMStore()
{
    OS_ACM_Store *obj;
    os_calloc(1, sizeof(OS_ACM_Store), obj);

    obj->timestamp = 0;
    obj->srcuser = NULL;
    obj->dstuser = NULL;
    obj->srcip = NULL;
    obj->dstip = NULL;
    obj->srcport = NULL;
    obj->dstport = NULL;
    obj->data = NULL;

    return obj;
}

/* Free an accumulation store struct */
void FreeACMStore(OS_ACM_Store *obj)
{
    if ( obj != NULL ) {
        debug2("accumulator: DEBUG: Freeing an accumulator struct.");
        free(obj->dstuser);
        free(obj->srcuser);
        free(obj->dstip);
        free(obj->srcip);
        free(obj->dstport);
        free(obj->srcport);
        free(obj->data);
        free(obj);
    }
}

int acm_str_replace(char **dst, const char *src)
{
    int result = 0;

    /* Don't overwrite with a null str */
    if ( src == NULL ) {
        return -1;
    }

    /* Don't overwrite something we already know */
    if (dst != NULL && *dst != NULL && **dst != '\0') {
        return -1;
    }

    /* Make sure we have data to write */
    int slen = strlen(src);
    if ( slen <= 0  || slen > OS_ACM_MAXELM - 1 ) {
        return -1;
    }

    /* Free dst, and malloc the memory we need! */
    if ( dst != NULL ) {
        free(*dst);
    }
    os_malloc(slen + 1, *dst);

    result = strcpy(*dst, src) == NULL ? -1 : 0;
    if (result < 0) {
        debug1("accumulator: DEBUG: error in acm_str_replace()");
    }
    return result;
}

