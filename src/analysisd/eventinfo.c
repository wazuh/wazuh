/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "os_regex/os_regex.h"

/* Global definitions */
#ifdef TESTRULE
int full_output;
int alert_only;
#endif

#define OS_COMMENT_MAX 1024


size_t field_offset[] = {
    offsetof(Eventinfo, srcip),
    offsetof(Eventinfo, id),
    offsetof(Eventinfo, dstip),
    offsetof(Eventinfo, srcport),
    offsetof(Eventinfo, dstport),
    offsetof(Eventinfo, srcuser),
    offsetof(Eventinfo, dstuser),
    offsetof(Eventinfo, protocol),
    offsetof(Eventinfo, action),
    offsetof(Eventinfo, url),
    offsetof(Eventinfo, data),
    offsetof(Eventinfo, extra_data),
    offsetof(Eventinfo, status),
    offsetof(Eventinfo, systemname),
    offsetof(Eventinfo, srcgeoip),
    offsetof(Eventinfo, dstgeoip),
    offsetof(Eventinfo, location)
};


// Function to check for repetitions from same static fields

bool same_loop(RuleInfo *rule, Eventinfo *lf, Eventinfo *my_lf) {

    if ((rule->same_field & ALL_FIELDS) == 0x0) {
        return TRUE; // No need to check anything
    }

    int i;
    u_int32_t same = rule->same_field >> 2;

    for (i = 2; same != 0 && i < N_FIELDS; i++) {
        if ((same & 1) == 1) {
            char * field1 = *(char **)((void *)lf + field_offset[i]);
            char * field2 = *(char **)((void *)my_lf + field_offset[i]);

            if (!(field1 && field2 && strcmp(field1, field2) == 0)) {
                return FALSE;
            }
        }
        same >>= 1;
    }
    return TRUE;
}

// Function to check for repetitions from different static fields

bool different_loop(RuleInfo *rule, Eventinfo *lf, Eventinfo *my_lf) {

    if ((rule->different_field & ALL_FIELDS) == 0x0) {
        return TRUE; // No need to check anything
    }

    int i;
    u_int32_t different = rule->different_field;

    for (i = 0; different != 0 && i < N_FIELDS; i++) {
        if ((different & 1) == 1) {
            char * field1 = *(char **)((void *)lf + field_offset[i]);
            char * field2 = *(char **)((void *)my_lf + field_offset[i]);

            if (field1 && field2 && strcmp(field1, field2) == 0) {
                return FALSE;
            }
        }
        different >>= 1;
    }
    return TRUE;
}

/* Search last times a signature fired
 * Will look for only that specific signature.
 */
Eventinfo *Search_LastSids(Eventinfo *my_lf, __attribute__((unused)) EventList *last_events, RuleInfo *rule, __attribute__((unused)) regex_matching *rule_match)
{
    Eventinfo *lf = NULL;
    Eventinfo *first_matched = NULL;
    OSListNode *lf_node;
    int frequency_count = 0;
    int i;
    int found;
    const char * my_field;
    const char * field;
    time_t current_time;

    /* Checking if sid search is valid */
    if (!rule->sid_search) {
        merror("No sid search.");
        return NULL;
    }

    while (1) {
        w_mutex_lock(&rule->sid_search->mutex);
            if (!rule->sid_search->pending_remove) {
                rule->sid_search->count++;
                w_mutex_unlock(&rule->sid_search->mutex);
                break;
            }
        w_mutex_unlock(&rule->sid_search->mutex);
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(rule->sid_search);
    if (!lf_node) {
        lf = NULL;
        goto end;
    }

    do {
        lf = (Eventinfo *)lf_node->data;
        current_time = w_get_current_time();

#ifdef TESTRULE
        time(&current_time);
 #endif

        /* If time is outside the timeframe, return */
        if ((current_time - lf->generate_time) > rule->timeframe) {
            lf = NULL;
            goto end;
        }

        if (!(rule->context_opts & FIELD_GFREQUENCY)) {
            if ((!lf->agent_id) || (!my_lf->agent_id)) {
                continue;
            }

            if (strcmp(lf->agent_id, my_lf->agent_id) != 0) {
                continue;
            }
        }

        /* Check for same ID */
        if (rule->same_field & FIELD_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->same_field & FIELD_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same dynamic fields */
        if (rule->same_field & FIELD_DYNAMICS) {
            if (my_lf->nfields == 0 || lf->nfields == 0)
                continue;

            found = 1;
            for (i = 0; rule->same_fields[i] && found; ++i) {
                found = 0;
                my_field = FindField(my_lf, rule->same_fields[i]);
                if (my_field) {
                    field = FindField(lf, rule->same_fields[i]);
                    if (field && strcmp(my_field, field) == 0) {
                        found = 1;
                    }
                }
            }

            if (!found) {
                continue;
            }
        }

        /* Check for differences from dynamic fields values (not_same_field) */
        if (rule->different_field & FIELD_DYNAMICS) {
            if (my_lf->nfields == 0 && lf->nfields == 0)
                continue;

            found = 0;
            for (i = 0; rule->not_same_fields[i] && !found; ++i) {
                my_field = FindField(my_lf, rule->not_same_fields[i]);
                if (my_field) {
                    field = FindField(lf, rule->not_same_fields[i]);
                    if (field && strcmp(my_field, field) == 0) {
                        found = 1;
                    }
                }
            }

            if (found) {
                continue;
            }
        }
        /* Grouping of additional data */
        if (rule->alert_opts & SAME_EXTRAINFO) {
            /* Searching same fields */
            if (!same_loop(rule, lf, my_lf)) {
                continue;
            }
            /* Searching different fields */
            if (!different_loop(rule, lf, my_lf)) {
                continue;
            }
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        if (lf->matched >= rule->level) {
            lf = NULL;
            goto end;
        }

        /* Check if the number of matches worked */
        if (frequency_count <= 10 && (my_lf->last_events == NULL || my_lf->last_events[frequency_count] == NULL)) {
            add_lastevt(my_lf->last_events, frequency_count, lf->full_log);
        }

        if (frequency_count < rule->frequency) {
            frequency_count++;
            if (!first_matched) {
               first_matched = lf;
            }
            continue;
        }
        frequency_count++;

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        if (first_matched) { // To protect from a possible frequency 0
            first_matched->matched = rule->level;
        }
        goto end;
    } while ((lf_node = lf_node->prev) != NULL);

    lf = NULL;
end:
    w_mutex_lock(&rule->sid_search->mutex);
    rule->sid_search->count--;
    w_mutex_unlock(&rule->sid_search->mutex);
    return lf;
}

/* Search last times a group fired
 * Will look for only that specific group on that rule.
 */
Eventinfo *Search_LastGroups(Eventinfo *my_lf, __attribute__((unused)) EventList *last_events, RuleInfo *rule, __attribute__((unused)) regex_matching *rule_match)
{
    Eventinfo *lf = NULL;
    OSListNode *lf_node;
    Eventinfo *first_matched = NULL;
    int frequency_count = 0;
    int i;
    int found;
    OSList *list = rule->group_search;
    const char * my_field;
    const char * field;
    time_t current_time;

    //w_mutex_lock(&rule->mutex);

    /* Check if sid search is valid */
    if (!list) {
        merror("No group search.");
        return NULL;
    }

    while (1) {
        w_mutex_lock(&list->mutex);
            if (!list->pending_remove) {
                list->count++;
                w_mutex_unlock(&list->mutex);
                break;
            }
        w_mutex_unlock(&list->mutex);
    }

    /* Get last node */
    lf_node = OSList_GetLastNode_group(list);

    if (!lf_node) {
        lf = NULL;
        goto end;
    }

    do {
        lf = (Eventinfo *)lf_node->data;
        current_time = w_get_current_time();

#ifdef TESTRULE
        time(&current_time);
#endif

        /* If time is outside the timeframe, return */
        if ((current_time - lf->generate_time) > rule->timeframe) {
            lf = NULL;
            goto end;
        }

        if (!(rule->context_opts & FIELD_GFREQUENCY)) {
            if ((!lf->agent_id) || (!my_lf->agent_id)) {
                continue;
            }

            if (strcmp(lf->agent_id, my_lf->agent_id) != 0) {
                continue;
            }
        }

        /* Check for same ID */
        if (rule->same_field & FIELD_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->same_field & FIELD_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same dynamic fields */
        if (rule->same_field & FIELD_DYNAMICS) {
            if (my_lf->nfields == 0 || lf->nfields == 0) {
                continue;
            }

            found = 1;
            for (i = 0; rule->same_fields[i] && found; ++i) {
                found = 0;
                my_field = FindField(my_lf, rule->same_fields[i]);
                if (my_field) {
                    field = FindField(lf, rule->same_fields[i]);
                    if (field && strcmp(my_field, field) == 0) {
                        found = 1;
                    }
                }
            }

            if (!found) {
                continue;
            }
        }

        /* Check for differences from dynamic fields values (not_same_field) */
        if (rule->different_field & FIELD_DYNAMICS) {
            if (my_lf->nfields == 0 && lf->nfields == 0) {
                continue;
            }

            found = 0;
            for (i = 0; rule->not_same_fields[i] && !found; ++i) {
                my_field = FindField(my_lf, rule->not_same_fields[i]);
                if (my_field) {
                    field = FindField(lf, rule->not_same_fields[i]);
                    if (field && strcmp(my_field, field) == 0) {
                        found = 1;
                    }
                }
            }

            if (found) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (rule->alert_opts & SAME_EXTRAINFO) {
            /* Searching same fields */
            if (!same_loop(rule, lf, my_lf)) {
                continue;
            }

            /* Searching different fields */
            if (!different_loop(rule, lf, my_lf)) {
                continue;
            }
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        if (lf->matched >= rule->level) {
            lf = NULL;
            goto end;
        }


        /* Check if the number of matches worked */
        if (frequency_count <= 10 && (my_lf->last_events == NULL || my_lf->last_events[frequency_count] == NULL)) {
            add_lastevt(my_lf->last_events, frequency_count, lf->full_log);
        }

        if (frequency_count < rule->frequency) {
            frequency_count++;
            if (!first_matched) {
               first_matched = lf;
            }
            continue;
        }
        frequency_count++;

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        if (first_matched) { // To protect from a possible frequency 0
            first_matched->matched = rule->level;
        }
        goto end;
    } while ((lf_node = lf_node->prev) != NULL);

    lf = NULL;
end:
    w_mutex_lock(&list->mutex);
    list->count--;
    w_mutex_unlock(&list->mutex);
    //w_mutex_unlock(&rule->mutex);
    return lf;
}


/* Look if any of the last events (inside the timeframe)
 * match the specified rule
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, EventList *last_events, RuleInfo *rule, regex_matching *rule_match)
{
    EventNode *eventnode_pt = NULL;
    EventNode *first_pt;
    Eventinfo *first_matched = NULL;
    Eventinfo *lf = NULL;
    int frequency_count = 0;
    int i;
    int found;
    const char * my_field;
    const char * field;
    time_t current_time;

    w_mutex_lock(&rule->mutex);

    /* Get the first event */
    if (first_pt = OS_GetFirstEvent(last_events), !first_pt) {
        /* Nothing found */
        goto end;
    }

    w_mutex_lock(&first_pt->mutex);
    if (eventnode_pt = first_pt->next, eventnode_pt) {
        eventnode_pt->count++;
    }
    w_mutex_unlock(&first_pt->mutex);

    /* Search all previous events */
    while (eventnode_pt) {
        lf = eventnode_pt->event;
        current_time = w_get_current_time();

#ifdef TESTRULE
        time(&current_time);
#endif

        /* If time is outside the timeframe, return */
        if ((current_time - lf->generate_time) > rule->timeframe) {
            lf = NULL;
            goto end;
        }

        if (!(rule->context_opts & FIELD_GFREQUENCY)) {
            if ((!lf->agent_id) || (!my_lf->agent_id)) {
                continue;
            }

            if (strcmp(lf->agent_id, my_lf->agent_id) != 0) {
                continue;
            }
        }

        /* The category must be the same */
        if (lf->decoder_info->type != my_lf->decoder_info->type) {
            goto next_it;
        }

        /* If regex does not match, go to next */
        if (rule->if_matched_regex) {
            if (!OSRegex_Execute_ex(lf->log, rule->if_matched_regex, rule_match)) {
                /* Didn't match */
                goto next_it;
            }
        }

        /* Check for same ID */
        if (rule->same_field & FIELD_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                goto next_it;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                goto next_it;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->same_field & FIELD_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                goto next_it;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                goto next_it;
            }
        }

        /* Searching same fields */
        if (!same_loop(rule, lf, my_lf)) {
            goto next_it;
        }

        /* Searching different fields */
        if (!different_loop(rule, lf, my_lf)) {
            goto next_it;
        }

        /* Check for repetitions from same dynamic fields */
        if (rule->same_field & FIELD_DYNAMICS) {
            if (my_lf->nfields == 0 || lf->nfields == 0)
                goto next_it;

            found = 1;
            for (i = 0; rule->same_fields[i] && found; ++i) {
                found = 0;
                my_field = FindField(my_lf, rule->same_fields[i]);
                if (my_field) {
                    field = FindField(lf, rule->same_fields[i]);
                    if (field && strcmp(my_field, field) == 0) {
                        found = 1;
                    }
                }
            }

            if (!found) {
                goto next_it;
            }
        }

        /* Check for differences from dynamic fields values (not_same_field) */
        if (rule->different_field & FIELD_DYNAMICS) {
            if (my_lf->nfields == 0 && lf->nfields == 0)
                goto next_it;

            found = 0;
            for (i = 0; rule->not_same_fields[i] && !found; ++i) {
                my_field = FindField(my_lf, rule->not_same_fields[i]);
                if (my_field) {
                    field = FindField(lf, rule->not_same_fields[i]);
                    if (field && strcmp(my_field, field) == 0) {
                        found = 1;
                    }
                }
            }

            if (found) {
                goto next_it;
            }
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        if (lf->matched >= rule->level) {
            lf = NULL;
            goto end;
        }

        /* Check if the number of matches worked */
        if (frequency_count < rule->frequency) {
            if (frequency_count <= 10 && (my_lf->last_events == NULL || my_lf->last_events[frequency_count] == NULL)) {
                add_lastevt(my_lf->last_events, frequency_count, lf->full_log);
            }

            frequency_count++;
            if (!first_matched) {
               first_matched = lf;
            }
            goto next_it;
        }

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        if (first_matched) { // To protect from a possible frequency 0
            first_matched->matched = rule->level;
        }
        goto end;
next_it:
        w_mutex_lock(&eventnode_pt->mutex);
        eventnode_pt->count--;
        if (first_pt = eventnode_pt->next, first_pt) {
            first_pt->count++;
        }
        w_mutex_unlock(&eventnode_pt->mutex);
        eventnode_pt = first_pt;
    } // while close
    lf = NULL;
end:
    if (eventnode_pt) {
        w_mutex_lock(&eventnode_pt->mutex);
        eventnode_pt->count--;
        w_mutex_unlock(&eventnode_pt->mutex);
    }
    w_mutex_unlock(&rule->mutex);
    return lf;
}

/* Zero the loginfo structure */
void Zero_Eventinfo(Eventinfo *lf)
{
    lf->log = NULL;
    lf->full_log = NULL;
    lf->log_after_parent = NULL;
    lf->log_after_prematch = NULL;
    lf->agent_id = NULL;
    lf->hostname = NULL;
    lf->program_name = NULL;
    lf->location = NULL;
    lf->comment = NULL;
    lf->dec_timestamp = NULL;

    lf->srcip = NULL;
    lf->srcgeoip = NULL;
    lf->dstip = NULL;
    lf->dstgeoip = NULL;
    lf->srcport = NULL;
    lf->dstport = NULL;
    lf->protocol = NULL;
    lf->action = NULL;
    lf->srcuser = NULL;
    lf->dstuser = NULL;
    lf->id = NULL;
    lf->status = NULL;
    lf->url = NULL;
    lf->data = NULL;
    lf->extra_data = NULL;
    lf->systemname = NULL;

    if (lf->fields) {
        int i;
        for (i = 0; i < lf->nfields; i++)
            free(lf->fields[i].value);

        memset(lf->fields, 0, sizeof(DynamicField) * Config.decoder_order_size);
    }

    lf->nfields = 0;

    lf->time.tv_sec = 0;
    lf->time.tv_nsec = 0;
    lf->matched = 0;

    lf->year = 0;
    lf->mon[3] = '\0';
    lf->hour[9] = '\0';
    lf->day = 0;

    lf->generated_rule = NULL;
    lf->sid_node_to_delete = NULL;
    lf->group_node_to_delete = NULL;
    lf->decoder_info = NULL_Decoder;

    lf->previous = NULL;
    lf->labels = NULL;

    lf->is_a_copy = 0;
    lf->last_events = NULL;
    lf->r_firedtimes = -1;
    lf->queue_added = 0;
    lf->rootcheck_fts = 0;
    lf->decoder_syscheck_id = 0;
    lf->tid = -1;

    return;
}

/* Free the loginfo structure */
void Free_Eventinfo(Eventinfo *lf)
{
    if (!lf) {
        merror("Trying to free NULL event. Inconsistent..");
        return;
    }

    if (lf->node && lf->node->prev) {
        EventNode *prev = lf->node->prev;
        w_mutex_lock(&prev->mutex);
        prev->next = NULL;
        while (lf->node->count > 0) {}
        w_mutex_unlock(&prev->mutex);
    }

    // Free node to delete
    if(!lf->is_a_copy){
        if (lf->sid_node_to_delete) {
            w_mutex_lock(&lf->generated_rule->sid_prev_matched->mutex);
            lf->generated_rule->sid_prev_matched->pending_remove = 1;
            w_mutex_unlock(&lf->generated_rule->sid_prev_matched->mutex);
            while (lf->generated_rule->sid_prev_matched->count);

            OSList_DeleteThisNode(lf->generated_rule->sid_prev_matched,
                                    lf->sid_node_to_delete);

            w_mutex_lock(&lf->generated_rule->sid_prev_matched->mutex);
            lf->generated_rule->sid_prev_matched->pending_remove = 0;
            w_mutex_unlock(&lf->generated_rule->sid_prev_matched->mutex);
        } else if (lf->generated_rule && lf->generated_rule->group_prev_matched) {
            unsigned int i = 0;

            // Block all lists
            while (i < lf->generated_rule->group_prev_matched_sz) {
                w_mutex_lock(&lf->generated_rule->group_prev_matched[i]->mutex);
                lf->generated_rule->group_prev_matched[i]->pending_remove = 1;
                w_mutex_unlock(&lf->generated_rule->group_prev_matched[i]->mutex);
                i++;
            }

            i = 0;
            // Remove the node from all lists
            while (i < lf->generated_rule->group_prev_matched_sz) {
                while (lf->generated_rule->group_prev_matched[i]->count > 0);
                if (lf->group_node_to_delete) {
                    OSList_DeleteThisNode(lf->generated_rule->group_prev_matched[i],
                                          lf->group_node_to_delete[i]);
                }
                // Unblock the list
                w_mutex_lock(&lf->generated_rule->group_prev_matched[i]->mutex);
                lf->generated_rule->group_prev_matched[i]->pending_remove = 0;
                w_mutex_unlock(&lf->generated_rule->group_prev_matched[i]->mutex);
                i++;
            }

            free(lf->group_node_to_delete);
        }
    }

    if (lf->is_a_copy && lf->program_name) {
        free(lf->program_name);
    }

    if (lf->comment) {
        free(lf->comment);
    }

    if (lf->full_log) {
        free(lf->full_log);
    }

    if (lf->agent_id) {
        free(lf->agent_id);
    }

    if (lf->location) {
        free(lf->location);
    }

    if (lf->hostname) {
        free(lf->hostname);
    }

    if (lf->srcip) {
        free(lf->srcip);
    }

    if(lf->srcgeoip) {
        free(lf->srcgeoip);
        lf->srcgeoip = NULL;
    }

    if (lf->dstip) {
        free(lf->dstip);
    }

    if(lf->dstgeoip) {
        free(lf->dstgeoip);
        lf->dstgeoip = NULL;
    }

    if (lf->srcport) {
        free(lf->srcport);
    }
    if (lf->dstport) {
        free(lf->dstport);
    }
    if (lf->protocol) {
        free(lf->protocol);
    }
    if (lf->action) {
        free(lf->action);
    }
    if (lf->status) {
        free(lf->status);
    }
    if (lf->srcuser) {
        free(lf->srcuser);
    }
    if (lf->dstuser) {
        free(lf->dstuser);
    }
    if (lf->labels && lf->labels != Config.labels) {
        labels_free(lf->labels);
    }
    if (lf->id) {
        free(lf->id);
    }
    if (lf->url) {
        free(lf->url);
    }

    if (lf->data) {
        free(lf->data);
    }

    if (lf->extra_data) {
        free(lf->extra_data);
    }

    if (lf->systemname) {
        free(lf->systemname);
    }

    if (lf->fields) {
        int i;
        for (i = 0; i < lf->nfields; i++) {
            free(lf->fields[i].key);
            free(lf->fields[i].value);
        }

        free(lf->fields);
    }

    if (lf->previous) {
        free(lf->previous);
    }

    if (lf->is_a_copy) {
        if (lf->dec_timestamp){
            free(lf->dec_timestamp);
        }
    }

    if (lf->last_events) {
        char **lasts = lf->last_events;
        char **last_event = lf->last_events;

        while (*lasts) {
            free(*lasts);
            lasts++;
        }
        free(last_event);
    }

    /* We dont need to free:
     * fts
     * comment
     */
    os_free(lf);

    return;
}

/* Parse rule comment with dynamic fields */
char* ParseRuleComment(Eventinfo *lf) {
    char final[OS_COMMENT_MAX + 1] = { '\0' };
    char orig[OS_COMMENT_MAX + 1] = { '\0' };
    const char *field;
    char *str;
    char *var;
    char *end;
    char *tok;
    size_t n = 0;
    size_t z;

    strncpy(orig, lf->generated_rule->comment, OS_COMMENT_MAX);

    for (str = orig; (tok = strstr(str, "$(")); str = end) {
        field = NULL;
        *tok = '\0';
        var = tok + 2;

        if (n + (z = strlen(str)) >= OS_COMMENT_MAX)
            return strdup(lf->generated_rule->comment);

        strncat(final, str, OS_COMMENT_MAX - n);
        n += z;

        if (!(end = strchr(var, ')'))) {
            *tok = '$';
            str = tok;
            break;
        }

        *(end++) = '\0';

        // Find static fields

        if (strcmp(var, "dstuser") == 0) {
            field = lf->dstuser;
        } else if (strcmp(var, "srcuser") == 0) {
            field = lf->srcuser;
        } else if (strcmp(var, "srcip") == 0) {
            field = lf->srcip;
        } else if (strcmp(var, "dstip") == 0) {
            field = lf->dstip;
#ifdef LIBGEOIP_ENABLED
        } else if (strcmp(var, "srcgeoip") == 0) {
            field = lf->srcgeoip;
        } else if (strcmp(var, "dstgeoip") == 0) {
            field = lf->dstgeoip;
#endif
        } else if (strcmp(var, "srcport") == 0) {
            field = lf->srcport;
        } else if (strcmp(var, "dstport") == 0) {
            field = lf->dstport;
        } else if (strcmp(var, "protocol") == 0) {
            field = lf->protocol;
        } else if (strcmp(var, "action") == 0) {
            field = lf->action;
        } else if (strcmp(var, "id") == 0) {
            field = lf->id;
        } else if (strcmp(var, "url") == 0) {
            field = lf->url;
        } else if (strcmp(var, "data") == 0) {
            field = lf->data;
        } else if (strcmp(var, "status") == 0) {
            field = lf->status;
        } else if (strcmp(var, "extra_data") == 0) {
            field = lf->extra_data;
        } else if (strcmp(var, "system_name") == 0) {
            field = lf->systemname;
        }

        // Find pre-decoding fields
        else if (strcmp(var, "program_name") == 0) {
            field = lf->program_name;
        } else if (strcmp(var, "hostname") == 0) {
            field = lf->hostname;
        }

        // Find dynamic fields

        else {
            field = FindField(lf, var);
        }

        if (field) {
            if (n + (z = strlen(field)) >= OS_COMMENT_MAX)
                return strdup(lf->generated_rule->comment);

            strncat(final, field, OS_COMMENT_MAX - n);
            n += z;
        }
    }

    if (n + (z = strlen(str)) >= OS_COMMENT_MAX)
        return strdup(lf->generated_rule->comment);

    strncat(final, str, OS_COMMENT_MAX - n);
    final[n + z] = '\0';
    return strdup(final);
}

void w_copy_event_for_log(Eventinfo *lf,Eventinfo *lf_cpy){


    if(lf->full_log){
        os_strdup(lf->full_log,lf_cpy->full_log);
    }

    lf_cpy->log_after_parent = lf->log_after_parent;
    lf_cpy->log_after_prematch = lf->log_after_prematch;
    lf_cpy->generate_time = lf->generate_time;

    if(lf->agent_id){
        os_strdup(lf->agent_id,lf_cpy->agent_id);
    }

    if(lf->location){
        os_strdup(lf->location,lf_cpy->location);
    }

    if(lf->hostname){
        os_strdup(lf->hostname,lf_cpy->hostname);
    }

    if(lf->program_name){
        os_strdup(lf->program_name,lf_cpy->program_name);
    }

    if(lf->comment){
        os_strdup(lf->comment,lf_cpy->comment);
    }

    if(lf->dec_timestamp){
        os_strdup(lf->dec_timestamp,lf_cpy->dec_timestamp);
    }

    /* Extracted from the decoders */
    if(lf->srcip){
        os_strdup(lf->srcip,lf_cpy->srcip);
    }

    if(lf->srcgeoip){
        os_strdup(lf->srcgeoip,lf_cpy->srcgeoip);
    }

    if(lf->dstip){
        os_strdup(lf->dstip,lf_cpy->dstip);
    }

    if(lf->dstgeoip){
        os_strdup(lf->dstgeoip,lf_cpy->dstgeoip);
    }

    if(lf->srcport){
        os_strdup(lf->srcport,lf_cpy->srcport);
    }

    if(lf->dstport){
        os_strdup(lf->dstport,lf_cpy->dstport);
    }

    if(lf->protocol){
        os_strdup(lf->protocol,lf_cpy->protocol);
    }

    if(lf->action){
        os_strdup(lf->action,lf_cpy->action);
    }

    if(lf->srcuser){
        os_strdup(lf->srcuser,lf_cpy->srcuser);
    }

    if(lf->dstuser){
        os_strdup(lf->dstuser,lf_cpy->dstuser);
    }

    if(lf->id){
        os_strdup(lf->id,lf_cpy->id);
    }

    if(lf->status){
        os_strdup(lf->status,lf_cpy->status);
    }

    if(lf->url){
        os_strdup(lf->url,lf_cpy->url);
    }

    if(lf->data){
        os_strdup(lf->data,lf_cpy->data);
    }

    if(lf->extra_data){
        os_strdup(lf->extra_data, lf_cpy->extra_data);
    }

    if(lf->systemname){
        os_strdup(lf->systemname,lf_cpy->systemname);
    }

    lf_cpy->nfields = lf->nfields;

    int i;
    os_calloc(lf->nfields, sizeof(DynamicField), lf_cpy->fields);

    for (i = 0; i < lf->nfields; i++) {
        w_strdup(lf->fields[i].value, lf_cpy->fields[i].value);
        w_strdup(lf->fields[i].key, lf_cpy->fields[i].key);
    }

    /* Pointer to the rule that generated it */
    lf_cpy->generated_rule = lf->generated_rule;

    lf_cpy->decoder_info = lf->decoder_info;

    /* Sid node to delete */
    lf_cpy->sid_node_to_delete = lf->sid_node_to_delete;

    /* Extract when the event fires a rule */
    lf_cpy->size = lf->size;
    lf_cpy->p_name_size = lf->p_name_size;

    /* Other internal variables */
    lf_cpy->matched = lf->matched;
    lf_cpy->time = lf->time;
    lf_cpy->day = lf->day;
    lf_cpy->year = lf->year;
    memcpy(lf_cpy->hour,lf->hour,10);
    memcpy(lf_cpy->mon,lf->mon,4);

    /* Whodata fields */
    lf_cpy->r_firedtimes = lf->r_firedtimes;

    if(lf->previous){
        os_strdup(lf->previous,lf_cpy->previous);
    }

    lf_cpy->last_events = NULL;

    if (lf->last_events){
        os_calloc(1,sizeof(char *),lf_cpy->last_events);
        char **lasts = lf->last_events;
        int index = 0;

        while (*lasts) {
            os_realloc(lf_cpy->last_events, sizeof(char *) * (index + 2), lf_cpy->last_events);
            lf_cpy->last_events[index] = NULL;

            os_strdup(*lasts,lf_cpy->last_events[index]);
            lasts++;
            index++;
        }
        lf_cpy->last_events[index] = NULL;
    }

    lf_cpy->labels = labels_dup(lf->labels);
    lf_cpy->decoder_syscheck_id = lf->decoder_syscheck_id;
    lf_cpy->rootcheck_fts = lf->rootcheck_fts;
    lf_cpy->is_a_copy = 1;
}

void w_free_event_info(Eventinfo *lf) {
    /** Cleaning the memory **/
    int force_remove = 1;
    /* Only clear the memory if the eventinfo was not
        * added to the stateful memory
        * -- message is free inside clean event --
    */
    if (lf->generated_rule == NULL) {
        Free_Eventinfo(lf);
        force_remove = 0;
    } else if (lf->last_events) {
        int i;
        if (lf->queue_added) {
            force_remove = 0;
        }
        if (lf->last_events) {
            for (i = 0; lf->last_events[i]; i++) {
                os_free(lf->last_events[i]);
            }
            os_free(lf->last_events);
        }
    } else if (lf->queue_added) {
        force_remove = 0;
    }

    if (force_remove) {
        Free_Eventinfo(lf);
    }
}
