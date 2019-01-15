/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

EventList *last_events_list;
int num_rule_matching_threads;
time_t current_time = 0;

/* Search last times a signature fired
 * Will look for only that specific signature.
 */
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *rule, __attribute__((unused)) regex_matching *rule_match)
{
    Eventinfo *lf = NULL;
    Eventinfo *first_lf;
    OSListNode *lf_node;
    int frequency_count = 0;

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

    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

#ifdef TESTRULE
        time(&current_time);
 #endif
        /* If time is outside the timeframe, return */
        if ((current_time - lf->generate_time) > rule->timeframe) {
            lf = NULL;
            goto end;
        }

        /* Check for same ID */
        if (rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (rule->alert_opts & SAME_EXTRAINFO) {
            /* Check for same source port */
            if (rule->context_opts & SAME_SRCPORT) {
                if ((!lf->srcport) || (!my_lf->srcport)) {
                    continue;
                }

                if (strcmp(lf->srcport, my_lf->srcport) != 0) {
                    continue;
                }
            }

            /* Check for same dst port */
            if (rule->context_opts & SAME_DSTPORT) {
                if ((!lf->dstport) || (!my_lf->dstport)) {
                    continue;
                }

                if (strcmp(lf->dstport, my_lf->dstport) != 0) {
                    continue;
                }
            }

            /* Check for repetitions on user error */
            if (rule->context_opts & SAME_USER) {
                if ((!lf->dstuser) || (!my_lf->dstuser)) {
                    continue;
                }

                if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                    continue;
                }
            }

            /* Check for same location */
            if (rule->context_opts & SAME_LOCATION) {
                if (strcmp(lf->hostname, my_lf->hostname) != 0) {
                    continue;
                }
            }

            /* Check for different URLs */
            if (rule->context_opts & DIFFERENT_URL) {
                if ((!lf->url) || (!my_lf->url)) {
                    continue;
                }

                if (strcmp(lf->url, my_lf->url) == 0) {
                    continue;
                }
            }

            /* Check for different from same srcgeoip */
            if (rule->context_opts & DIFFERENT_SRCGEOIP) {

                if ((!lf->srcgeoip) || (!my_lf->srcgeoip)) {
                    continue;
                }
                if (strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0) {
                    continue;
                }
            }


        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            lf = NULL;
            goto end;
        }

        /* Check if the number of matches worked */
        if (frequency_count <= 10) {
            add_lastevt(my_lf->last_events, frequency_count, lf->full_log);
        }

        if (frequency_count < rule->frequency) {
            frequency_count++;
            continue;
        }
        frequency_count++;
        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;
        first_lf->matched = rule->level;
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
Eventinfo *Search_LastGroups(Eventinfo *my_lf, RuleInfo *rule, __attribute__((unused)) regex_matching *rule_match)
{
    Eventinfo *lf = NULL;
    OSListNode *lf_node;
    Eventinfo *first_lf;
    int frequency_count = 0;
    OSList *list = rule->group_search;

    //w_mutex_lock(&rule->mutex);

    /* Check if sid search is valid */
    if (!list) {
        merror("No group search!");
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

    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

#ifdef TESTRULE
        time(&current_time);
#endif
        /* If time is outside the timeframe, return */
        if ((current_time - lf->generate_time) > rule->timeframe) {
            lf = NULL;
            goto end;
        }

        /* Check for same ID */
        if (rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (rule->alert_opts & SAME_EXTRAINFO) {
            /* Check for same source port */
            if (rule->context_opts & SAME_SRCPORT) {
                if ((!lf->srcport) || (!my_lf->srcport)) {
                    continue;
                }

                if (strcmp(lf->srcport, my_lf->srcport) != 0) {
                    continue;
                }
            }

            /* Check for same dst port */
            if (rule->context_opts & SAME_DSTPORT) {
                if ((!lf->dstport) || (!my_lf->dstport)) {
                    continue;
                }

                if (strcmp(lf->dstport, my_lf->dstport) != 0) {
                    continue;
                }
            }

            /* Check for repetitions on user error */
            if (rule->context_opts & SAME_USER) {
                if ((!lf->dstuser) || (!my_lf->dstuser)) {
                    continue;
                }

                if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                    continue;
                }
            }

            /* Check for same location */
            if (rule->context_opts & SAME_LOCATION) {
                if (strcmp(lf->hostname, my_lf->hostname) != 0) {
                    continue;
                }
            }

            /* Check for different URLs */
            if (rule->context_opts & DIFFERENT_URL) {
                if ((!lf->url) || (!my_lf->url)) {
                    continue;
                }

                if (strcmp(lf->url, my_lf->url) == 0) {
                    continue;
                }
            }

            /* Check for different from same srcgeoip */
            if (rule->context_opts & DIFFERENT_SRCGEOIP) {

                if ((!lf->srcgeoip) || (!my_lf->srcgeoip)) {
                    continue;
                }

                if (strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0) {
                    continue;
                }
            }
        }
        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            lf = NULL;
            goto end;
        }


        /* Check if the number of matches worked */
        if (frequency_count < rule->frequency) {
            if (frequency_count <= 10) {
                add_lastevt(my_lf->last_events, frequency_count, lf->full_log);
            }

            frequency_count++;
            continue;
        }

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;
        first_lf->matched = rule->level;
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
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *rule, regex_matching *rule_match)
{
    EventNode *eventnode_pt = NULL;
    EventNode *first_pt;
    Eventinfo *lf = NULL;
    int frequency_count = 0;

    w_mutex_lock(&rule->mutex);

    /* Get the first event */
    if (first_pt = OS_GetFirstEvent(last_events_list), !first_pt) {
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

#ifdef TESTRULE
        time(&current_time);
#endif
        /* If time is outside the timeframe, return */
        if ((current_time - lf->generate_time) > rule->timeframe) {
            lf = NULL;
            goto end;
        }

        /* The category must be the same */
        else if (lf->decoder_info->type != my_lf->decoder_info->type) {
            goto next_it;
        }

        /* If regex does not match, go to next */
        if (rule->if_matched_regex) {
            if (!OSRegex_Execute_ex(lf->log, rule->if_matched_regex, rule_match)) {
                /* Didn't match */
                goto next_it;
            }
        }

        /* Check for repetitions on user error */
        if (rule->context_opts & SAME_USER) {
            if ((!lf->dstuser) || (!my_lf->dstuser)) {
                goto next_it;
            }

            if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                goto next_it;
            }
        }

        /* Check for same ID */
        if (rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                goto next_it;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                goto next_it;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                goto next_it;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                goto next_it;
            }
        }

        /* Check for different urls */
        if (rule->context_opts & DIFFERENT_URL) {
            if ((!lf->url) || (!my_lf->url)) {
                goto next_it;
            }

            if (strcmp(lf->url, my_lf->url) == 0) {
                goto next_it;
            }
        }

        /* Check for different from same srcgeoip */
        if (rule->context_opts & DIFFERENT_SRCGEOIP) {
            if ((!lf->srcgeoip) || (!my_lf->srcgeoip)) {
                goto next_it;
            }

            if (strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0) {
                goto next_it;
            }
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            lf = NULL;
            goto end;
        }

        /* Check if the number of matches worked */
        if (frequency_count < rule->frequency) {
            if (frequency_count <= 10) {
                add_lastevt(my_lf->last_events, frequency_count, lf->full_log);
            }

            frequency_count++;
            goto next_it;
        }

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;

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
    lf->command = NULL;
    lf->url = NULL;
    lf->data = NULL;
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

    lf->filename = NULL;
    lf->perm_before = 0;
    lf->perm_after = 0;
    lf->win_perm_before = NULL;
    lf->win_perm_after = NULL;
    lf->md5_before = NULL;
    lf->md5_after = NULL;
    lf->sha1_before = NULL;
    lf->sha1_after = NULL;
    lf->sha256_before = NULL;
    lf->sha256_after = NULL;
    lf->size_before = NULL;
    lf->size_after = NULL;
    lf->owner_before = NULL;
    lf->owner_after = NULL;
    lf->gowner_before = NULL;
    lf->gowner_after = NULL;
    lf->uname_before = NULL;
    lf->uname_after = NULL;
    lf->gname_before = NULL;
    lf->gname_after = NULL;
    lf->mtime_before = 0;
    lf->mtime_after = 0;
    lf->inode_before = 0;
    lf->inode_after = 0;
    lf->diff = NULL;
    lf->previous = NULL;
    lf->labels = NULL;
    lf->sk_tag = NULL;

    lf->user_id = NULL;
    lf->user_name = NULL;
    lf->group_id = NULL;
    lf->group_name = NULL;
    lf->process_name = NULL;
    lf->audit_uid = NULL;
    lf->audit_name = NULL;
    lf->effective_uid = NULL;
    lf->effective_name = NULL;
    lf->ppid = NULL;
    lf->process_id = NULL;
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
                OSList_DeleteThisNode(lf->generated_rule->group_prev_matched[i],
                                        lf->group_node_to_delete[i]);
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
    if (lf->command) {
        free(lf->command);
    }
    if (lf->url) {
        free(lf->url);
    }

    if (lf->data) {
        free(lf->data);
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

    if (lf->filename) {
        free(lf->filename);
    }
    if (lf->sk_tag) {
        free(lf->sk_tag);
    }
    if (lf->win_perm_before) {
        free(lf->win_perm_before);
    }
    if (lf->win_perm_after) {
        free(lf->win_perm_after);
    }
    if (lf->md5_before) {
        free(lf->md5_before);
    }
    if (lf->md5_after) {
        free(lf->md5_after);
    }
    if (lf->sha1_before) {
        free(lf->sha1_before);
    }
    if (lf->sha1_after) {
        free(lf->sha1_after);
    }
    if (lf->sha256_before) {
        free(lf->sha256_before);
    }
    if (lf->sha256_after) {
        free(lf->sha256_after);
    }
    if (lf->size_before) {
        free(lf->size_before);
    }
    if (lf->size_after) {
        free(lf->size_after);
    }
    if (lf->owner_before) {
        free(lf->owner_before);
    }
    if (lf->owner_after) {
        free(lf->owner_after);
    }
    if (lf->gowner_before) {
        free(lf->gowner_before);
    }
    if (lf->gowner_after) {
        free(lf->gowner_after);
    }
    if (lf->uname_before) {
        free(lf->uname_before);
    }
    if (lf->uname_after) {
        free(lf->uname_after);
    }
    if (lf->gname_before) {
        free(lf->gname_before);
    }
    if (lf->gname_after) {
        free(lf->gname_after);
    }
    if (lf->user_id) {
        free(lf->user_id);
    }
    if (lf->user_name) {
        free(lf->user_name);
    }
    if (lf->group_id) {
        free(lf->group_id);
    }
    if (lf->group_name) {
        free(lf->group_name);
    }
    if (lf->process_name) {
        free(lf->process_name);
    }
    if (lf->audit_uid) {
        free(lf->audit_uid);
    }
    if (lf->audit_name) {
        free(lf->audit_name);
    }
    if (lf->effective_uid) {
        free(lf->effective_uid);
    }
    if (lf->effective_name) {
        free(lf->effective_name);
    }
    if (lf->ppid) {
        free(lf->ppid);
    }
    if (lf->process_id) {
        free(lf->process_id);
    }
    if (lf->diff) {
        free(lf->diff);
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

        strncpy(&final[n], str, z);
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
        } else if (strcmp(var, "dstuser") == 0) {
            field = lf->dstgeoip;
#endif
        } else if (strcmp(var, "srcport") == 0) {
            field = lf->srcport;
        } else if (strcmp(var, "protocol") == 0) {
            field = lf->protocol;
        } else if (strcmp(var, "action") == 0) {
            field = lf->action;
        } else if (strcmp(var, "id") == 0) {
            field = lf->id;
        } else if (strcmp(var, "url") == 0) {
            field = lf->url;
        } else if (strcmp(var, "data") == 0 || strcmp(var, "extra_data") == 0) {
            field = lf->data;
        } else if (strcmp(var, "status") == 0) {
            field = lf->status;
        } else if (strcmp(var, "system_name") == 0) {
            field = lf->systemname;
        }

        // Find dynamic fields

        else {
            field = FindField(lf, var);
        }

        if (field) {
            if (n + (z = strlen(field)) >= OS_COMMENT_MAX)
                return strdup(lf->generated_rule->comment);

            strncpy(&final[n], field, z);
            n += z;
        }
    }

    if (n + (z = strlen(str)) >= OS_COMMENT_MAX)
        return strdup(lf->generated_rule->comment);

    strncpy(&final[n], str, z);
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

    if(lf->command){
        os_strdup(lf->command,lf_cpy->command);
    }

    if(lf->url){
        os_strdup(lf->url,lf_cpy->url);
    }

    if(lf->data){
        os_strdup(lf->data,lf_cpy->data);
    }

    if(lf->systemname){
        os_strdup(lf->systemname,lf_cpy->systemname);
    }

    lf_cpy->nfields = lf->nfields;

    int i;
    os_calloc(lf->nfields, sizeof(DynamicField), lf_cpy->fields);

    for (i = 0; i < lf->nfields; i++) {
        if (lf->fields[i].value) {
           os_strdup(lf->fields[i].value,lf_cpy->fields[i].value);
        }
        if (lf->fields[i].key) {
           os_strdup(lf->fields[i].key,lf_cpy->fields[i].key);
        }
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

    /* SYSCHECK Results variables */
    lf_cpy->event_type = lf->event_type;

    if(lf->filename){
        os_strdup(lf->filename,lf_cpy->filename);
    }

    lf_cpy->perm_before = lf->perm_before;
    lf_cpy->perm_after = lf->perm_after;

    if (lf->sk_tag){
        os_strdup(lf->sk_tag, lf_cpy->sk_tag);
    }

    if (lf->win_perm_before) {
        os_strdup(lf->win_perm_before, lf_cpy->win_perm_before);
    }

    if (lf->win_perm_after) {
        os_strdup(lf->win_perm_after, lf_cpy->win_perm_after);
    }

    if(lf->md5_before){
        os_strdup(lf->md5_before,lf_cpy->md5_before);
    }

    if(lf->md5_after){
        os_strdup(lf->md5_after,lf_cpy->md5_after);
    }

    if(lf->sha1_before){
        os_strdup(lf->sha1_before,lf_cpy->sha1_before);
    }

    if(lf->sha1_after){
        os_strdup(lf->sha1_after,lf_cpy->sha1_after);
    }

    if(lf->sha256_before){
        os_strdup(lf->sha256_before,lf_cpy->sha256_before);
    }

    if(lf->sha256_after){
        os_strdup(lf->sha256_after,lf_cpy->sha256_after);
    }

    lf_cpy->attrs_before = lf->attrs_before;
    lf_cpy->attrs_after = lf->attrs_after;

    if(lf->size_before){
        os_strdup(lf->size_before,lf_cpy->size_before);
    }

    if(lf->size_after){
        os_strdup(lf->size_after,lf_cpy->size_after);
    }

    if(lf->owner_before){
        os_strdup(lf->owner_before,lf_cpy->owner_before);
    }

    if(lf->owner_after){
        os_strdup(lf->owner_after,lf_cpy->owner_after);
    }

    if(lf->gowner_before){
        os_strdup(lf->gowner_before,lf_cpy->gowner_before);
    }

    if(lf->gowner_after){
        os_strdup(lf->gowner_after,lf_cpy->gowner_after);
    }

    if(lf->uname_before){
        os_strdup(lf->uname_before,lf_cpy->uname_before);
    }

    if(lf->uname_after){
        os_strdup(lf->uname_after,lf_cpy->uname_after);
    }

    if(lf->gname_before){
        os_strdup(lf->gname_before,lf_cpy->gname_before);
    }

    if(lf->gname_after){
        os_strdup(lf->gname_after,lf_cpy->gname_after);
    }

    /* Whodata fields */
    if (lf->user_id){
        os_strdup(lf->user_id, lf_cpy->user_id);
    }

    if (lf->user_name){
        os_strdup(lf->user_name, lf_cpy->user_name);
    }

    if (lf->group_id){
        os_strdup(lf->group_id, lf_cpy->group_id);
    }

    if (lf->group_name){
        os_strdup(lf->group_name, lf_cpy->group_name);
    }

    if (lf->process_name){
        os_strdup(lf->process_name, lf_cpy->process_name);
    }

    if (lf->audit_uid){
        os_strdup(lf->audit_uid, lf_cpy->audit_uid);
    }

    if (lf->audit_name){
        os_strdup(lf->audit_name, lf_cpy->audit_name);
    }

    if (lf->effective_uid){
        os_strdup(lf->effective_uid, lf_cpy->effective_uid);
    }

    if (lf->effective_name){
        os_strdup(lf->effective_name, lf_cpy->effective_name);
    }

    if (lf->ppid){
        os_strdup(lf->ppid, lf_cpy->ppid);
    }

    if (lf->process_id){
        os_strdup(lf->process_id, lf_cpy->process_id);
    }

    lf_cpy->mtime_before = lf->mtime_before;
    lf_cpy->mtime_after = lf->mtime_after;
    lf_cpy->inode_before = lf->inode_before;
    lf_cpy->inode_after = lf->inode_after;
    lf_cpy->r_firedtimes = lf->r_firedtimes;


    if(lf->diff){
        os_strdup(lf->diff,lf_cpy->diff);
    }

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
