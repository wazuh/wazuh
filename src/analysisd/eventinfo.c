/* Copyright (C) 2009 Trend Micro Inc.
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

/* Search last times a signature fired
 * Will look for only that specific signature.
 */
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    OSListNode *lf_node;

    /* Set frequency to 0 */
    rule->__frequency = 0;

    /* Checking if sid search is valid */
    if (!rule->sid_search) {
        merror("No sid search.");
        return (NULL);
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(rule->sid_search);
    if (!lf_node) {
        return (NULL);
    }
    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if ((c_time - lf->time.tv_sec) > rule->timeframe) {
            return (NULL);
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
            return (NULL);
        }

        /* Check if the number of matches worked */
        if (rule->__frequency <= 10) {
            rule->last_events[rule->__frequency]
                = lf->full_log;
            rule->last_events[rule->__frequency + 1]
                = NULL;
        }

        if (rule->__frequency < rule->frequency) {
            rule->__frequency++;
            continue;
        }
        rule->__frequency++;

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;
        first_lf->matched = rule->level;

        return (lf);

    } while ((lf_node = lf_node->prev) != NULL);

    return (NULL);
}

/* Search last times a group fired
 * Will look for only that specific group on that rule.
 */
Eventinfo *Search_LastGroups(Eventinfo *my_lf, RuleInfo *rule)
{
    Eventinfo *lf;
    OSListNode *lf_node;

    /* Set frequency to 0 */
    rule->__frequency = 0;

    /* Check if sid search is valid */
    if (!rule->group_search) {
        merror("No group search!");
        return (NULL);
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(rule->group_search);
    if (!lf_node) {
        return (NULL);
    }

    do {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if ((c_time - lf->time.tv_sec) > rule->timeframe) {
            return (NULL);
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
            return (NULL);
        }


        /* Check if the number of matches worked */
        if (rule->__frequency < rule->frequency) {
            if (rule->__frequency <= 10) {
                rule->last_events[rule->__frequency]
                    = lf->full_log;
                rule->last_events[rule->__frequency + 1]
                    = NULL;
            }

            rule->__frequency++;
            continue;
        }

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;

        return (lf);

    } while ((lf_node = lf_node->prev) != NULL);

    return (NULL);
}


/* Look if any of the last events (inside the timeframe)
 * match the specified rule
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *rule)
{
    EventNode *eventnode_pt;
    Eventinfo *lf;

    /* Last events */
    eventnode_pt = OS_GetLastEvent();
    if (!eventnode_pt) {
        /* Nothing found */
        return (NULL);
    }

    /* Set frequency to 0 */
    rule->__frequency = 0;

    /* Search all previous events */
    do {
        lf = eventnode_pt->event;

        /* If time is outside the timeframe, return */
        if ((c_time - lf->time.tv_sec) > rule->timeframe) {
            return (NULL);
        }

        /* The category must be the same */
        else if (lf->decoder_info->type != my_lf->decoder_info->type) {
            continue;
        }

        /* If regex does not match, go to next */
        if (rule->if_matched_regex) {
            if (!OSRegex_Execute(lf->log, rule->if_matched_regex)) {
                /* Didn't match */
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

        /* Check for different urls */
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

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            return (NULL);
        }

        /* Check if the number of matches worked */
        if (rule->__frequency < rule->frequency) {
            if (rule->__frequency <= 10) {
                rule->last_events[rule->__frequency]
                    = lf->full_log;
                rule->last_events[rule->__frequency + 1]
                    = NULL;
            }

            rule->__frequency++;
            continue;
        }

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;

        return (lf);

    } while ((eventnode_pt = eventnode_pt->next) != NULL);

    return (NULL);
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
    lf->decoder_info = NULL_Decoder;

    lf->filename = NULL;
    lf->perm_before = 0;
    lf->perm_after = 0;
    lf->md5_before = NULL;
    lf->md5_after = NULL;
    lf->sha1_before = NULL;
    lf->sha1_after = NULL;
    lf->sha256_before = NULL;
    lf->sha256_after = NULL;
    lf->user = NULL;
    lf->process = NULL;
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

    return;
}

/* Free the loginfo structure */
void Free_Eventinfo(Eventinfo *lf)
{
    if (!lf) {
        merror("Trying to free NULL event. Inconsistent..");
        return;
    }

    if (lf->comment)
        free(lf->comment);

    if (lf->full_log) {
        free(lf->full_log);
    }

    if (lf->agent_id) {
        free(lf->agent_id);
    }

    if (lf->location) {
        free(lf->location);
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
    if (lf->user) {
        free(lf->user);
    }
    if (lf->process) {
        free(lf->process);
    }
    if (lf->diff) {
        free(lf->diff);
    }

    /* Free node to delete */
    if (lf->sid_node_to_delete) {
        OSList_DeleteThisNode(lf->generated_rule->sid_prev_matched,
                              lf->sid_node_to_delete);
    } else if (lf->generated_rule && lf->generated_rule->group_prev_matched) {
        unsigned int i = 0;

        while (i < lf->generated_rule->group_prev_matched_sz) {
            OSList_DeleteOldestNode(lf->generated_rule->group_prev_matched[i]);
            i++;
        }
    }

    /* We dont need to free:
     * fts
     * comment
     */
    free(lf);
    lf = NULL;

    return;
}

/* Parse rule comment with dynamic fields */
char* ParseRuleComment(Eventinfo *lf) {
    static char final[OS_COMMENT_MAX + 1] = { '\0' };
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
