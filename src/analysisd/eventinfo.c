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


/* Search last times a signature fired
 * Will look for only that specific signature.
 */
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    OSListNode *lf_node;

    /* Set frequency to 0 */
    currently_rule->__frequency = 0;

    /* Checking if sid search is valid */
    if (!currently_rule->sid_search) {
        merror("%s: No sid search!! XXX", ARGV0);
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(currently_rule->sid_search);
    if (!lf_node) {
        return (NULL);
    }
    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if ((c_time - lf->time) > currently_rule->timeframe) {
            return (NULL);
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= currently_rule->level) {
            return (NULL);
        }

        /* Check for same ID */
        if (currently_rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (currently_rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (currently_rule->alert_opts & SAME_EXTRAINFO) {
            /* Check for same source port */
            if (currently_rule->context_opts & SAME_SRCPORT) {
                if ((!lf->srcport) || (!my_lf->srcport)) {
                    continue;
                }

                if (strcmp(lf->srcport, my_lf->srcport) != 0) {
                    continue;
                }
            }

            /* Check for same dst port */
            if (currently_rule->context_opts & SAME_DSTPORT) {
                if ((!lf->dstport) || (!my_lf->dstport)) {
                    continue;
                }

                if (strcmp(lf->dstport, my_lf->dstport) != 0) {
                    continue;
                }
            }

            /* Check for repetitions on user error */
            if (currently_rule->context_opts & SAME_USER) {
                if ((!lf->dstuser) || (!my_lf->dstuser)) {
                    continue;
                }

                if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                    continue;
                }
            }

            /* Check for same location */
            if (currently_rule->context_opts & SAME_LOCATION) {
                if (strcmp(lf->hostname, my_lf->hostname) != 0) {
                    continue;
                }
            }

            /* Check for different URLs */
            if (currently_rule->context_opts & DIFFERENT_URL) {
                if ((!lf->url) || (!my_lf->url)) {
                    continue;
                }

                if (strcmp(lf->url, my_lf->url) == 0) {
                    continue;
                }
            }
        }

        /* Check if the number of matches worked */
        if (currently_rule->__frequency <= 10) {
            currently_rule->last_events[currently_rule->__frequency]
                = lf->full_log;
            currently_rule->last_events[currently_rule->__frequency + 1]
                = NULL;
        }

        if (currently_rule->__frequency < currently_rule->frequency) {
            currently_rule->__frequency++;
            continue;
        }
        currently_rule->__frequency++;


        /* If reached here, we matched */
        my_lf->matched = currently_rule->level;
        lf->matched = currently_rule->level;
        first_lf->matched = currently_rule->level;

        return (lf);

    } while ((lf_node = lf_node->prev) != NULL);

    return (NULL);
}

/* Search last times a group fired
 * Will look for only that specific group on that rule.
 */
Eventinfo *Search_LastGroups(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    OSListNode *lf_node;

    /* Set frequency to 0 */
    currently_rule->__frequency = 0;

    /* Check if sid search is valid */
    if (!currently_rule->group_search) {
        merror("%s: No group search!! XXX", ARGV0);
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(currently_rule->group_search);
    if (!lf_node) {
        return (NULL);
    }
    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if ((c_time - lf->time) > currently_rule->timeframe) {
            return (NULL);
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= currently_rule->level) {
            return (NULL);
        }

        /* Check for same ID */
        if (currently_rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (currently_rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (currently_rule->alert_opts & SAME_EXTRAINFO) {
            /* Check for same source port */
            if (currently_rule->context_opts & SAME_SRCPORT) {
                if ((!lf->srcport) || (!my_lf->srcport)) {
                    continue;
                }

                if (strcmp(lf->srcport, my_lf->srcport) != 0) {
                    continue;
                }
            }

            /* Check for same dst port */
            if (currently_rule->context_opts & SAME_DSTPORT) {
                if ((!lf->dstport) || (!my_lf->dstport)) {
                    continue;
                }

                if (strcmp(lf->dstport, my_lf->dstport) != 0) {
                    continue;
                }
            }

            /* Check for repetitions on user error */
            if (currently_rule->context_opts & SAME_USER) {
                if ((!lf->dstuser) || (!my_lf->dstuser)) {
                    continue;
                }

                if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                    continue;
                }
            }

            /* Check for same location */
            if (currently_rule->context_opts & SAME_LOCATION) {
                if (strcmp(lf->hostname, my_lf->hostname) != 0) {
                    continue;
                }
            }


            /* Check for different URLs */
            if (currently_rule->context_opts & DIFFERENT_URL) {
                if ((!lf->url) || (!my_lf->url)) {
                    continue;
                }

                if (strcmp(lf->url, my_lf->url) == 0) {
                    continue;
                }
            }

        }

        /* Check if the number of matches worked */
        if (currently_rule->__frequency < currently_rule->frequency) {
            if (currently_rule->__frequency <= 10) {
                currently_rule->last_events[currently_rule->__frequency]
                    = lf->full_log;
                currently_rule->last_events[currently_rule->__frequency + 1]
                    = NULL;
            }

            currently_rule->__frequency++;
            continue;
        }


        /* If reached here, we matched */
        my_lf->matched = currently_rule->level;
        lf->matched = currently_rule->level;
        first_lf->matched = currently_rule->level;

        return (lf);


    } while ((lf_node = lf_node->prev) != NULL);

    return (NULL);
}


/* Look if any of the last events (inside the timeframe)
 * match the specified rule
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    EventNode *eventnode_pt;
    Eventinfo *lf;
    Eventinfo *first_lf;

    merror("XXXX : remove me!");

    /* Last events */
    eventnode_pt = OS_GetLastEvent();
    if (!eventnode_pt) {
        /* Nothing found */
        return (NULL);
    }

    /* Set frequency to 0 */
    currently_rule->__frequency = 0;
    first_lf = (Eventinfo *)eventnode_pt->event;

    /* Search all previous events */
    do {
        lf = eventnode_pt->event;

        /* If time is outside the timeframe, return */
        if ((c_time - lf->time) > currently_rule->timeframe) {
            return (NULL);
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= currently_rule->level) {
            return (NULL);
        }

        /* The category must be the same */
        else if (lf->decoder_info->type != my_lf->decoder_info->type) {
            continue;
        }

        /* If regex does not match, go to next */
        if (currently_rule->if_matched_regex) {
            if (!OSRegex_Execute(lf->log, currently_rule->if_matched_regex)) {
                /* Didn't match */
                continue;
            }
        }

        /* Check for repetitions on user error */
        if (currently_rule->context_opts & SAME_USER) {
            if ((!lf->dstuser) || (!my_lf->dstuser)) {
                continue;
            }

            if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                continue;
            }
        }

        /* Check for same ID */
        if (currently_rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (currently_rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Check for different urls */
        if (currently_rule->context_opts & DIFFERENT_URL) {
            if ((!lf->url) || (!my_lf->url)) {
                continue;
            }

            if (strcmp(lf->url, my_lf->url) == 0) {
                continue;
            }
        }


        /* Check if the number of matches worked */
        if (currently_rule->__frequency < currently_rule->frequency) {
            if (currently_rule->__frequency <= 10) {
                currently_rule->last_events[currently_rule->__frequency]
                    = lf->full_log;
                currently_rule->last_events[currently_rule->__frequency + 1]
                    = NULL;
            }

            currently_rule->__frequency++;
            continue;
        }

        /* If reached here, we matched */
        my_lf->matched = currently_rule->level;
        lf->matched = currently_rule->level;
        first_lf->matched = currently_rule->level;

        return (lf);

    } while ((eventnode_pt = eventnode_pt->next) != NULL);

    return (NULL);
}

/* Zero the loginfo structure */
void Zero_Eventinfo(Eventinfo *lf)
{
    lf->log = NULL;
    lf->full_log = NULL;
    lf->hostname = NULL;
    lf->program_name = NULL;
    lf->location = NULL;

    lf->srcip = NULL;
    lf->dstip = NULL;
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

    lf->time = 0;
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
    lf->size_before = NULL;
    lf->size_after = NULL;
    lf->owner_before = NULL;
    lf->owner_after = NULL;
    lf->gowner_before = NULL;
    lf->gowner_after = NULL;

    return;
}

/* Free the loginfo structure */
void Free_Eventinfo(Eventinfo *lf)
{
    if (!lf) {
        merror("%s: Trying to free NULL event. Inconsistent..", ARGV0);
        return;
    }

    if (lf->full_log) {
        free(lf->full_log);
    }
    if (lf->location) {
        free(lf->location);
    }

    if (lf->srcip) {
        free(lf->srcip);
    }
    if (lf->dstip) {
        free(lf->dstip);
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

    /* Free node to delete */
    if (lf->sid_node_to_delete) {
        OSList_DeleteThisNode(lf->generated_rule->sid_prev_matched,
                              lf->sid_node_to_delete);
    } else if (lf->generated_rule && lf->generated_rule->group_prev_matched) {
        int i = 0;

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

