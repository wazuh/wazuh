/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "eventinfo.h"
#include "analysisd.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif


/* _OS_Addrule: Internal AddRule */
STATIC RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule);
STATIC int _AddtoRule(int sid, int level, int none, const char *group,
               RuleNode *r_node, RuleInfo *read_rule);


RuleNode *os_analysisd_rulelist;

/* Create the RuleList */
void OS_CreateRuleList() {
    os_analysisd_rulelist = NULL;
}

/* Get first node from rule */
RuleNode *OS_GetFirstRule()
{
    RuleNode *rulenode_pt = os_analysisd_rulelist;
    return (rulenode_pt);
}

/* Search all rules, including children */
STATIC int _AddtoRule(int sid, int level, int none, const char *group,
               RuleNode *r_node, RuleInfo *read_rule)
{
    int r_code = 0;

    /* If we don't have the first node, start from
     * the beginning of the list
     */
    if (!r_node) {
        return r_code;
    }

    while (r_node) {
        /* Check if the sigid matches */
        if (sid) {
            if (r_node->ruleinfo->sigid == sid) {
                /* Assign the category of this rule to the child
                 * as they must match
                 */
                read_rule->category = r_node->ruleinfo->category;

                r_node->child =
                    _OS_AddRule(r_node->child, read_rule);
                return (1);
            }
        }

        /* Check if the group matches */
        else if (group) {
            if (OS_WordMatch(group, r_node->ruleinfo->group) &&
                    (r_node->ruleinfo->sigid != read_rule->sigid)) {
                /* Loop over all rules until we find it */
                r_node->child =
                    _OS_AddRule(r_node->child, read_rule);
                r_code = 1;
            }
        }

        /* Check if the level matches */
        else if (level) {
            if ((r_node->ruleinfo->level >= level) &&
                    (r_node->ruleinfo->sigid != read_rule->sigid)) {
                r_node->child =
                    _OS_AddRule(r_node->child, read_rule);
                r_code = 1;
            }
        }

        /* If we are not searching for the sid/group, the category must
         * be the same
         */
        else if (read_rule->category != r_node->ruleinfo->category) {
            r_node = r_node->next;
            continue;
        }

        /* If none of them are set, add for the category */
        else {
            /* Set the parent category to it */
            read_rule->category = r_node->ruleinfo->category;
            r_node->child =
                _OS_AddRule(r_node->child, read_rule);
            return (1);
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            if (_AddtoRule(sid, level, none, group, r_node->child, read_rule)) {
                r_code = 1;
            }
        }

        r_node = r_node->next;
    }

    return (r_code);
}

/* Add a child */
int OS_AddChild(RuleInfo *read_rule, RuleNode **r_node, OSList* log_msg)
{
    if (read_rule == NULL) {
        smwarn(log_msg, ANALYSISD_NULL_RULE);
        return -1;
    }

    /* Adding for if_sid */
    if (read_rule->if_sid != NULL) {

        const char * sid_ptr = read_rule->if_sid;
        bool id_found = false;     // True if sid_ptr points to a sid (number)
        bool added_as_child = false; // True if the rule was added as a child of at least one rule

        /* Loop to read all the rules (comma or space separated) */
        do {
            if ((*sid_ptr == ',') || (*sid_ptr == ' ')) {
                id_found = false;
                continue;
            } else if ((isdigit((int) *sid_ptr)) || (*sid_ptr == '\0')) {

                if (!id_found) {
                    id_found = true;

                    int if_sid_rule_id = atoi(sid_ptr);

                    if (_AddtoRule(if_sid_rule_id, 0, 0, NULL, *r_node, read_rule) == 0) {
                        if (read_rule->if_matched_sid != 0) {
                            // if_matched_sid is not a list of sid, but a single sid
                            smwarn(log_msg, ANALYSISD_SIG_ID_NOT_FOUND_MID, if_sid_rule_id, read_rule->sigid);
                            return -1;
                        } else {
                            smwarn(log_msg, ANALYSISD_SIG_ID_NOT_FOUND, if_sid_rule_id, read_rule->sigid);
                        }
                    } else {
                        added_as_child = true;
                    }
                }

            } else {
                // This should not happen if the if_sid was validated on loading
                smwarn(log_msg, ANALYSISD_INV_SIG_ID, read_rule->if_matched_sid != 0 ? "if_matched_sid" : "if_sid",
                       read_rule->sigid);
                return added_as_child ? 0 : -1;
            }
        } while (*sid_ptr++ != '\0');

        // If the rule was not added as a child of at least one rule, return error
        if (!added_as_child) {
            smwarn(log_msg, ANALYSISD_EMPTY_SID, read_rule->sigid);
            return -1;
        }
    }

    /* Adding for if_level */
    else if (read_rule->if_level != NULL) {

        int ilevel = atoi(read_rule->if_level);

        if (ilevel == 0) {
            smwarn(log_msg, ANALYSISD_INV_IF_LEVEL, read_rule->if_level, read_rule->sigid);
            return -1;
        }

        ilevel *= 100;

        if (_AddtoRule(0, ilevel, 0, NULL, *r_node, read_rule) == 0) {
            smwarn(log_msg, ANALYSISD_LEVEL_NOT_FOUND, ilevel, read_rule->sigid);
            return -1;
        }
    }

    /* Adding for if_group */
    else if (read_rule->if_group != NULL) {
        if (_AddtoRule(0, 0, 0, read_rule->if_group, *r_node, read_rule) == 0) {
            smwarn(log_msg, ANALYSISD_GROUP_NOT_FOUND, read_rule->if_group, read_rule->sigid);
            return -1;
        }
    }

    /* Just add based on the category */
    else {
        if (_AddtoRule(0, 0, 0, NULL, *r_node, read_rule) == 0) {
            smwarn(log_msg, ANALYSISD_CATEGORY_NOT_FOUND, read_rule->sigid);
            return -1;
        }
    }

    /* done over here */
    return (0);
}

/* Add a rule in the chain */
STATIC RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule)
{
    RuleNode *tmp_rulenode = _rulenode;

    if (tmp_rulenode != NULL) {
        int middle_insertion = 0;
        RuleNode *prev_rulenode = NULL;
        RuleNode *new_rulenode = NULL;

        while (tmp_rulenode != NULL) {
            if (read_rule->level > tmp_rulenode->ruleinfo->level) {
                middle_insertion = 1;
                break;
            }
            prev_rulenode = tmp_rulenode;
            tmp_rulenode = tmp_rulenode->next;
        }

        new_rulenode = (RuleNode *)calloc(1, sizeof(RuleNode));

        if (!new_rulenode) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        if (middle_insertion == 1) {
            if (prev_rulenode == NULL) {
                _rulenode = new_rulenode;
            } else {
                prev_rulenode->next = new_rulenode;
            }

            new_rulenode->next = tmp_rulenode;
            new_rulenode->ruleinfo = read_rule;
            new_rulenode->child = NULL;
        } else {
            prev_rulenode->next = new_rulenode;
            prev_rulenode->next->ruleinfo = read_rule;
            prev_rulenode->next->next = NULL;
            prev_rulenode->next->child = NULL;
        }
    } else {
        _rulenode = (RuleNode *)calloc(1, sizeof(RuleNode));
        if (_rulenode == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        _rulenode->ruleinfo = read_rule;
        _rulenode->next = NULL;
        _rulenode->child = NULL;
    }

    return (_rulenode);
}

/* External AddRule */
int OS_AddRule(RuleInfo *read_rule, RuleNode **r_node)
{
    *r_node = _OS_AddRule(*r_node, read_rule);

    return (0);
}

/* Update rule info for overwritten ones */
int OS_AddRuleInfo(RuleNode *r_node, RuleInfo *newrule, int sid, OSList* log_msg)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        return -1;
    }

    if (sid == 0) {
        return (0);
    }

    while (r_node) {
        /* Check if the sigid matches */
        if (r_node->ruleinfo->sigid == sid) {
            r_node->ruleinfo->level = newrule->level;
            r_node->ruleinfo->maxsize = newrule->maxsize;
            r_node->ruleinfo->frequency = newrule->frequency;
            r_node->ruleinfo->timeframe = newrule->timeframe;
            r_node->ruleinfo->context = newrule->context;

            r_node->ruleinfo->ignore_time = newrule->ignore_time;
            r_node->ruleinfo->ignore = newrule->ignore;
            r_node->ruleinfo->ckignore = newrule->ckignore;
            free_strarray(r_node->ruleinfo->ignore_fields);
            r_node->ruleinfo->ignore_fields = newrule->ignore_fields;
            free_strarray(r_node->ruleinfo->ckignore_fields);
            r_node->ruleinfo->ckignore_fields = newrule->ckignore_fields;

            r_node->ruleinfo->alert_opts = newrule->alert_opts;
            r_node->ruleinfo->context_opts = newrule->context_opts;
            r_node->ruleinfo->same_field = newrule->same_field;
            r_node->ruleinfo->different_field = newrule->different_field;
            r_node->ruleinfo->category = newrule->category;
            r_node->ruleinfo->decoded_as = newrule->decoded_as;

            os_free(r_node->ruleinfo->group);
            r_node->ruleinfo->group = newrule->group;

            w_free_expression_t(&r_node->ruleinfo->match);
            r_node->ruleinfo->match = newrule->match;
            w_free_expression_t(&r_node->ruleinfo->regex);
            r_node->ruleinfo->regex = newrule->regex;

            os_free(r_node->ruleinfo->day_time);
            r_node->ruleinfo->day_time = newrule->day_time;
            os_free(r_node->ruleinfo->week_day);
            r_node->ruleinfo->week_day = newrule->week_day;

            w_free_expression_t(&r_node->ruleinfo->srcip);
            r_node->ruleinfo->srcip = newrule->srcip;
            w_free_expression_t(&r_node->ruleinfo->dstip);
            r_node->ruleinfo->dstip = newrule->dstip;
#ifdef LIBGEOIP_ENABLED
            w_free_expression_t(&r_node->ruleinfo->srcgeoip);
            r_node->ruleinfo->srcgeoip = newrule->srcgeoip;
            w_free_expression_t(&r_node->ruleinfo->dstgeoip);
            r_node->ruleinfo->dstgeoip = newrule->dstgeoip;
#endif
            w_free_expression_t(&r_node->ruleinfo->srcport);
            r_node->ruleinfo->srcport = newrule->srcport;
            w_free_expression_t(&r_node->ruleinfo->dstport);
            r_node->ruleinfo->dstport = newrule->dstport;
            w_free_expression_t(&r_node->ruleinfo->user);
            r_node->ruleinfo->user = newrule->user;
            w_free_expression_t(&r_node->ruleinfo->url);
            r_node->ruleinfo->url = newrule->url;
            w_free_expression_t(&r_node->ruleinfo->id);
            r_node->ruleinfo->id = newrule->id;
            w_free_expression_t(&r_node->ruleinfo->status);
            r_node->ruleinfo->status = newrule->status;
            w_free_expression_t(&r_node->ruleinfo->hostname);
            r_node->ruleinfo->hostname = newrule->hostname;
            w_free_expression_t(&r_node->ruleinfo->program_name);
            r_node->ruleinfo->program_name = newrule->program_name;
            w_free_expression_t(&r_node->ruleinfo->data);
            r_node->ruleinfo->data = newrule->data;
            w_free_expression_t(&r_node->ruleinfo->extra_data);
            r_node->ruleinfo->extra_data = newrule->extra_data;
            w_free_expression_t(&r_node->ruleinfo->location);
            r_node->ruleinfo->location = newrule->location;
            w_free_expression_t(&r_node->ruleinfo->system_name);
            r_node->ruleinfo->system_name = newrule->system_name;
            w_free_expression_t(&r_node->ruleinfo->protocol);
            r_node->ruleinfo->protocol = newrule->protocol;
            if (r_node->ruleinfo->fields) {
                for (int i = 0; r_node->ruleinfo->fields[i]; i++) {
                    os_free(r_node->ruleinfo->fields[i]->name);
                    w_free_expression_t(&r_node->ruleinfo->fields[i]->regex);
                    os_free(r_node->ruleinfo->fields[i]);
                }
                os_free(r_node->ruleinfo->fields);
            }
            r_node->ruleinfo->fields = newrule->fields;
            w_free_expression_t(&r_node->ruleinfo->action);
            r_node->ruleinfo->action = newrule->action;

            os_free(r_node->ruleinfo->comment);
            r_node->ruleinfo->comment = newrule->comment;
            os_free(r_node->ruleinfo->info);
            r_node->ruleinfo->info = newrule->info;
            os_free(r_node->ruleinfo->cve);
            r_node->ruleinfo->cve = newrule->cve;

            if (r_node->ruleinfo->info_details) {
                RuleInfoDetail *tmp;
                while (r_node->ruleinfo->info_details) {
                    tmp = r_node->ruleinfo->info_details;
                    r_node->ruleinfo->info_details = r_node->ruleinfo->info_details->next;
                    os_free(tmp->data);
                    os_free(tmp);
                }
            }
            r_node->ruleinfo->info_details = newrule->info_details;
            if (r_node->ruleinfo->lists) {
                os_remove_cdbrules(&r_node->ruleinfo->lists);
            }
            r_node->ruleinfo->lists = newrule->lists;

            /*
                if_sid, if_group, and if_level cannot be overwritten.
                When the new rule tries to replace the value throws a warning.
            */

            if (newrule->if_sid && !newrule->if_matched_sid) {
                if (!r_node->ruleinfo->if_sid ||
                        strcmp(r_node->ruleinfo->if_sid, newrule->if_sid)) {
                    smwarn(log_msg, ANALYSISD_INV_OVERWRITE, "if_sid", sid);
                }
            }

            os_free(newrule->if_sid);

            if (newrule->if_group && !newrule->if_matched_group) {
                if (!r_node->ruleinfo->if_group ||
                        strcmp(r_node->ruleinfo->if_group, newrule->if_group)) {
                    smwarn(log_msg, ANALYSISD_INV_OVERWRITE, "if_group", sid);
                }
            }
            if (newrule->if_level) {
                if (!r_node->ruleinfo->if_level ||
                        strcmp(r_node->ruleinfo->if_level, newrule->if_level)) {
                    smwarn(log_msg, ANALYSISD_INV_OVERWRITE, "if_level", sid);
                }
            }

            os_free(newrule->if_level);

            if (r_node->ruleinfo->if_matched_regex) {
                OSRegex_FreePattern(r_node->ruleinfo->if_matched_regex);
                os_free(r_node->ruleinfo->if_matched_regex);
            }
            r_node->ruleinfo->if_matched_regex = newrule->if_matched_regex;

            if (newrule->if_matched_group) {
                if (!r_node->ruleinfo->if_matched_group ||
                        strcmp(r_node->ruleinfo->if_matched_group->raw, newrule->if_matched_group->raw)) {
                    smwarn(log_msg, ANALYSISD_INV_OVERWRITE, "if_matched_group", sid);
                }
                OSMatch_FreePattern(newrule->if_matched_group);
                os_free(newrule->if_matched_group);
            }

            if (newrule->if_matched_sid) {
                if (!r_node->ruleinfo->if_matched_sid ||
                        r_node->ruleinfo->if_matched_sid != newrule->if_matched_sid) {
                    smwarn(log_msg, ANALYSISD_INV_OVERWRITE, "if_matched_sid", sid);
                }
            }

            r_node->ruleinfo->compiled_rule = newrule->compiled_rule;

            os_free(r_node->ruleinfo->ar);
            r_node->ruleinfo->ar = newrule->ar;

            os_free(r_node->ruleinfo->file);
            r_node->ruleinfo->file = newrule->file;

            free_strarray(r_node->ruleinfo->same_fields);
            r_node->ruleinfo->same_fields = newrule->same_fields;
            free_strarray(r_node->ruleinfo->not_same_fields);
            r_node->ruleinfo->not_same_fields = newrule->not_same_fields;

            free_strarray(r_node->ruleinfo->mitre_id);
            r_node->ruleinfo->mitre_id = newrule->mitre_id;
            free_strarray(r_node->ruleinfo->mitre_tactic_id);
            r_node->ruleinfo->mitre_tactic_id = newrule->mitre_tactic_id;
            free_strarray(r_node->ruleinfo->mitre_technique_id);
            r_node->ruleinfo->mitre_technique_id = newrule->mitre_technique_id;

            /* Finally the reference to newrule is store so it is freed at the end */

            if (r_node->ruleinfo->rule_overwrite == NULL) {
                r_node->ruleinfo->rule_overwrite = OSList_Create();
                OSList_SetFreeDataPointer(r_node->ruleinfo->rule_overwrite, free);
            }

            OSList_PushData(r_node->ruleinfo->rule_overwrite, newrule);

            return (1);
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            if (OS_AddRuleInfo(r_node->child, newrule, sid, log_msg)) {
                return (1);
            }
        }

        r_node = r_node->next;
    }

    return (0);
}

/* Mark rules that match specific id (for if_matched_sid) */
int OS_MarkID(RuleNode *r_node, RuleInfo *orig_rule)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        return -1;
    }

    while (r_node) {
        if (r_node->ruleinfo->sigid == orig_rule->if_matched_sid) {
            /* If child does not have a list, create one */
            if (!r_node->ruleinfo->sid_prev_matched) {
                r_node->ruleinfo->sid_prev_matched = OSList_Create();
                if (!r_node->ruleinfo->sid_prev_matched) {
                    merror_exit(MEM_ERROR, errno, strerror(errno));
                }
            }

            /* Assign the parent pointer to it */
            orig_rule->sid_search = r_node->ruleinfo->sid_prev_matched;
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            OS_MarkID(r_node->child, orig_rule);
        }

        r_node = r_node->next;
    }

    return (0);
}

/* Mark rules that match specific group (for if_matched_group) */
int OS_MarkGroup(RuleNode *r_node, RuleInfo *orig_rule)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        return -1;
    }

    while (r_node) {
        if (OSMatch_Execute(r_node->ruleinfo->group,
                            strlen(r_node->ruleinfo->group),
                            orig_rule->if_matched_group)) {
            unsigned int rule_g = 0;
            if (r_node->ruleinfo->group_prev_matched) {
                while (r_node->ruleinfo->group_prev_matched[rule_g]) {
                    rule_g++;
                }
            }

            os_realloc(r_node->ruleinfo->group_prev_matched,
                       (rule_g + 2)*sizeof(OSList *),
                       r_node->ruleinfo->group_prev_matched);

            r_node->ruleinfo->group_prev_matched[rule_g] = NULL;
            r_node->ruleinfo->group_prev_matched[rule_g + 1] = NULL;

            /* Set the size */
            r_node->ruleinfo->group_prev_matched_sz = rule_g + 1;

            r_node->ruleinfo->group_prev_matched[rule_g] =
                orig_rule->group_search;
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            OS_MarkGroup(r_node->child, orig_rule);
        }

        r_node = r_node->next;
    }

    return (0);
}

void os_remove_rules_list(RuleNode *node) {

    RuleInfo **rules;
    int pos = 0;
    int num_rules = 0;

    os_count_rules(node, &num_rules);

    os_calloc(num_rules + 1, sizeof(RuleInfo *), rules);

    os_remove_rulenode(node, rules, &pos, &num_rules);

    for (int i = 0; i <= pos; i++) {
        os_remove_ruleinfo(rules[i]);
    }

    os_free(rules);
}


void os_remove_rulenode(RuleNode *node, RuleInfo **rules, int *pos, int *max_size) {

    RuleNode *tmp;

    while (node) {

        if (node->child) {
            os_remove_rulenode(node->child, rules, pos, max_size);
        }

        tmp = node;
        node = node->next;

        if (tmp->ruleinfo->internal_saving == false && *pos <= *max_size) {

            tmp->ruleinfo->internal_saving = true;
            rules[*pos] = tmp->ruleinfo;
            (*pos)++;
        }

        os_free(tmp);
    }
}

void os_remove_ruleinfo(RuleInfo *ruleinfo) {

    if (!ruleinfo) {
        return;
    }

    free_strarray(ruleinfo->ignore_fields);
    free_strarray(ruleinfo->ckignore_fields);

    if (ruleinfo->group_search) {
        OSList_Destroy(ruleinfo->group_search);
    }

    os_free(ruleinfo->sid_prev_matched);
    os_free(ruleinfo->group_prev_matched);

    os_free(ruleinfo->group);
    w_free_expression_t(&ruleinfo->match);
    w_free_expression_t(&ruleinfo->regex);

    os_free(ruleinfo->day_time);
    os_free(ruleinfo->week_day);

    w_free_expression_t(&ruleinfo->srcip);
    w_free_expression_t(&ruleinfo->dstip);
    w_free_expression_t(&ruleinfo->srcgeoip);
    w_free_expression_t(&ruleinfo->dstgeoip);
    w_free_expression_t(&ruleinfo->srcport);
    w_free_expression_t(&ruleinfo->dstport);
    w_free_expression_t(&ruleinfo->user);
    w_free_expression_t(&ruleinfo->url);
    w_free_expression_t(&ruleinfo->id);
    w_free_expression_t(&ruleinfo->status);
    w_free_expression_t(&ruleinfo->hostname);
    w_free_expression_t(&ruleinfo->program_name);
    w_free_expression_t(&ruleinfo->data);
    w_free_expression_t(&ruleinfo->extra_data);
    w_free_expression_t(&ruleinfo->location);
    w_free_expression_t(&ruleinfo->system_name);
    w_free_expression_t(&ruleinfo->protocol);
    if (ruleinfo->fields) {
        for (int i = 0; ruleinfo->fields[i]; i++) {
            os_free(ruleinfo->fields[i]->name);
            w_free_expression_t(&ruleinfo->fields[i]->regex);
            os_free(ruleinfo->fields[i]);
        }
        os_free(ruleinfo->fields);
    }
    w_free_expression_t(&ruleinfo->action);

    os_free(ruleinfo->comment);
    os_free(ruleinfo->info);
    os_free(ruleinfo->cve);

    if (ruleinfo->info_details) {
        RuleInfoDetail *tmp;
        while (ruleinfo->info_details) {
            tmp = ruleinfo->info_details;
            ruleinfo->info_details = ruleinfo->info_details->next;
            os_free(tmp->data);
            os_free(tmp);
        }
    }
    if (ruleinfo->lists) {
        os_remove_cdbrules(&ruleinfo->lists);
    }

    os_free(ruleinfo->if_sid);
    os_free(ruleinfo->if_level);
    os_free(ruleinfo->if_group);

    if (ruleinfo->if_matched_regex) {
        OSRegex_FreePattern(ruleinfo->if_matched_regex);
        os_free(ruleinfo->if_matched_regex);
    }

    if (ruleinfo->if_matched_group) {
        OSMatch_FreePattern(ruleinfo->if_matched_group);
        os_free(ruleinfo->if_matched_group);
    }

    os_free(ruleinfo->ar);
    os_free(ruleinfo->file);
    free_strarray(ruleinfo->same_fields);
    free_strarray(ruleinfo->not_same_fields);
    free_strarray(ruleinfo->mitre_id);
    free_strarray(ruleinfo->mitre_tactic_id);
    free_strarray(ruleinfo->mitre_technique_id);

    OSList_Destroy(ruleinfo->rule_overwrite);
    os_free(ruleinfo);
}

void os_count_rules(RuleNode *node, int *num_rules) {

    while (node) {

        if (node->child) {
            os_count_rules(node->child, num_rules);
        }

        (*num_rules)++;

        node = node->next;
    }
}
