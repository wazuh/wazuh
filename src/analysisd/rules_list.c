/* Copyright (C) 2015-2019, Wazuh Inc.
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

/* Rulenode local  */
RuleNode *rulenode;

/* It's used to overwrite rules */
RuleInfo *copied_rules[70000];
int num_rules_copied;


/* _OS_Addrule: Internal AddRule */
static RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule);
static int _AddtoRule(int sid, int level, int none, const char *group,
               RuleNode *r_node, RuleInfo *read_rule);

/**
 * @brief Remove rule and childs
 * @param array Array of rule childs.
 *
 * @note Does not remove RuleInfo
 */
static void remove_RuleNode(RuleNode *array);

/**
 * @brief Search rule and call remove_RuleNode to remove it
 * @param parent Rule parent
 * @param sid_rule Rule
 *
 * @note Does not remove RuleInfo
 */
static void remove_Rule(RuleNode *parent, int sid_rule);

/**
 * @brief Remove RuleInfo
 * @param r_info RuleInfo to remove.
 *
 * @note Not all fields are deleted because some fields are shared by multiples rules.
 * They are lists, sid_search, group_search, sid_prev_matched, group_prev_matched.
 */
static void free_RuleInfo(RuleInfo *r_info);

/**
 * @brief Saves the reference to the rule child in an array
 * @param orig Rule parent of all the rules
 *
 * @note Saves the reference to the childs in the copies_rules array.
 * And the childs number is stored in num_rules_copied
 */
static void savesChild(RuleNode *orig);

/**
 * @brief Sorts the array to make sure that no try to adde rule if its parent has not yet added.
 * @param sid_rule Parent ID of all the rules
 */
static void sortTheCopiedRules(int sid_rule);


/* Create the RuleList */
void OS_CreateRuleList()
{
    rulenode = NULL;
    return;
}

/* Get first node from rule */
RuleNode *OS_GetFirstRule()
{
    RuleNode *rulenode_pt = rulenode;
    return (rulenode_pt);
}

/* Search all rules, including children */
static int _AddtoRule(int sid, int level, int none, const char *group,
               RuleNode *r_node, RuleInfo *read_rule)
{
    int r_code = 0;

    /* If we don't have the first node, start from
     * the beginning of the list
     */
    if (!r_node) {
        r_node = OS_GetFirstRule();
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
int OS_AddChild(RuleInfo *read_rule, RuleNode *r_node)
{
    if (!read_rule) {
        merror("rules_list: Passing a NULL rule. Inconsistent state");
        return (1);
    }

    /* Adding for if_sid */
    if (read_rule->if_sid) {
        int val = 0;
        const char *sid;

        sid  = read_rule->if_sid;

        /* Loop to read all the rules (comma or space separated) */
        do {
            int rule_id = 0;
            if ((*sid == ',') || (*sid == ' ')) {
                val = 0;
                continue;
            } else if ((isdigit((int)*sid)) || (*sid == '\0')) {
                if (val == 0) {
                    rule_id = atoi(sid);
                    if (!_AddtoRule(rule_id, 0, 0, NULL, r_node, read_rule)) {
                        merror_exit("rules_list: Signature ID '%d' not "
                                  "found. Invalid 'if_sid'.", rule_id);
                    }
                    val = 1;
                }
            } else {
                merror_exit("rules_list: Signature ID must be an integer. "
                          "Exiting...");
            }
        } while (*sid++ != '\0');
    }

    /* Adding for if_level */
    else if (read_rule->if_level) {
        int  ilevel = 0;

        ilevel = atoi(read_rule->if_level);
        if (ilevel == 0) {
            merror("Invalid level (atoi)");
            return (1);
        }

        ilevel *= 100;

        if (!_AddtoRule(0, ilevel, 0, NULL, r_node, read_rule)) {
            merror_exit("rules_list: Level ID '%d' not "
                      "found. Invalid 'if_level'.", ilevel);
        }
    }

    /* Adding for if_group */
    else if (read_rule->if_group) {
        if (!_AddtoRule(0, 0, 0, read_rule->if_group, r_node, read_rule)) {
            merror_exit("rules_list: Group '%s' not "
                      "found. Invalid 'if_group'.", read_rule->if_group);
        }
    }

    /* Just add based on the category */
    else {
        if (!_AddtoRule(0, 0, 0, NULL, r_node, read_rule)) {
            merror_exit("rules_list: Category '%d' not "
                      "found. Invalid 'category'.", read_rule->category);
        }
    }

    /* done over here */
    return (0);
}

/* Add a rule in the chain */
static RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule)
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
int OS_AddRule(RuleInfo *read_rule)
{
    rulenode = _OS_AddRule(rulenode, read_rule);

    return (0);
}

/* Add an overwrite rule */
int OS_AddRuleInfo(RuleInfo *newrule, int sid)
{

    RuleNode *r_node = existRule(sid, rulenode);
    RuleInfo *removed;
    int i;

    if (!r_node) {
        return (0);
    }
    else {

        removed = r_node->ruleinfo;

        if (r_node->child) {

            num_rules_copied = 0;
            savesChild(r_node->child);
            sortTheCopiedRules(newrule->sigid);

            remove_Rule(NULL, sid);

            OS_AddChild(newrule, NULL);

            for (i = 0; i < num_rules_copied; i++){
                OS_AddChild(copied_rules[i], NULL);
            }
        }
        else {

            remove_Rule(NULL, sid);
            OS_AddChild(newrule, NULL);
        }

        free_RuleInfo(removed);

        return (1);
    }
}

/* Mark IDs (if_matched_sid) */
int OS_MarkID(RuleNode *r_node, RuleInfo *orig_rule)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        r_node = OS_GetFirstRule();
    }

    while (r_node) {
        if (r_node->ruleinfo->sigid == orig_rule->if_matched_sid) {
            /* If child does not have a list, create one */
            if (!r_node->ruleinfo->sid_prev_matched) {
                r_node->ruleinfo->sid_prev_matched = OSList_Create();
                if (!r_node->ruleinfo->sid_prev_matched) {
                    merror_exit(MEM_ERROR, errno, strerror(errno));
                }
                //OSList_SetFreeDataPointer(r_node->ruleinfo->sid_prev_matched, (void (*)(void *)) Free_Eventinfo);
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

/* Mark groups (if_matched_group) */
int OS_MarkGroup(RuleNode *r_node, RuleInfo *orig_rule)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        r_node = OS_GetFirstRule();
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


RuleNode *existRule (int sigid, RuleNode *array)
{
    RuleNode *tmp = array, *node = NULL;

    while(tmp != NULL){

        if (tmp->ruleinfo->sigid == sigid) {
            return tmp;
        }

        if (tmp->child){

            if(node = existRule(sigid, tmp->child), node != NULL){
                return node;
            }
        }

        tmp = tmp->next;
    }

    return node;
}


static void remove_Rule (RuleNode *parent, int sid_rule)
{
    RuleNode *tmp = NULL;
    RuleNode *prev = NULL;

    if (!parent){
        parent = OS_GetFirstRule();
    }

    while (parent){

        if (parent->child) {

            if (parent->child->ruleinfo->sigid == sid_rule) {

                tmp = parent->child;
                parent->child = parent->child->next;
                tmp->next = NULL;

                remove_RuleNode(tmp);
            }
            else {

                prev = parent->child;
                tmp = parent->child->next;

                while (tmp) {

                    if (tmp->ruleinfo->sigid == sid_rule) {

                        prev->next = tmp->next;
                        tmp->next = NULL;

                        remove_RuleNode(tmp);

                        tmp = prev->next;
                    }
                    else {

                        prev = tmp;
                        tmp = tmp->next;
                    }
                }
            }

            tmp = parent->child;

            while (tmp) {

                if (tmp->child) {
                    remove_Rule(tmp, sid_rule);
                }

                tmp = tmp->next;
            }
        }

        parent = parent->next;
    }

}


static void remove_RuleNode (RuleNode *array)
{
    RuleNode *tmp = NULL;

    while (array){
        tmp = array;

        if (tmp->child){
            remove_RuleNode(array->child);
        }

        array = array->next;
        os_free(tmp);
    }
}


static void free_RuleInfo(RuleInfo *r_info)
{

    int i;

    if (r_info->ignore_fields) {
        os_free(r_info->ignore_fields);
    }

    if (r_info->ckignore_fields) {
        os_free(r_info->ckignore_fields);
    }

    if (r_info->group) {
        os_free(r_info->group);
    }

    if (r_info->match) {
        OSMatch_FreePattern(r_info->match);
    }

    if (r_info->regex) {
        OSRegex_FreePattern(r_info->regex);
    }

    if (r_info->day_time) {
        os_free(r_info->day_time);
    }

    if (r_info->week_day) {
        os_free(r_info->week_day);
    }

    if (r_info->srcip) {
        i = 0;
        while(r_info->srcip[i]){
            free(r_info->srcip[i]->ip);
            free(r_info->srcip[i]);
            i++;
        }
    }

    if (r_info->dstip) {
        i = 0;
        while (r_info->dstip[i]){
            free(r_info->dstip[i]->ip);
            free(r_info->dstip[i]);
            i++;
        }
    }

    if (r_info->srcgeoip) {
        OSMatch_FreePattern(r_info->srcgeoip);
    }

    if (r_info->dstgeoip) {
        OSMatch_FreePattern(r_info->dstgeoip);
    }

    if (r_info->srcport) {
        OSMatch_FreePattern(r_info->srcport);
    }

    if (r_info->dstport) {
        OSMatch_FreePattern(r_info->dstport);
    }

    if (r_info->user) {
        OSMatch_FreePattern(r_info->user);
    }

    if (r_info->url) {
        OSMatch_FreePattern(r_info->url);
    }

    if (r_info->id) {
        OSMatch_FreePattern(r_info->id);
    }

    if (r_info->status) {
        OSMatch_FreePattern(r_info->status);
    }

    if (r_info->hostname) {
        OSMatch_FreePattern(r_info->hostname);
    }

    if (r_info->program_name) {
        OSMatch_FreePattern(r_info->program_name);
    }

    if (r_info->extra_data) {
        OSMatch_FreePattern(r_info->extra_data);
    }

    if (r_info->location) {
        OSMatch_FreePattern(r_info->location);
    }

    i = 0;
    while (r_info->fields[i]){
        os_free(r_info->fields[i]->name);
        OSRegex_FreePattern(r_info->fields[i]->regex);
        os_free(r_info->fields[i]);
        i++;
    }

    if (r_info->action) {
        os_free(r_info->action);
    }

    if (r_info->comment) {
        os_free(r_info->comment);
    }

    if (r_info->info) {
        os_free(r_info->info);
    }

    if (r_info->cve) {
        os_free(r_info->cve);
    }

    if (r_info->info_details) {
        RuleInfoDetail *tmp;

        while(r_info->info_details) {
            tmp = r_info->info_details->next;
            os_free(r_info->info_details->data);
            os_free(r_info->info_details);
            r_info->info_details = tmp;
        }
    }

    if (r_info->if_sid) {
        os_free(r_info->if_sid);
    }

    if (r_info->if_level) {
        os_free(r_info->if_level);
    }

    if (r_info->if_group) {
        os_free(r_info->if_group);
    }

    if (r_info->if_matched_regex) {
        OSRegex_FreePattern(r_info->if_matched_regex);
    }

    if (r_info->if_matched_group) {
        OSMatch_FreePattern(r_info->if_matched_group);
    }

    if (r_info->ar) {
        os_free(r_info->ar);
    }

    if (r_info->file) {
        os_free(r_info->file);
    }

    if (r_info->same_fields) {
        os_free(r_info->same_fields);
    }

    if (r_info->not_same_fields) {
        os_free(r_info->not_same_fields);
    }

    os_free(r_info);

}


static void savesChild(RuleNode *orig)
{
    RuleNode *tmp = orig;

    while (tmp) {

        copied_rules[num_rules_copied] = tmp->ruleinfo;
        num_rules_copied++;

        tmp = tmp->next;
    }

    tmp = orig;
    while (tmp) {

        if (tmp->child) {
            savesChild(tmp->child);
        }

        tmp = tmp->next;
    }
}

static void sortTheCopiedRules(int sid_rule)
{

    /* Array size and capability */
    static int CAP = 30;
    int size;
    /* Loop index */
    int i, j, k;

    /* To read all if_sid values */
    int ifsid[CAP];
    const char *sid;
    int val;

    /* To check if parent(s) are before rule */
    bool is_previously[CAP];


    for (i = 1; i < num_rules_copied - 3; i++) {


        /*  */
        if (copied_rules[i]->if_sid) {

            /* Read all if_sid values */
            sid  = copied_rules[i]->if_sid;
            size = 0;
            val = 0;

            do {
                if ((*sid == ',') || (*sid == ' ')) {

                    val = 0;
                    continue;
                }
                else if ((isdigit((int)*sid)) || (*sid == '\0')) {

                    if (val == 0 && size < CAP) {

                        ifsid[size] = atoi(sid);
                        size++;

                        val = 1;
                    }
                }

            } while (*sid++ != '\0');

        }
        else if (copied_rules[i]->if_matched_sid != 0) {

            ifsid[size] = copied_rules[i]->if_matched_sid;
            size++;
        }
        else {
            continue;
        }


        /* Check if parent is before it */
        for (k = 0; k < CAP; k++){
            is_previously[k] = 0;
        }

        for (j = 0; j < i; j++) {

            for (k = 0; k < size; k++){

                if (copied_rules[j]->sigid == ifsid[k] || ifsid[k] == sid_rule){
                    is_previously[k] = 1;
                }
            }
        }


        /* If parent isn't before, it's replace by i+1 */
        RuleInfo *aux;

        for (k = 0; k < size; k++){

            if (is_previously[k] != 1) {

                aux = copied_rules[i];
                copied_rules[i] = copied_rules[i+3];
                copied_rules[i+3] = aux;

                continue;
            }
        }

    }

}
