/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "dbd.h"
#include "config/config.h"
#include "rules_op.h"

/* Prototypes */
static int __Groups_SelectGroup(const char *group, const DBConfig *db_config) __attribute((nonnull));
static int __Groups_InsertGroup(const char *group, const DBConfig *db_config) __attribute((nonnull));
static int __Groups_SelectGroupMapping(int cat_id, int rule_id, const DBConfig *db_config) __attribute((nonnull));
static int __Groups_InsertGroupMapping(int cat_id, int rule_id, const DBConfig *db_config) __attribute((nonnull));
static void _Groups_ReadInsertDB(RuleInfo *rule, const DBConfig *db_config) __attribute((nonnull));
static void *_Rules_ReadInsertDB(RuleInfo *rule, void *db_config) __attribute((nonnull));


/* Select group (categories) from the db
 * Returns 0 if not found
 */
static int __Groups_SelectGroup(const char *group, const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT cat_id FROM "
             "category WHERE cat_name = '%s'",
             group);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}

/* Insert group (categories) in to the db */
static int __Groups_InsertGroup(const char *group, const DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "INSERT INTO "
             "category(cat_name) "
             "VALUES ('%s')",
             group);

    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR, ARGV0);
    }

    return (0);
}

static int __Groups_SelectGroupMapping(int cat_id, int rule_id, const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT id FROM signature_category_mapping "
             "WHERE cat_id = '%u' AND rule_id = '%u'",
             cat_id, rule_id);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}

static int __Groups_InsertGroupMapping(int cat_id, int rule_id, const DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "INSERT INTO "
             "signature_category_mapping(cat_id, rule_id) "
             "VALUES ('%u', '%u')",
             cat_id, rule_id);

    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR, ARGV0);
    }

    return (0);
}

static void _Groups_ReadInsertDB(RuleInfo *rule, const DBConfig *db_config)
{
    /* We must insert each group separately */
    int cat_id;
    char *tmp_group;
    char *tmp_str;

    debug1("%s: DEBUG: entering _Groups_ReadInsertDB", ARGV0);

    /* If group is null, just return */
    if (rule->group == NULL) {
        return;
    }

    tmp_str = strchr(rule->group, ',');
    tmp_group = rule->group;

    /* Groups are separated by comma */
    while (tmp_group) {
        if (tmp_str) {
            *tmp_str = '\0';
            tmp_str++;
        }

        /* Remove whitespace */
        while (*tmp_group == ' ') {
            tmp_group++;
        }

        /* Check for empty group */
        if (*tmp_group == '\0') {
            tmp_group = tmp_str;
            if (tmp_group) {
                tmp_str = strchr(tmp_group, ',');
            }
            continue;
        }

        cat_id = __Groups_SelectGroup(tmp_group, db_config);

        /* Check if we have this group in the db already. If not, add it. */
        if (cat_id == 0) {
            __Groups_InsertGroup(tmp_group, db_config);
            cat_id = __Groups_SelectGroup(tmp_group, db_config);
        }

        /* If cat_id is valid (not zero), insert the mapping between
         * the category and the rule
         */
        if (cat_id != 0) {
            /* First check if the mapping is not already there */
            if (!__Groups_SelectGroupMapping(cat_id, rule->sigid, db_config)) {
                /* If not, we add it */
                __Groups_InsertGroupMapping(cat_id, rule->sigid, db_config);
            }
        }

        /* Get next category */
        tmp_group = tmp_str;
        if (tmp_group) {
            tmp_str = strchr(tmp_group, ',');
        }
    }

    return;
}

/* Insert rules in to the db */
static void *_Rules_ReadInsertDB(RuleInfo *rule, void *db_config)
{
    char sql_query[OS_SIZE_1024];
    memset(sql_query, '\0', OS_SIZE_1024);

    /* Escape strings */
    osdb_escapestr(rule->group);
    osdb_escapestr(rule->comment);

    /* Check level limit */
    if (rule->level > 20) {
        rule->level = 20;
    }
    if (rule->level < 0) {
        rule->level = 0;
    }

    debug1("%s: DEBUG: entering _Rules_ReadInsertDB()", ARGV0);

    /* Check rule limit */
    if (rule->sigid < 0 || rule->sigid > 9999999) {
        merror("%s: Invalid rule id: %u", ARGV0, rule->sigid);
        return (NULL);
    }

    /* Insert group into the signature mapping */
    _Groups_ReadInsertDB(rule, (DBConfig *) db_config);

    debug2("%s: DEBUG: Inserting: %d", ARGV0, rule->sigid);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "REPLACE INTO "
             "signature(rule_id, level, description) "
             "VALUES ('%u','%u','%s')",
             rule->sigid, rule->level, rule->comment);

    /* XXX We don't actually insert!?
    if(!osdb_query_insert(dbc->conn, sql_query))
    {
        merror(DB_GENERROR, ARGV0);
    }
    */

    return (NULL);
}

int OS_InsertRulesDB(DBConfig *db_config)
{
    char **rulesfiles;

    rulesfiles = db_config->includes;
    while (rulesfiles && *rulesfiles) {
        debug1("%s: Reading rules file: '%s'", ARGV0, *rulesfiles);

        if (OS_ReadXMLRules(*rulesfiles, _Rules_ReadInsertDB, db_config) < 0) {
            merror(RULES_ERROR, ARGV0, *rulesfiles);
            return (-1);
        }

        free(*rulesfiles);
        rulesfiles++;
    }

    free(db_config->includes);
    db_config->includes = NULL;


    return (0);
}

