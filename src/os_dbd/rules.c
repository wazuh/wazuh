/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "dbd.h"
#include "config/config.h"
#include "rules_op.h"


void *_Rules_ReadInsertDB(RuleInfo *rule, void *db_config)
{
    DBConfig *dbc = (DBConfig *)db_config;
    char sql_query[OS_SIZE_1024];
    memset(sql_query, '\0', OS_SIZE_1024);

    
    merror("XXX inserting: %d", rule->sigid);

    
    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
             "INSERT INTO "
             "signature(id, rule_id, level, category, description) "
             "VALUES (NULL, '%u','%u','%s','%s') "
             "ON DUPLICATE KEY UPDATE level='%u'", 
             rule->sigid, rule->level, rule->group, rule->comment,
             rule->level);
    
    if(!osdb_query(dbc->conn, sql_query))
    {
        merror(DB_MAINERROR, ARGV0);
    }

    return(NULL);
}


int OS_InsertRulesDB(DBConfig *db_config)
{
    char **rulesfiles;
    
    rulesfiles = db_config->includes;
    while(rulesfiles && *rulesfiles)
    {
        debug1("%s: Reading rules file: '%s'", ARGV0, *rulesfiles);
        
        if(OS_ReadXMLRules(*rulesfiles, _Rules_ReadInsertDB, db_config) < 0)
        {
            merror(RULES_ERROR, ARGV0, *rulesfiles);
            return(-1);
        }

        free(*rulesfiles);
        rulesfiles++;
    }

    free(db_config->includes);
    db_config->includes = NULL;


    return(0);
}


/* EOF */
