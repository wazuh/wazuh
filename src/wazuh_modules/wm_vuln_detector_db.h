/*
 * Wazuh Module to analyze system vulnerabilities
 * Copyright (C) 2018 Wazuh Inc.
 * January 4, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_VUNALIZER_DB
#define WM_VUNALIZER_DB

#define CVE_DBS_PATH            "wodles/"
#define CVE_DB CVE_DBS_PATH     "cve.db"

#define AGENTS_TABLE            "AGENTS"
#define CVE_TABLE               "VULNERABILITIES"
#define CVE_INFO_TABLE          "VULNERABILITIES_INFO"
#define INFO_STATE_TABLE        "INFO_STATE"
#define METADATA_TABLE          "METADATA"
#define MAX_QUERY_SIZE          OS_SIZE_1024
#define MAX_SQL_ATTEMPTS        10
#define VU_MAX_PACK_REQ         40

typedef enum vu_query {
    SELECT_QUERY,
    DELETE_QUERY,
    TIMESTAMP_QUERY,
    VU_INSERT_QUERY,
    VU_INSERT_CVE,
    VU_INSERT_CVE_INFO,
    VU_INSERT_METADATA,
    VU_INSERT_AGENTS,
    VU_UPDATE_CVE,
    VU_UPDATE_CVE_VAL,
    VU_JOIN_QUERY,
    VU_REMOVE_OS,
    VU_AGENTS_TABLE,
    VU_SOFTWARE_REQUEST,
    VU_SOFTWARE_FULL_REQ,
    VU_SYSC_SCAN_REQUEST,
    VU_SYSC_UPDATE_SCAN,
    BEGIN_T,
    END_T
} vu_query;

static const char *vu_queries[] = {
    "SELECT %s FROM %s WHERE %s;",
    "DELETE FROM %s WHERE %s;",
    "SELECT TIMESTAMP FROM " METADATA_TABLE " WHERE OS = ?;",
    "INSERT INTO ",
    "INSERT INTO " CVE_TABLE " VALUES(?,?,?,?,?,?);",
    "INSERT INTO " CVE_INFO_TABLE " VALUES(?,?,?,?,?,?,?,?);",
    "INSERT INTO " METADATA_TABLE " VALUES(?,?,?,?,?);",
    "INSERT INTO " AGENTS_TABLE " VALUES(?,?,?,?);",
    "UPDATE " CVE_TABLE " SET OPERATION = ? WHERE OPERATION = ?;",
    "UPDATE " CVE_TABLE " SET OPERATION = ?, OPERATION_VALUE = ? WHERE OPERATION = ?;",
    "SELECT ID, PACKAGE_NAME, TITLE, SEVERITY, PUBLISHED, UPDATED, REFERENCE, RATIONALE, VERSION, OPERATION, OPERATION_VALUE, PENDING FROM " CVE_INFO_TABLE " INNER JOIN " CVE_TABLE " ON ID = CVEID AND " CVE_INFO_TABLE ".OS = " CVE_TABLE ".OS INNER JOIN " AGENTS_TABLE " ON PACKAGE_NAME = PACKAGE WHERE AGENT_ID = ? AND VULNERABILITIES_INFO.OS = ? ORDER BY ID;",
    "DELETE FROM %s WHERE OS = ?;",
    "DELETE FROM " AGENTS_TABLE ";",
    "agent %s sql SELECT DISTINCT NAME, VERSION, ARCHITECTURE FROM SYS_PROGRAMS WHERE TRIAGED = 0 AND SCAN_ID = '%s' LIMIT %i OFFSET %i;",
    "agent %s sql SELECT DISTINCT NAME, VERSION, ARCHITECTURE FROM SYS_PROGRAMS WHERE SCAN_ID = '%s' LIMIT %i OFFSET %i;",
    "agent %s sql SELECT SCAN_ID FROM SYS_PROGRAMS LIMIT 1;",
    "agent %s sql UPDATE SYS_PROGRAMS SET TRIAGED = 1 WHERE SCAN_ID = '%s';",
    "BEGIN TRANSACTION;",
    "END TRANSACTION;"
};

extern char *schema_vuln_detector_sql;

#endif
