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

#define CVE_DBS_PATH         "wodles/"
#define CVE_DB CVE_DBS_PATH "cve.db"

#define AGENTS_TABLE        "AGENTS"
#define CVE_TABLE           "VULNERABILITIES"
#define CVE_INFO_TABLE      "VULNERABILITIES_INFO"
#define INFO_STATE_TABLE    "INFO_STATE"
#define METADATA_TABLE      "METADATA"
#define MAX_QUERY_SIZE      OS_SIZE_1024
#define MAX_SQL_ATTEMPTS    10
#define VU_MAX_PACK_REQ     40

#define SELECT_QUERY        "SELECT %s FROM %s WHERE %s;"
#define DELETE_QUERY        "DELETE FROM %s WHERE %s;"
#define TIMESTAMP_QUERY     "SELECT TIMESTAMP FROM " METADATA_TABLE " WHERE OS = ?;"
#define VU_INSERT_QUERY     "INSERT INTO "
#define VU_INSERT_CVE       "INSERT INTO " CVE_TABLE " VALUES(?,?,?,?,?,?);"
#define VU_INSERT_CVE_INFO  "INSERT INTO " CVE_INFO_TABLE " VALUES(?,?,?,?,?,?,?,?);"
#define VU_INSERT_METADATA  "INSERT INTO " METADATA_TABLE " VALUES(?,?,?,?,?);"
#define VU_INSERT_AGENTS    "INSERT INTO " AGENTS_TABLE " VALUES(?,?,?,?);"
#define VU_UPDATE_CVE       "UPDATE " CVE_TABLE " SET OPERATION = ? WHERE OPERATION = ?;"
#define VU_UPDATE_CVE2      "UPDATE " CVE_TABLE " SET OPERATION = ?, OPERATION_VALUE = ? WHERE OPERATION = ?;"
#define VU_JOIN_QUERY       "SELECT ID, PACKAGE_NAME, TITLE, SEVERITY, PUBLISHED, UPDATED, REFERENCE, RATIONALE, VERSION, OPERATION, OPERATION_VALUE, PENDING FROM " CVE_INFO_TABLE " INNER JOIN " CVE_TABLE " ON ID = CVEID INNER JOIN " AGENTS_TABLE " ON PACKAGE_NAME = PACKAGE WHERE AGENT_ID = ? AND VULNERABILITIES_INFO.OS = ? ORDER BY ID;"
#define VU_REMOVE_OS        "DELETE FROM %s WHERE OS = ?;"
#define VU_AGENTS_TABLE     "DELETE FROM " AGENTS_TABLE ";"
#define VU_SOFTWARE_REQUEST "agent %s sql SELECT DISTINCT NAME, VERSION, ARCHITECTURE FROM PROGRAMS LIMIT %i OFFSET %i;"
/*
#define VU_REPORT_QUERY     "SELECT " CVE_INFO_TABLE ".CVEID, PACKAGE_NAME, PENDING, "\
                            "VERSION, OPERATION, OPERATION_VALUE, TITLE, SEVERITY, "\
                            "PUBLISHED, UPDATED, REFERENCE, RATIONALE FROM" AGENTS_TABLE\
                            "INNER JOIN " CVE_TABLE "ON AGENT_ID =  AND %s.OS = '%s' AND PACKAGE_NAME = PACKAGE INNER JOIN '%s' "
*/

#define BEGIN_T             "BEGIN TRANSACTION;"
#define END_T               "END TRANSACTION;"

extern char *schema_vuln_detector_sql;

#endif
