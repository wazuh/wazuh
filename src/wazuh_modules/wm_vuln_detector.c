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

#ifndef WIN32

#include "wmodules.h"
#include "wm_vuln_detector_db.h"
#include "external/sqlite/sqlite3.h"
#include "addagent/manage_agents.h"
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <os_net/os_net.h>

static void * wm_vulnerability_detector_main(wm_vulnerability_detector_t * vulnerability_detector);
static void wm_vulnerability_detector_destroy(wm_vulnerability_detector_t * vulnerability_detector);
int wm_vulnerability_detector_socketconnect(char *host);
int wm_vulnerability_detector_updatedb(update_flags *flags, time_intervals *max, time_intervals *remaining);
char * wm_vulnerability_detector_preparser(cve_db dist);
int wm_vulnerability_update_oval(cve_db version);
int wm_vulnerability_fetch_oval(cve_db version, int *need_update);
int wm_vulnerability_detector_parser(OS_XML *xml, XML_NODE node, wm_vulnerability_detector_db *parsed_oval, parser_state version, cve_db dist);
int wm_vulnerability_detector_check_db();
int wm_vulnerability_detector_insert(wm_vulnerability_detector_db *parsed_oval);
int wm_vulnerability_detector_remove_OS_table(sqlite3 *db, char *TABLE, char *OS);
int wm_vulnerability_detector_sql_error(sqlite3 *db);
int wm_vulnerability_detector_sql_exec(sqlite3 *db, char *sql, size_t size, int allows_constr);
int wm_vulnerability_detector_get_software_info(agent_software *agent, sqlite3 *db);
int wm_vulnerability_detector_report_agent_vulnerabilities(agent_software *agents, sqlite3 *db, int max);
int wm_vulnerability_detector_check_agent_vulnerabilities(agent_software *agents);
int wm_vulnerability_detector_sql_prepare(sqlite3 *db, char *sql, size_t size, sqlite3_stmt **stmt);
int wm_checks_package_vulnerability(const char *package, char *version, const char *operation, char *operation_value);
void wm_vulnerability_update_intervals(time_intervals *remaining, time_t time_sleep);
int wm_vulnerability_detector_step(sqlite3_stmt *stmt);
int wm_vulnerability_create_file(const char *path, const char *source);

int *vu_queue;
const wm_context WM_VULNDETECTOR_CONTEXT = {
    "vulnerability-detector",
    (wm_routine)wm_vulnerability_detector_main,
    (wm_routine)wm_vulnerability_detector_destroy
};


int wm_vulnerability_create_file(const char *path, const char *source) {
    const char *ROOT = "root";
    const char *sql;
    const char *tail;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;
    uid_t uid;
    gid_t gid;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_DB_ERROR);
        return wm_vulnerability_detector_sql_error(db);
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_DB_ERROR);
            return wm_vulnerability_detector_sql_error(db);
        }

        result = sqlite3_step(stmt);

        switch (result) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            sqlite3_finalize(stmt);
            mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_DB_ERROR);
            return wm_vulnerability_detector_sql_error(db);
        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close_v2(db);

    uid = Privsep_GetUser(ROOT);
    gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        mterror(WM_VULNDETECTOR_LOGTAG, USER_ERROR, ROOT, GROUPGLOBAL);
        return OS_INVALID;
    }

    if (chown(path, uid, gid) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, CHOWN_ERROR, path, errno, strerror(errno));
        return OS_INVALID;
    }

    if (chmod(path, 0660) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, CHMOD_ERROR, path, errno, strerror(errno));
        return OS_INVALID;
    }

    return 0;
}

int wm_vulnerability_detector_step(sqlite3_stmt *stmt) {
    int attempts;
    int result;
    for (attempts = 0; (result = sqlite3_step(stmt)) == SQLITE_BUSY; attempts++) {
        if (attempts == MAX_SQL_ATTEMPTS) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_MAX_ACC_EXC);
            return OS_INVALID;
        }
    }
    return result;
}

int wm_checks_package_vulnerability(const char *package, char *version, const char *operation, char *operation_value) {
    if (operation_value) {
        if (!strcmp(operation, "less than")) {
            int i, j;
            int attemps = 0;
            int version_value, limit_value;
            int version_found, limit_found;
            char version_cl[KEY_SIZE];
            char limit_cl[KEY_SIZE];
            char *version_it, *version_it2;
            char *limit_it, *limit_it2;

            snprintf(version_cl, KEY_SIZE, "%s", version);
            snprintf(limit_cl, KEY_SIZE, "%s", operation_value);

            // Check EPOCH
            if (version_it = strchr(version_cl, ':'), version_it) {
                *version_it = '\0';
                version_value = strtol(version_cl, NULL, 10);
                version_it++;
            } else {
                version_it = version_cl;
                version_value = 0;
            }

            if (limit_it = strchr(limit_cl, ':'), limit_it) {
                *limit_it = '\0';
                limit_value = strtol(limit_cl, NULL, 10);
                limit_it++;
            } else {
                limit_it = limit_cl;
                limit_value = 0;
            }

            if (version_value > limit_value) {
                return 0;
            } else if (version_value < limit_value) {
                return 1;
            }

            // Check Version
            if ((version_it2 = strchr(version_it, '~')) ||
                (version_it2 = strchr(version_it, '-')) ||
                (version_it2 = strchr(version_it, '+'))) {
                *version_it2 = '\0';
                version_it2++;
                if (*version_it2 == '\0') {
                    version_it2 = NULL;
                }
            }

            if ((limit_it2 = strchr(limit_it, '~')) ||
                (limit_it2 = strchr(limit_it, '-')) ||
                (limit_it2 = strchr(limit_it, '+'))) {
                *limit_it2 = '\0';
                limit_it2++;
                if (*limit_it2 == '\0') {
                    limit_it2 = NULL;
                }
            }

            if (strcmp(version_it, limit_it)) {
                for (i = 0, j = 0, version_found = 0, limit_found = 0; attemps < VU_MAX_VERSION_ATTEMPS; attemps++) {
                    if (!version_found) {
                        if (version_it[i] == '.' || isalpha(version_it[i])) {
                            version_found = 1;
                            version_it[i] = '\0';
                        } else if (version_it[i] == '\0') {
                            version_found = 2;
                        } else {
                            i++;
                        }
                    }

                    if (!limit_found) {
                        if (limit_it[j] == '.' || isalpha(limit_it[j])) {
                            limit_found = 1;
                            limit_it[j] = '\0';
                        } else if (limit_it[j] == '\0') {
                            limit_found = 2;
                        } else {
                            j++;
                        }
                    }

                    if (version_found && limit_found) {
                        version_value = strtol(version_it, NULL, 10);
                        limit_value = strtol(limit_it, NULL, 10);
                        if (version_value > limit_value) {
                            return 0;
                        } else if (version_value < limit_value) {
                            return 1;
                        } else if (version_found != limit_found) {
                            if (version_found < limit_found) {
                                return 0;
                            } else {
                                return 1;
                            }
                        } else if (version_found > 1) {
                            break;
                        }
                        attemps = 0;
                        version_found = 0;
                        limit_found = 0;
                        version_it = &version_it[i + 1];
                        limit_it = &limit_it[j + 1];
                        i = 0;
                        j = 0;
                    }
                }
            }

            if (attemps == VU_MAX_VERSION_ATTEMPS) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_COMPARE_VERSION_ERROR, version, package, operation_value);
                return 0;
            }

            if (version_it2 && limit_it2) {
                version_it = version_it2;
                limit_it = limit_it2;
            } else {
                return 0;
            }

            // Check release
            version_found = 0;
            limit_found = 0;
            for (i = 0, j = 0, attemps = 0, version_found = 0, limit_found = 0; i < KEY_SIZE && j < KEY_SIZE;) {
                if (version_it[i] != '\0' && isdigit(version_it[i])) {
                    if (!version_found) {
                        version_it = &version_it[i];
                        version_found = 1;
                        i = -1;
                    }
                    i++;
                } else if (version_found) {
                    version_it[i] = '\0';
                } else {
                    i++;
                }

                if (limit_it[j] != '\0' && isdigit(limit_it[j])) {
                    if (!limit_found) {
                        limit_it = &limit_it[j];
                        limit_found = 1;
                        j = -1;
                    }
                    j++;
                } else if (limit_found) {
                    limit_it[j] = '\0';
                } else {
                    j++;
                }

                if (version_found && limit_found) {
                    version_value = strtol(version_it, NULL, 10);
                    limit_value = strtol(limit_it, NULL, 10);
                    if (version_value > limit_value) {
                        return 0;
                    } else if (version_value < limit_value) {
                        return 1;
                    }
                    version_found = 0;
                    limit_found = 0;
                    if (!(i < (KEY_SIZE - 1) && j < (KEY_SIZE - 1))) {
                        return 0;
                    }
                    version_it = &version_it[i + 1];
                    limit_it = &limit_it[j + 1];
                    if (*version_it == '\0' || *limit_it == '\0') {
                        break;
}
                    i = 0;
                    j = 0;
                }
            }
        }
        return 0;
    }
    return 2;
}

int wm_vulnerability_detector_report_agent_vulnerabilities(agent_software *agents, sqlite3 *db, int max) {
    sqlite3_stmt *stmt = NULL;
    char alert_msg[OS_MAXSTR];
    char header[OS_SIZE_256];
    int size;
    agent_software *agents_it;
    cJSON *alert = NULL;
    cJSON *alert_cve = NULL;
    char *str_json;
    char *cve;
    char *title;
    char *severity;
    char *published;
    char *updated;
    char *reference;
    char *rationale;
    int i;

    if (alert = cJSON_CreateObject(), !alert) {
        return OS_INVALID;
    }

    for (agents_it = agents, i = 0; agents_it && i < max; agents_it = agents_it->prev, i++) {
        if (!agents_it->info) {
            continue;
        }

        if (sqlite3_prepare_v2(db, VU_JOIN_QUERY, -1, &stmt, NULL) != SQLITE_OK) {
            cJSON_free(alert);
            return wm_vulnerability_detector_sql_error(db);
        }
        sqlite3_bind_int(stmt, 1,  strtol(agents_it->agent_id, NULL, 10));
        sqlite3_bind_text(stmt, 2, agents_it->OS, -1, NULL);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            char *package;
            char *version;
            char *operation;
            char *operation_value;
            int pending = 0;
            char state[50];
            int v_type;

            cve = (char *)sqlite3_column_text(stmt, 0);
            package = (char *)sqlite3_column_text(stmt, 1);
            title = (char *)sqlite3_column_text(stmt, 2);
            severity = (char *)sqlite3_column_text(stmt, 3);
            published = (char *)sqlite3_column_text(stmt, 4);
            updated = (char *)sqlite3_column_text(stmt, 5);
            reference = (char *)sqlite3_column_text(stmt, 6);
            rationale = (char *)sqlite3_column_text(stmt, 7);
            version = (char *)sqlite3_column_text(stmt, 8);
            operation = (char *)sqlite3_column_text(stmt, 9);
            operation_value = (char *)sqlite3_column_text(stmt, 10);
            pending = sqlite3_column_int(stmt, 11);

            if (*updated == '\0') {
                updated = published;
            }
            if (pending) {
                size = snprintf(state, 30, "Pending confirmation");
            } else if (v_type = wm_checks_package_vulnerability(package, version, operation, operation_value), v_type) {
                if (v_type != 2) {
                    size = snprintf(state, 15, "Fixed");
                    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_PACK_VER_VULN, package, version, operation_value, agents_it->agent_id, cve);
                } else {
                    size = snprintf(state, 15, "Unfixed");
                    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_PACK_VULN, package, cve);
                }
            } else {
                mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_NOT_VULN, package, version, operation_value, agents_it->agent_id, cve);
                continue;
            }
            state[size] = '\0';

            if (alert_cve = cJSON_CreateObject(), alert_cve) {
                cJSON_AddStringToObject(alert_cve, "cve", cve);
                cJSON_AddStringToObject(alert_cve, "title", title);
                cJSON_AddStringToObject(alert_cve, "severity", severity);
                cJSON_AddStringToObject(alert_cve, "published", published);
                cJSON_AddStringToObject(alert_cve, "updated", updated);
                cJSON_AddStringToObject(alert_cve, "reference", reference);
                cJSON_AddStringToObject(alert_cve, "rationale", rationale);
                cJSON_AddStringToObject(alert_cve, "state", state);
                cJSON_AddStringToObject(alert_cve, "affected_package", package);
                cJSON_AddStringToObject(alert_cve, "version", version);
                cJSON_AddItemToObject(alert, "vulnerability", alert_cve);
            } else {
                cJSON_Delete(alert);
                return OS_INVALID;
            }

            str_json = cJSON_PrintUnformatted(alert);
            snprintf(header, OS_SIZE_256, VU_ALERT_HEADER, agents_it->agent_id, agents_it->agent_name, agents_it->agent_ip);
            snprintf(alert_msg, OS_MAXSTR, VU_ALERT_JSON, str_json);
            free(str_json);

            if (SendMSG(*vu_queue, alert_msg, header, SECURE_MQ) < 0) {
                mterror(WM_VULNDETECTOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                if ((*vu_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                    mterror_exit(WM_VULNDETECTOR_LOGTAG, QUEUE_FATAL, DEFAULTQUEUE);
                }
            }

            cJSON_Delete(alert_cve);
            alert->child = NULL;
        }

        sqlite3_finalize(stmt);
    }

    cJSON_Delete(alert);

    return 0;
}


int wm_vulnerability_detector_check_agent_vulnerabilities(agent_software *agents) {
    agent_software *agents_it;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int i;

    if (!agents) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_AG_TARGET_ERROR);
        return OS_INVALID;
    } else if (wm_vulnerability_detector_check_db()) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CHECK_DB_ERROR);
        return OS_INVALID;
    } else if (sqlite3_open_v2(CVE_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db);
    }

    if (sqlite3_prepare_v2(db, VU_AGENTS_TABLE, -1, &stmt, NULL) != SQLITE_OK) {
            return wm_vulnerability_detector_sql_error(db);
    }
    if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return wm_vulnerability_detector_sql_error(db);
    }
    sqlite3_finalize(stmt);

    for (i = 1, agents_it = agents;; i++) {
        if (wm_vulnerability_detector_get_software_info(agents_it, db)) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_GET_SOFTWARE_ERROR);
            return OS_INVALID;
        }

        if (VU_AGENT_REQUEST_LIMIT && i == VU_AGENT_REQUEST_LIMIT) {
            wm_vulnerability_detector_report_agent_vulnerabilities(agents_it, db, i);
            i = 0;
            if (sqlite3_prepare_v2(db, VU_AGENTS_TABLE, -1, &stmt, NULL) != SQLITE_OK) {
                    sqlite3_finalize(stmt);
                    return wm_vulnerability_detector_sql_error(db);
            }
            if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
                sqlite3_finalize(stmt);
                return wm_vulnerability_detector_sql_error(db);
            }
            sqlite3_finalize(stmt);
        }
        if (agents_it->next) {
            agents_it = agents_it->next;
        } else {
            break;
        }
    }

    if (!VU_AGENT_REQUEST_LIMIT) {
        wm_vulnerability_detector_report_agent_vulnerabilities(agents_it, db, i);
    }

    sqlite3_close(db);
    return 0;
}

int wm_vulnerability_detector_sql_error(sqlite3 *db) {
    mterror(WM_VULNDETECTOR_LOGTAG, VU_SQL_ERROR, sqlite3_errmsg(db));
    sqlite3_close(db);
    return OS_INVALID;
}

int wm_vulnerability_detector_sql_prepare(sqlite3 *db, char *sql, size_t size, sqlite3_stmt **stmt) {
    if (sql[size - 1] != ';') {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_QUERY_ERROR);
        return OS_INVALID;
    }
    if (sqlite3_prepare_v2(db, sql, size, stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db);
    }
    return 0;
}

int wm_vulnerability_detector_sql_exec(sqlite3 *db, char *sql, size_t size, int allows_constr) {
    int result;
    if (sql[size - 1] != ';') {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_QUERY_ERROR);
        return OS_INVALID;
    }
    if (result = sqlite3_exec(db, sql, NULL, NULL, NULL), result != SQLITE_OK && !(allows_constr && result == SQLITE_CONSTRAINT)) {
        return wm_vulnerability_detector_sql_error(db);
    }
    return 0;
}

int wm_vulnerability_detector_remove_OS_table(sqlite3 *db, char *TABLE, char *OS) {
    sqlite3_stmt *stmt = NULL;
    char sql[MAX_QUERY_SIZE];
    size_t size;

    if (size = snprintf(sql, MAX_QUERY_SIZE, VU_REMOVE_OS, TABLE), sql[size - 1] != ';') {
        return OS_INVALID;
    }

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db);
    }

    sqlite3_bind_text(stmt, 1, OS, -1, NULL);

    if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
        return wm_vulnerability_detector_sql_error(db);
    }
    sqlite3_finalize(stmt);

    return 0;
}

int wm_vulnerability_detector_insert(wm_vulnerability_detector_db *parsed_oval) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int result;
    oval_metadata *met_it = &parsed_oval->metadata;
    vulnerability *vul_it = parsed_oval->vulnerabilities;
    info_state *state_it = parsed_oval->info_states;
    info_test *test_it = parsed_oval->info_tests;
    info_cve *info_it = parsed_oval->info_cves;

    if (sqlite3_open_v2(CVE_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db);
    }
    if (wm_vulnerability_detector_remove_OS_table(db, CVE_TABLE, parsed_oval->OS)        ||
        wm_vulnerability_detector_remove_OS_table(db, METADATA_TABLE, parsed_oval->OS)   ||
        wm_vulnerability_detector_remove_OS_table(db, CVE_INFO_TABLE, parsed_oval->OS)) {
        return wm_vulnerability_detector_sql_error(db);
    }

    sqlite3_exec(db, BEGIN_T, NULL, NULL, NULL);

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_VU);

    while (vul_it) {
        // If you do not have this field, it has been discarded by the preparser and the OS is not affected
        if (vul_it->state_id) {
            if (sqlite3_prepare_v2(db, VU_INSERT_CVE, -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db);
            }

            sqlite3_bind_text(stmt, 1, vul_it->cve_id, -1, NULL);
            sqlite3_bind_text(stmt, 2, parsed_oval->OS, -1, NULL);
            sqlite3_bind_text(stmt, 3, vul_it->package_name, -1, NULL);
            sqlite3_bind_int(stmt, 4, vul_it->pending);
            sqlite3_bind_text(stmt, 5, vul_it->state_id, -1, NULL);
            sqlite3_bind_text(stmt, 6, NULL, -1, NULL);

            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                sqlite3_finalize(stmt);
                return wm_vulnerability_detector_sql_error(db);
            }
            sqlite3_finalize(stmt);
        }

        vulnerability *vul_aux = vul_it;
        vul_it = vul_it->prev;
        free(vul_aux->cve_id);
        free(vul_aux->state_id);
        free(vul_aux->package_name);
        free(vul_aux);
    }

    while (test_it) {
        if (test_it->state) {
            if (sqlite3_prepare_v2(db, VU_UPDATE_CVE, -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db);
            }
            sqlite3_bind_text(stmt, 1, test_it->state, -1, NULL);
            sqlite3_bind_text(stmt, 2, test_it->id, -1, NULL);
            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                sqlite3_finalize(stmt);
                return wm_vulnerability_detector_sql_error(db);
            }
        } else {
            if (sqlite3_prepare_v2(db, VU_UPDATE_CVE, -1, &stmt, NULL) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                return wm_vulnerability_detector_sql_error(db);
            }
            sqlite3_bind_text(stmt, 1, "exists", -1, NULL);
            sqlite3_bind_text(stmt, 2, test_it->id, -1, NULL);
            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                sqlite3_finalize(stmt);
                return wm_vulnerability_detector_sql_error(db);
            }
        }
        sqlite3_finalize(stmt);
        info_test *test_aux = test_it;
        test_it = test_it->prev;
        free(test_aux->id);
        free(test_aux->state);
        free(test_aux);
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_VU_CO);

    while (state_it) {
        if (sqlite3_prepare_v2(db, VU_UPDATE_CVE2, -1, &stmt, NULL) != SQLITE_OK) {
            return wm_vulnerability_detector_sql_error(db);
        }
        sqlite3_bind_text(stmt, 1, state_it->operation, -1, NULL);
        sqlite3_bind_text(stmt, 2, state_it->operation_value, -1, NULL);
        sqlite3_bind_text(stmt, 3, state_it->id, -1, NULL);
        if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
            sqlite3_finalize(stmt);
            return wm_vulnerability_detector_sql_error(db);
        }
        sqlite3_finalize(stmt);
        info_state *state_aux = state_it;
        state_it = state_it->prev;
        free(state_aux->id);
        free(state_aux->operation);
        free(state_aux->operation_value);
        free(state_aux);
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_VU_INFO);

    while (info_it) {
        char date_diff;
        if (!info_it->updated) {
            info_it->updated = info_it->published;
            date_diff = 0;
        } else {
            date_diff = 1;
        }

        if (sqlite3_prepare_v2(db, VU_INSERT_CVE_INFO, -1, &stmt, NULL) != SQLITE_OK) {
            return wm_vulnerability_detector_sql_error(db);
        }

        sqlite3_bind_text(stmt, 1, info_it->cveid, -1, NULL);
        sqlite3_bind_text(stmt, 2, info_it->title, -1, NULL);
        sqlite3_bind_text(stmt, 3, info_it->severity, -1, NULL);
        sqlite3_bind_text(stmt, 4, info_it->published, -1, NULL);
        sqlite3_bind_text(stmt, 5, info_it->updated, -1, NULL);
        sqlite3_bind_text(stmt, 6, info_it->reference, -1, NULL);
        sqlite3_bind_text(stmt, 7, parsed_oval->OS, -1, NULL);
        sqlite3_bind_text(stmt, 8, info_it->description, -1, NULL);
        if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
            sqlite3_finalize(stmt);
            return wm_vulnerability_detector_sql_error(db);
        }
        sqlite3_finalize(stmt);
        info_cve *info_aux = info_it;
        info_it = info_it->prev;
        free(info_aux->cveid);
        free(info_aux->title);
        free(info_aux->severity);
        free(info_aux->published);
        if (date_diff) {
            free(info_aux->updated);
        }
        free(info_aux->reference);
        free(info_aux->description);
        free(info_aux);
    }

    if (sqlite3_prepare_v2(db, VU_INSERT_METADATA, -1, &stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db);
    }
    sqlite3_bind_text(stmt, 1, parsed_oval->OS, -1, NULL);
    sqlite3_bind_text(stmt, 2, met_it->product_name, -1, NULL);
    sqlite3_bind_text(stmt, 3, met_it->product_version, -1, NULL);
    sqlite3_bind_text(stmt, 4, met_it->schema_version, -1, NULL);
    sqlite3_bind_text(stmt, 5, met_it->timestamp, -1, NULL);
    if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        sqlite3_finalize(stmt);
        return wm_vulnerability_detector_sql_error(db);
    }
    sqlite3_finalize(stmt);

    free(met_it->product_name);
    free(met_it->product_version);
    free(met_it->schema_version);
    free(met_it->timestamp);

    sqlite3_exec(db, END_T, NULL, NULL, NULL);

    return 0;
}

int wm_vulnerability_detector_check_db() {
    if (wm_vulnerability_create_file(CVE_DB, schema_vuln_detector_sql)) {
        return OS_INVALID;
    }
    return 0;
}

char * wm_vulnerability_detector_preparser(cve_db dist) {
    FILE *input, *output;
    char *buffer = NULL;
    size_t size;
    size_t max_size = OS_MAXSTR;
    parser_state state = V_OVALDEFINITIONS;
    char *found;
    char *tmp_file;

    /*
    // No need to be prepared
    if ( X ) {
        os_strdup(CVE_TEMP_FILE, tmp_file);
        return tmp_file;
    }
    */

    os_strdup(CVE_FIT_TEMP_FILE, tmp_file);

    if (input = fopen(CVE_TEMP_FILE, "r" ), !input) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_OPEN_FILE_ERROR, CVE_TEMP_FILE);
        free(tmp_file);
        tmp_file = NULL;
        goto free_mem;
    } else if (output = fopen(tmp_file, "w" ), !output) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_OPEN_FILE_ERROR, tmp_file);
        free(tmp_file);
        tmp_file = NULL;
        goto free_mem;
    }

    while (size = getline(&buffer, &max_size, input), (int) size > 0) {
        if (dist == UBUNTU) { //5.11.1
            switch (state) {
                case V_OBJECTS:
                    if (found = strstr(buffer, "</objects>"), found) {
                        state = V_OVALDEFINITIONS;
                    }
                    goto free_buffer;
                break;
                case V_DEFINITIONS:
                    if ((found = strstr(buffer, "is not affected")) &&
                              (found = strstr(buffer, "negate")) &&
                        strstr(found, "true")) {
                        goto free_buffer;
                    } else if (strstr(buffer, "a decision has been made to ignore it")) {
                        goto free_buffer;
                    } else if (found = strstr(buffer, "</definitions>"), found) {
                        state = V_OVALDEFINITIONS;
                        //goto free_buffer;
                    }
                break;
                default:
                    if (strstr(buffer, "<objects>")) {
                        state = V_OBJECTS;
                        goto free_buffer;
                    } else if (strstr(buffer, "<definitions>")) {
                      state = V_DEFINITIONS;
                      //goto free_buffer;
                  }
            }
        } else if (dist == REDHAT) { //5.10
            switch (state) {
                case V_OVALDEFINITIONS:
                    if (found = strstr(buffer, "200 OK"), found) {
                        state = V_HEADER;
                        goto free_buffer;
                    }
                break;
                case V_HEADER:
                    if (found = strstr(buffer, "?>"), found) {
                        state = V_STATES;
                    }
                    goto free_buffer;
                break;
                case V_OBJECTS:
                    if (found = strstr(buffer, "</objects>"), found) {
                        state = V_STATES;
                    }
                    goto free_buffer;
                break;
                case V_DEFINITIONS:
                    if ((found = strstr(buffer, "Red Hat Enterprise Linux")) && strstr(++found, "is installed")) {
                        goto free_buffer;
                    } else if (strstr(buffer, "is signed with")) {
                        goto free_buffer;
                    } else if (strstr(buffer, "</definitions>")) {
                        state = V_STATES;
                    }
                break;
                case V_DESCRIPTION:
                    if (strstr(buffer, "</description>")) {
                        state = V_DEFINITIONS;
                    }
                    goto free_buffer;
                break;
                case V_TESTS:
                    if (strstr(buffer, "is signed with")) {
                        state = V_SIGNED_TEST;
                        goto free_buffer;
                    } else if (strstr(buffer, "</tests>")) {
                        state = V_STATES;
                    }
                break;
                case V_SIGNED_TEST:
                    if (strstr(buffer, "</red-def:rpminfo_test>")) {
                        state = V_TESTS;
                    }
                    goto free_buffer;
                break;
                default:
                    if (strstr(buffer, "<objects>")) {
                        state = V_OBJECTS;
                        goto free_buffer;
                    } else if (strstr(buffer, "<definitions>")) {
                      state = V_DEFINITIONS;
                    } else if (strstr(buffer, "<tests>")) {
                      state = V_TESTS;
                    }
            }
        } else {
            free(tmp_file);
            tmp_file = NULL;
            goto free_mem;
        }
        fwrite(buffer, 1, size, output);
free_buffer:
        free(buffer);
        buffer = NULL;
    }

free_mem:
    free(buffer);
    fclose(input);
    if (output) {
        fclose(output);
    }
    return tmp_file;
}

int wm_vulnerability_detector_parser(OS_XML *xml, XML_NODE node, wm_vulnerability_detector_db *parsed_oval, parser_state version, cve_db dist) {
    int i, j;
    char *found;
    static const char *XML_OVAL_DEFINITIONS = "oval_definitions";
    static const char *XML_GENERATOR = "generator";
    static const char *XML_DEFINITIONS = "definitions";
    static const char *XML_DEFINITION = "definition";
    static const char *XML_TITLE = "title";
    static const char *XML_CLASS = "class";
    static const char *XML_VULNERABILITY = "vulnerability"; //ub 15.11.1
    static const char *XML_PATH = "patch"; //rh 15.10
    static const char *XML_METADATA = "metadata";
    static const char *XML_CRITERIA = "criteria";
    static const char *XML_REFERENCE = "reference";
    static const char *XML_REF_URL = "ref_url";
    static const char *XML_OPERATOR = "operator";
    static const char *XML_OR = "OR";
    static const char *XML_AND = "AND";
    static const char *XML_COMMENT = "comment";
    static const char *XML_CRITERION = "criterion";
    static const char *XML_TEST_REF = "test_ref";
    static const char *XML_TESTS = "tests";
    static const char *XML_DPKG_INFO_TEST = "linux-def:dpkginfo_test";
    static const char *XML_RPM_INFO_TEST = "red-def:rpminfo_test";
    static const char *XML_ID = "id";
    static const char *XML_LINUX_STATE = "linux-def:state";
    static const char *XML_RPM_STATE = "red-def:state";
    static const char *XML_STATE_REF = "state_ref";
    static const char *XML_STATES = "states";
    static const char *XML_DPKG_INFO_STATE = "linux-def:dpkginfo_state";
    static const char *XML_RPM_INFO_STATE = "red-def:rpminfo_state";
    static const char *XML_LINUX_DEF_EVR = "linux-def:evr";
    static const char *XML_RPM_DEF_EVR = "red-def:evr";
    static const char *XML_RPM_DEF_VERSION = "red-def:version";
    static const char *XML_RPM_DEF_SIGN = "red-def:signature_keyid";
    static const char *XML_OPERATION = "operation";
    static const char *XML_OVAL_PRODUCT_NAME = "oval:product_name";
    static const char *XML_OVAL_PRODUCT_VERSION = "oval:product_version";
    static const char *XML_OVAL_SCHEMA_VERSION = "oval:schema_version";
    static const char *XML_OVAL_TIMESTAMP = "oval:timestamp";
    static const char *XML_ADVIDSORY = "advisory";
    static const char *XML_SEVERITY = "severity";
    static const char *XML_PUBLIC_DATE = "public_date";
    static const char *XML_ISSUED = "issued";
    static const char *XML_UPDATED = "updated";
    static const char *XML_DESCRIPTION = "description";
    static const char *XML_DATE = "date";

    for (i = 0; node[i]; i++) {
        XML_NODE chld_node = NULL;
        if (!node[i]->element) {
            mterror(WM_VULNDETECTOR_LOGTAG, XML_ELEMNULL);
            return OS_INVALID;
        }

        if ((dist == UBUNTU && !strcmp(node[i]->element, XML_DPKG_INFO_STATE)) ||
            (dist == REDHAT && !strcmp(node[i]->element, XML_RPM_INFO_STATE))) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_ID)) {
                    info_state *infos;
                    os_calloc(1, sizeof(info_state), infos);
                    os_strdup(node[i]->values[j], infos->id);
                    infos->operation = infos->operation_value = NULL;
                    infos->prev = parsed_oval->info_states;
                    parsed_oval->info_states = infos;
                    if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
                      return OS_INVALID;
                    }
                }
            }
        } else if ((dist == UBUNTU && !strcmp(node[i]->element, XML_DPKG_INFO_TEST)) ||
                   (dist == REDHAT && !strcmp(node[i]->element, XML_RPM_INFO_TEST))) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            info_test *infot;
            os_calloc(1, sizeof(info_test), infot);
            infot->state = NULL;
            infot->prev = parsed_oval->info_tests;
            parsed_oval->info_tests = infot;

            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_ID)) {
                    os_strdup(node[i]->values[j], parsed_oval->info_tests->id);
                }
            }
            if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
              return OS_INVALID;
          }
        } else if ((dist == UBUNTU && !strcmp(node[i]->element, XML_LINUX_DEF_EVR)) ||
                   (dist == REDHAT && (!strcmp(node[i]->element, XML_RPM_DEF_EVR)   ||
                   !strcmp(node[i]->element, XML_RPM_DEF_VERSION)                   ||
                   !strcmp(node[i]->element, XML_RPM_DEF_SIGN)))) {
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_OPERATION)) {
                    os_strdup(node[i]->values[j], parsed_oval->info_states->operation);
                    os_strdup(node[i]->content, parsed_oval->info_states->operation_value);
                }
            }
        } else if ((dist == UBUNTU && !strcmp(node[i]->element, XML_LINUX_STATE)) ||
                   (dist == REDHAT && !strcmp(node[i]->element, XML_RPM_STATE))) {
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_STATE_REF)) {
                    os_strdup(node[i]->values[j], parsed_oval->info_tests->state);
                }
            }
        } else if (!strcmp(node[i]->element, XML_DEFINITION)) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_CLASS)) {
                    if (!strcmp(node[i]->values[j], XML_VULNERABILITY) || !strcmp(node[i]->values[j], XML_PATH)) {
                        vulnerability *vuln;
                        info_cve *cves;
                        os_calloc(1, sizeof(vulnerability), vuln);
                        os_calloc(1, sizeof(info_cve), cves);

                        vuln->cve_id = NULL;
                        vuln->state_id = NULL;
                        vuln->pending = 0;
                        vuln->package_name = NULL;
                        vuln->prev = parsed_oval->vulnerabilities;
                        cves->cveid = NULL;
                        cves->title = NULL;
                        cves->severity = NULL;
                        cves->published = NULL;
                        cves->updated = NULL;
                        cves->reference = NULL;
                        cves->prev = parsed_oval->info_cves;

                        parsed_oval->vulnerabilities = vuln;
                        parsed_oval->info_cves = cves;
                        if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
                          return OS_INVALID;
                        }
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_METADATA)) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
              return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_REFERENCE)) {
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!parsed_oval->info_cves->reference && !strcmp(node[i]->attributes[j], XML_REF_URL)) {
                    os_strdup(node[i]->values[j], parsed_oval->info_cves->reference);
                }
            }
        } else if (!strcmp(node[i]->element, XML_TITLE)) {
                char *found;
                os_strdup(node[i]->content, parsed_oval->info_cves->title);
                if (found = strchr(node[i]->content, ' '), found) {
                    *found = '\0';
                    if (*(--found) == ':') {
                        *found = '\0';
                    }
                    os_strdup(node[i]->content, parsed_oval->vulnerabilities->cve_id);
                    os_strdup(node[i]->content, parsed_oval->info_cves->cveid);
                } else {
                    mterror(WM_VULNDETECTOR_LOGTAG, VU_CVE_ID_FETCH_ERROR, node[i]->content);
                    return OS_INVALID;
                }
        } else if (!strcmp(node[i]->element, XML_CRITERIA)) {
            if (!node[i]->attributes) {
                if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                    goto invalid_elem;
                }
                if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
                  return OS_INVALID;
                }
            } else {
                for (j = 0; node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_OPERATOR)) {
                        if (!strcmp(node[i]->values[j], XML_OR) || !strcmp(node[i]->values[j], XML_AND)) {
                            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                                continue;
                            }
                            if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
                              return OS_INVALID;
                            }
                        } else {
                            mterror(WM_VULNDETECTOR_LOGTAG, VU_INVALID_OPERATOR, node[i]->values[j]);
                            return OS_INVALID;
                        }
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_CRITERION)) {
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_TEST_REF)) {
                    if (parsed_oval->vulnerabilities->state_id) {
                        vulnerability *vuln;
                        os_calloc(1, sizeof(vulnerability), vuln);
                        os_strdup(parsed_oval->vulnerabilities->cve_id, vuln->cve_id);
                        vuln->prev = parsed_oval->vulnerabilities;
                        vuln->state_id = NULL;
                        vuln->package_name = NULL;
                        parsed_oval->vulnerabilities = vuln;

                        if (strstr(node[i]->values[j], "tst:10\0")) {
                            vuln->pending = 1;
                        } else {
                            vuln->pending = 0;
                        }
                        os_strdup(node[i]->values[j], vuln->state_id);
                    } else {
                        if (strstr(node[i]->values[j], "tst:10\0")) {
                            parsed_oval->vulnerabilities->pending = 1;
                        } else {
                            parsed_oval->vulnerabilities->pending = 0;
                        }
                        os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->state_id);
                    }
                } else if (!strcmp(node[i]->attributes[j], XML_COMMENT)) {
                    if (parsed_oval->vulnerabilities->package_name) {
                        vulnerability *vuln;
                        os_calloc(1, sizeof(vulnerability), vuln);
                        os_strdup(parsed_oval->vulnerabilities->cve_id, vuln->cve_id);
                        vuln->prev = parsed_oval->vulnerabilities;
                        vuln->state_id = NULL;
                        vuln->package_name = NULL;
                        parsed_oval->vulnerabilities = vuln;
                    }

                    if (dist == UBUNTU && (found = strstr(node[i]->values[j], "'"))) {
                        char *base = ++found;
                        if (found = strstr(found, "'"), found) {
                            *found = '\0';
                            os_strdup(base, parsed_oval->vulnerabilities->package_name);
                        }
                    } else if (dist == REDHAT && (found = strstr(node[i]->values[j], " "))) {
                        *found = '\0';
                        os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->package_name);
                    } else {
                        mterror(WM_VULNDETECTOR_LOGTAG, VU_PACKAGE_NAME_ERROR);
                        return OS_INVALID;
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_DESCRIPTION)) {
            os_strdup(node[i]->content, parsed_oval->info_cves->description);
        } else if (!strcmp(node[i]->element, XML_OVAL_PRODUCT_VERSION)) {
            os_strdup(node[i]->content, parsed_oval->metadata.product_version);
        } else if (!strcmp(node[i]->element, XML_OVAL_PRODUCT_NAME)) {
            os_strdup(node[i]->content, parsed_oval->metadata.product_name);
        } else if (!strcmp(node[i]->element, XML_OVAL_TIMESTAMP)) {
            os_strdup(node[i]->content, parsed_oval->metadata.timestamp);
            if (found = strstr(parsed_oval->metadata.timestamp, "T"), found) {
                *found = ' ';
            }
        } else if (!strcmp(node[i]->element, XML_OVAL_SCHEMA_VERSION)) {
            os_strdup(node[i]->content, parsed_oval->metadata.schema_version);
        } else if (!strcmp(node[i]->element, XML_SEVERITY)) {
            if (*node[i]->content != '\0') {
                if (!strcmp(node[i]->content, VU_MODERATE)) {
                    os_strdup(VU_MEDIUM, parsed_oval->info_cves->severity);
                } else if (!strcmp(node[i]->content, VU_IMPORTANT)) {
                    os_strdup(VU_HIGH, parsed_oval->info_cves->severity);
                } else {
                    os_strdup(node[i]->content, parsed_oval->info_cves->severity);
                }
            } else {
                os_strdup("Unknow", parsed_oval->info_cves->severity);
            }
        } else if (!strcmp(node[i]->element, XML_UPDATED)) {
            if (node[i]->attributes) {
                for (j = 0; node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_DATE)) {
                        os_strdup(node[i]->values[j], parsed_oval->info_cves->updated);
                    }
                }
            }
        } else if ((dist == UBUNTU && !strcmp(node[i]->element, XML_PUBLIC_DATE)) ||
                   (dist == REDHAT && !strcmp(node[i]->element, XML_ISSUED))) {
                       if (dist == REDHAT) {
                           if (node[i]->attributes) {
                               for (j = 0; node[i]->attributes[j]; j++) {
                                   if (!strcmp(node[i]->attributes[j], XML_DATE)) {
                                       os_strdup(node[i]->values[j], parsed_oval->info_cves->published);
                                   }
                               }
                           }
                       } else if (dist == UBUNTU) {
                           os_strdup(node[i]->content, parsed_oval->info_cves->published);
                       }
        } else if (!strcmp(node[i]->element, XML_OVAL_DEFINITIONS)  ||
                   !strcmp(node[i]->element, XML_DEFINITIONS)       ||
                   !strcmp(node[i]->element, XML_TESTS)             ||
                   !strcmp(node[i]->element, XML_STATES)            ||
                   !strcmp(node[i]->element, XML_ADVIDSORY)         ||
                   !strcmp(node[i]->element, XML_GENERATOR)) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, version, dist)) {
              return OS_INVALID;
            }
        }
    }

    return 0;

invalid_elem:
    mterror(WM_VULNDETECTOR_LOGTAG, XML_INVELEM, node[i]->element);
    return OS_INVALID;
}

int wm_vulnerability_update_oval(cve_db version) {
    OS_XML xml;
    XML_NODE node;
    char *tmp_file = NULL;
    wm_vulnerability_detector_db parsed_oval;
    char *OS_VERSION = NULL;
    cve_db dist;
    char success = 0;

    switch (version) {
        case PRECISE:
            os_strdup(VU_PRECISE, OS_VERSION);
            dist = UBUNTU;
        break;
        case TRUSTY:
            os_strdup(VU_TRUSTY, OS_VERSION);
            dist = UBUNTU;
        break;
        case XENIAL:
            os_strdup(VU_XENIAL, OS_VERSION);
            dist = UBUNTU;
        break;
        case RHEL5:
            os_strdup(VU_RHEL5, OS_VERSION);
            dist = REDHAT;
        break;
        case RHEL6:
            os_strdup(VU_RHEL6, OS_VERSION);
            dist = REDHAT;
        break;
        case RHEL7:
            os_strdup(VU_RHEL7, OS_VERSION);
            dist = REDHAT;
        break;
        default:
            mterror(WM_VULNDETECTOR_LOGTAG, VU_OS_VERSION_ERROR);
            goto free_mem;
        break;
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_PRE);
    if (tmp_file = wm_vulnerability_detector_preparser(dist), !tmp_file) {
        goto free_mem;
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_PAR);
    if (OS_ReadXML(tmp_file, &xml) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_LOAD_CVE_ERROR, OS_VERSION);
        goto free_mem;
    }

    if (node = OS_GetElementsbyNode(&xml, NULL), !node) {
        goto free_mem;
    };

    parsed_oval.vulnerabilities = NULL;
    parsed_oval.info_tests = NULL;
    parsed_oval.info_states = NULL;
    parsed_oval.info_cves = NULL;
    os_strdup(OS_VERSION, parsed_oval.OS);

    // Reduces a level of recurrence
    if (node = OS_GetElementsbyNode(&xml, *node), !node) {
        goto free_mem;
    }

    if (wm_vulnerability_detector_parser(&xml, node, &parsed_oval, V_OVALDEFINITIONS, dist)) {
        goto free_mem;
    }

    if (wm_vulnerability_detector_check_db()) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CHECK_DB_ERROR);
        goto free_mem;
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_START_REFRESH_DB, OS_VERSION);

    if (wm_vulnerability_detector_insert(&parsed_oval)) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_REFRESH_DB_ERROR, OS_VERSION);
        goto free_mem;
    }
    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_STOP_REFRESH_DB, OS_VERSION);

success = 1;
free_mem:
    if (OS_VERSION) {
        free(OS_VERSION);
    }
    if (tmp_file) {
        free(tmp_file);
    }
    if (success) {
        return 0;
    } else {
        return OS_INVALID;
    }
}

int wm_vulnerability_detector_socketconnect(char *url) {
	struct sockaddr_in addr, *addr_it;
	int on = 1, sock;
    char host[OS_SIZE_256];
    in_port_t port;
    struct addrinfo hints, *host_info, *hinfo_it;
    char ip_addr[30];

    if (url = strstr(url, "https://"), !url) {
        return OS_INVALID;
    }

    snprintf(host, OS_SIZE_256, "%s", url + 8);

    if(url = strchr(host, ':'), url) {
        port = strtol(++url, NULL, 10);
        *(--url) = '\0';
    } else {
        port = DEFAULT_OVAL_PORT;
    }

	*ip_addr = '\0';
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, "http" , &hints , &host_info)) {
        return OS_INVALID;
	}

	for(hinfo_it = host_info; hinfo_it != NULL; hinfo_it = hinfo_it->ai_next) {
		addr_it = (struct sockaddr_in *) hinfo_it->ai_addr;
		if (addr_it->sin_addr.s_addr) {
			strcpy(ip_addr , inet_ntoa(addr_it->sin_addr) );
		}
	}

	freeaddrinfo(host_info);

    if (*ip_addr == '\0') {
        return OS_INVALID;
	}

	inet_pton(AF_INET, ip_addr, &addr.sin_addr);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if(sock < 0 || connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Cannot connect to %s:%i.", host, (int)port);
        return OS_INVALID;
	}

    int one = 1;
    if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        return OS_INVALID;
    }
	return sock;
}

int wm_vulnerability_fetch_oval(cve_db version, int *need_update) {
    int sock = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int size;
    unsigned int readed;
    unsigned int oval_size;
    char buffer[VU_SSL_BUFFER];
    char *repo;
    FILE *fp;
    char *OS = NULL;
    char timestamp_found = 0;
    int attemps = 0;
    *need_update = 1;
    unsigned char success = 1;

    switch (version) {
        case PRECISE:
            os_strdup(VU_PRECISE, OS);
            snprintf(buffer, VU_SSL_BUFFER, UBUNTU_OVAL, "precise");
            os_strdup(CANONICAL_REPO, repo);
        break;
        case TRUSTY:
            os_strdup(VU_TRUSTY, OS);
            snprintf(buffer, VU_SSL_BUFFER, UBUNTU_OVAL, "trusty");
            os_strdup(CANONICAL_REPO, repo);
        break;
        case XENIAL:
            os_strdup(VU_XENIAL, OS);
            snprintf(buffer, VU_SSL_BUFFER, UBUNTU_OVAL, "xenial");
            os_strdup(CANONICAL_REPO, repo);
        break;
        case RHEL5:
            os_strdup(VU_RHEL5, OS);
            snprintf(buffer, VU_SSL_BUFFER, REDHAT_OVAL, 5);
            os_strdup(REDHAT_REPO, repo);
        break;
        case RHEL6:
            os_strdup(VU_RHEL6, OS);
            snprintf(buffer, VU_SSL_BUFFER, REDHAT_OVAL, 6);
            os_strdup(REDHAT_REPO, repo);
        break;
        case RHEL7:
            os_strdup(VU_RHEL7, OS);
            snprintf(buffer, VU_SSL_BUFFER, REDHAT_OVAL, 7);
            os_strdup(REDHAT_REPO, repo);
        break;
        default:
            mterror(WM_VULNDETECTOR_LOGTAG, VU_OS_VERSION_ERROR);
            success = 0;
            os_strdup("unknow OS", OS);
            goto free_mem;
    }

    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_DOWNLOAD, OS);

    if (sock = wm_vulnerability_detector_socketconnect(repo), sock < 0) {
        sock = 0;
        success = 0;
        goto free_mem;
    }

    if (ctx = SSL_CTX_new(SSLv23_client_method()), !ctx) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SSL_CONTEXT_ERROR);
        success = 0;
        goto free_mem;
    }

    SSL_CTX_set_options(ctx, SSL_MODE_AUTO_RETRY);

    if (ssl = SSL_new(ctx), !ssl) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SSL_CREATE_ERROR);
        success = 0;
        goto free_mem;
    }

    if (!SSL_set_fd(ssl, sock)) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SSL_LINK_ERROR);
        success = 0;
        goto free_mem;
    }

    if (SSL_connect(ssl) < 1) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SSL_CONNECT_ERROR, OS);
        success = 0;
        goto free_mem;
    }

    SSL_write(ssl, buffer, strlen(buffer));
    readed = 0;
    if (fp = fopen(CVE_TEMP_FILE, "w"), !fp) {
        success = 0;
        goto free_mem;
    }
    bzero(buffer, VU_SSL_BUFFER);

    if (size = SSL_read(ssl, buffer, WM_HEADER_SIZE), size < 1) {
        success = 0;
        goto free_mem;
    }

    oval_size = wm_read_http_header(buffer);

    while (!readed || (oval_size != readed && (size = SSL_read(ssl, buffer, ((oval_size - readed) > VU_SSL_BUFFER)? VU_SSL_BUFFER : (oval_size - readed)))) > 0) {
        buffer[size] = '\0';
        if (!readed) {
            char *found;
            if(!(found = strstr(buffer, "<?xml version=")) && !(found = strstr(buffer, "<oval_definitions"))) {
                success = 0;
                goto free_mem;
            }
            readed = strlen(found);
            fwrite(buffer, 1, size, fp);
            bzero(buffer, VU_SSL_BUFFER);
            continue;
        }

        readed += size;

        if (!timestamp_found) {
            char *timst;
            if (timst = strstr(buffer, "timestamp>"), timst) {
                int update = 1;
                char stored_timestamp[KEY_SIZE];
                int i;
                sqlite3_stmt *stmt = NULL;
                sqlite3 *db;
                timestamp_found = 1;

                if (sqlite3_open_v2(CVE_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
                    update = 0;
                } else {
                    if (sqlite3_prepare_v2(db, TIMESTAMP_QUERY, -1, &stmt, NULL) != SQLITE_OK) {
                        success = 0;
                        sqlite3_finalize(stmt);
                        goto free_mem;
                    }
                    sqlite3_bind_text(stmt, 1, OS, -1, NULL);

                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        char *close_tag;
                        timst = strstr(timst, ">");
                        timst++;
                        if (close_tag = strstr(timst, "<"), close_tag) {
                            *close_tag = '\0';
                            snprintf(stored_timestamp, KEY_SIZE, "%s", sqlite3_column_text(stmt, 0));

                            for (i = 0; stored_timestamp[i] != '\0'; i++) {
                                 if (stored_timestamp[i] == '-' ||
                                     stored_timestamp[i] == ' ' ||
                                     stored_timestamp[i] == ':' ||
                                     stored_timestamp[i] == 'T') {
                                    continue;
                                 }
                                 if (stored_timestamp[i] < timst[i]) {
                                     update = 0;
                                     break;
                                 }
                            }

                            *close_tag = '<';
                        } else {
                            update = 0;
                            mterror(WM_VULNDETECTOR_LOGTAG, VU_DB_TIMESTAMP_OVAL_ERROR, OS);
                        }
                    } else {
                        update = 0;
                        mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_DB_TIMESTAMP_OVAL, OS);
                    }
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                }

                if (update) {
                    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_DATE, OS, stored_timestamp);
                    *need_update = 0;
                    goto free_mem;
                }
            }

            attemps++;
            if (attemps == VU_MAX_TIMESTAMP_ATTEMPS) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_TIMESTAMP_LABEL_ERROR, VU_MAX_TIMESTAMP_ATTEMPS);
                close(sock);
                success = 0;
                goto free_mem;
            }
        }
        fwrite(buffer, 1, size, fp);
        bzero(buffer, VU_SSL_BUFFER);
    }

free_mem:
    CRYPTO_cleanup_all_ex_data();
    if (fp) {
        fclose(fp);
    }
    if (sock) {
        close(sock);
    }
    if (ssl) {
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (success) {
        close(sock);
        if (OS) {
            free(OS);
            OS = NULL;
        }
        return 0;
    } else {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_FETCH_ERROR, OS);
        if (OS) {
            free(OS);
            OS = NULL;
        }
        return OS_INVALID;
    }
}

int wm_vulnerability_detector_updatedb(update_flags *flags, time_intervals *max, time_intervals *remaining) {
    int need_update = 1;
    time_t time_start;

    if (flags->update_ubuntu && !remaining->ubuntu) {
        time_start = time(NULL);
        if (flags->xenial) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, "Ubuntu Xenial");
            if (wm_vulnerability_fetch_oval(XENIAL, &need_update) || (need_update && wm_vulnerability_update_oval(XENIAL))) {
                return OS_INVALID;
            } else {
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, "Ubuntu Xenial");
            }
        }
        if (flags->trusty) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, "Ubuntu Trusty");
            if (wm_vulnerability_fetch_oval(TRUSTY, &need_update) || (need_update && wm_vulnerability_update_oval(TRUSTY))) {
                return OS_INVALID;
            } else {
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, "Ubuntu Trusty");
            }
        }
        if (flags->precise) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, "Ubuntu Precise");
            if (wm_vulnerability_fetch_oval(PRECISE, &need_update) || (need_update && wm_vulnerability_update_oval(PRECISE))) {
                return OS_INVALID;
            } else {
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, "Ubuntu Precise");
            }
        }
        wm_vulnerability_update_intervals(remaining, time(NULL) - time_start);
        remaining->ubuntu = max->ubuntu;
    }
    if (flags->update_redhat && !remaining->redhat) {
        time_start = time(NULL);
        if (flags->rh5) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, "Red Hat Enterprise Linux 5");
            if (wm_vulnerability_fetch_oval(RHEL5, &need_update) || (need_update && wm_vulnerability_update_oval(RHEL5))) {
                return OS_INVALID;
            } else {
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, "Red Hat Enterprise Linux 5");
            }
        }
        if (flags->rh6) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, "Red Hat Enterprise Linux 6");
            if (wm_vulnerability_fetch_oval(RHEL6, &need_update) || (need_update && wm_vulnerability_update_oval(RHEL6))) {
                return OS_INVALID;
            } else {
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, "Red Hat Enterprise Linux 6");
            }
        }
        if (flags->rh7) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, "Red Hat Enterprise Linux 7");
            if (wm_vulnerability_fetch_oval(RHEL7, &need_update) || (need_update && wm_vulnerability_update_oval(RHEL7))) {
                return OS_INVALID;
            } else {
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, "Red Hat Enterprise Linux 7");
            }
        }
        wm_vulnerability_update_intervals(remaining, time(NULL) - time_start);
        remaining->redhat = max->redhat;
    }
    return 0;
};

int wm_vulnerability_detector_get_software_info(agent_software * agent, sqlite3 *db) {
    int sock;
    unsigned int i;
    int size;
    char buffer[OS_MAXSTR];
    char json_str[OS_MAXSTR];
    sqlite3_stmt *stmt;
    cJSON *obj = NULL;
    cJSON *package_list = NULL;

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_AGENT_SOFTWARE_REQ, agent->agent_id);

    for (i = 0; i < VU_MAX_WAZUH_DB_ATTEMPS && (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK_PATH, SOCK_STREAM, OS_MAXSTR)) < 1; i++) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Unable to connect to socket '%s'. Waiting %d seconds.", WDB_LOCAL_SOCK_PATH, i);
        sleep(i);
    }

    if (i == VU_MAX_WAZUH_DB_ATTEMPS) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Unable to connect to socket '%s'.", WDB_LOCAL_SOCK_PATH);
        return OS_INVALID;
    }

    i = 0;
    size = snprintf(buffer, OS_MAXSTR, VU_SOFTWARE_REQUEST, agent->agent_id, VU_MAX_PACK_REQ, i);
    if (send(sock, buffer, size + 1, 0) < size) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SOFTWARE_REQUEST_ERROR, agent->agent_id);
        return OS_INVALID;
    }

    while (size = recv(sock, buffer, OS_MAXSTR, 0), size) {
        if (size < 10) {
            break;
        }
        buffer[size] = '\0';
        if (size != -1) {
            if (!strncmp(buffer, "ok", 2)) {
                buffer[0] = buffer[1] = ' ';
                size = snprintf(json_str, OS_MAXSTR, "{\"data\":%s}", buffer);
                json_str[size] = '\0';
            } else {
                goto error;
            }
            if (obj) {
                cJSON *new_obj;
                cJSON *data;
                if (new_obj = cJSON_Parse(json_str), !new_obj || !cJSON_IsObject(new_obj)) {
                    goto error;
                }
                data = cJSON_GetObjectItem(new_obj, "data");
                if (data) {
                    cJSON_AddItemToArray(package_list, data->child);
                }
                free(new_obj);
                free(data->string);
                free(data);
            } else if (obj = cJSON_Parse(json_str), obj && cJSON_IsObject(obj)) {
                package_list = cJSON_GetObjectItem(obj, "data");
                if (!package_list) {
                    goto error;
                }
            } else {
                goto error;
            }


            i += VU_MAX_PACK_REQ;
            size = snprintf(buffer, OS_MAXSTR, VU_SOFTWARE_REQUEST, agent->agent_id, VU_MAX_PACK_REQ, i);
            if (send(sock, buffer, size + 1, 0) < size) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_SOFTWARE_REQUEST_ERROR, agent->agent_id);
                goto error;
            }
        } else {
            goto error;
        }
    }


    if (package_list) {
        sqlite3_exec(db, BEGIN_T, NULL, NULL, NULL);
        for (package_list = package_list->child; package_list; package_list = package_list->next) {
            if (sqlite3_prepare_v2(db, VU_INSERT_AGENTS, -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db);
            }

            sqlite3_bind_text(stmt, 1, agent->agent_id, -1, NULL);
            sqlite3_bind_text(stmt, 2, cJSON_GetObjectItem(package_list, "name")->valuestring, -1, NULL);
            sqlite3_bind_text(stmt, 3, cJSON_GetObjectItem(package_list, "version")->valuestring, -1, NULL);
            sqlite3_bind_text(stmt, 4, cJSON_GetObjectItem(package_list, "architecture")->valuestring, -1, NULL);

            if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
                sqlite3_finalize(stmt);
                return wm_vulnerability_detector_sql_error(db);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_exec(db, END_T, NULL, NULL, NULL);
        agent->info = 1;
    } else {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SOFTWARE_REQUEST_ERROR, agent->agent_id);
    }

    if (obj) {
        cJSON_Delete(obj);
    }
    close(sock);
    return 0;
error:
    if (obj) {
        cJSON_Delete(obj);
    }
    close(sock);
    return OS_INVALID;
}

void wm_vulnerability_update_intervals(time_intervals *remaining, time_t time_sleep) {
    if ((time_t)remaining->detect > time_sleep) {
        remaining->detect -= time_sleep;
    } else {
        remaining->detect = 0;
    }

    if ((time_t)remaining->redhat > time_sleep) {
        remaining->redhat -= time_sleep;
    } else {
        remaining->redhat = 0;
    }

    if ((time_t)remaining->ubuntu > time_sleep) {
        remaining->ubuntu -= time_sleep;
    } else {
        remaining->ubuntu = 0;
    }
}

void * wm_vulnerability_detector_main(wm_vulnerability_detector_t * vulnerability_detector) {
    time_t time_start;
    time_t time_sleep = 0;
    time_intervals *remaining = &vulnerability_detector->remaining_intervals;
    time_intervals *intervals = &vulnerability_detector->intervals;
    wm_vulnerability_detector_flags *flags = &vulnerability_detector->flags;
    int i;

    if (!flags->enabled) {
        mtdebug1(WM_VULNDETECTOR_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    for (i = 0; vulnerability_detector->queue_fd = StartMQ(DEFAULTQPATH, WRITE), vulnerability_detector->queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++) {
        sleep(WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    vu_queue = &vulnerability_detector->queue_fd;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    for (i = 0; SSL_library_init() < 0 && i < WM_MAX_ATTEMPTS; i++) {
        sleep(WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SSL_LIBRARY_ERROR);
        pthread_exit(NULL);
    }

    if (flags->run_on_start) {
        remaining->detect = 0;
        remaining->ubuntu = 0;
        remaining->redhat = 0;
    } else {
        remaining->detect = intervals->detect;
        remaining->ubuntu = intervals->ubuntu;
        remaining->redhat = intervals->redhat;
    }

    while (1) {
        // Update CVE databases
        if (flags->u_flags.update &&
            wm_vulnerability_detector_updatedb(&flags->u_flags, intervals, remaining)) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_OVAL_UPDATE_ERROR);
        }

        if (!remaining->detect) {
            time_start = time(NULL);
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_START_SCAN);

            if (wm_vunlnerability_detector_set_agents_info(&vulnerability_detector->agents_software)) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_NO_AGENT_ERROR);
            } else {
                if (wm_vulnerability_detector_check_agent_vulnerabilities(vulnerability_detector->agents_software)) {
                    mterror(WM_VULNDETECTOR_LOGTAG, VU_AG_CHECK_ERR);
                } else {
                    mtinfo(WM_VULNDETECTOR_LOGTAG, VU_END_SCAN);
                }
                agent_software *agent;
                for (agent = vulnerability_detector->agents_software; agent;) {
                    agent_software *agent_aux = agent->next;
                    free(agent->agent_id);
                    free(agent->agent_name);
                    free(agent->agent_ip);
                    free(agent->OS);
                    free(agent);

                    if (agent_aux) {
                        agent = agent->next;
                    } else {
                        break;
                    }
                }
            }

            wm_vulnerability_update_intervals(&vulnerability_detector->remaining_intervals, time(NULL) - time_start);
            remaining->detect = intervals->detect;
        }

        time_start = time(NULL);
        if (wm_state_io(WM_VULNDETECTOR_CONTEXT.name, WM_IO_WRITE, &vulnerability_detector->state, sizeof(vulnerability_detector->state)) < 0)
            mterror(WM_VULNDETECTOR_LOGTAG, "Couldn't save running state.");
        wm_vulnerability_update_intervals(&vulnerability_detector->remaining_intervals, time(NULL) - time_start);

        time_start = time(NULL);
        time_sleep = remaining->detect;
        if (flags->u_flags.update_ubuntu && time_sleep > (time_t)remaining->ubuntu) {
            time_sleep = remaining->ubuntu;
        }
        if (flags->u_flags.update_redhat && time_sleep > (time_t)remaining->redhat) {
            time_sleep = remaining->redhat;
        }

        sleep(time_sleep);
        wm_vulnerability_update_intervals(&vulnerability_detector->remaining_intervals, time(NULL) - time_start);
    }

}

int wm_vunlnerability_detector_set_agents_info(agent_software **agents_software) {
    agent_software *agents;
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry *entry;
    unsigned int i;
    size_t size;
    char agent_info[OS_MAXSTR];
    char m_uname[OS_MAXSTR] = "";
    FILE *fp;
    char manager_found = 0;
    char *buffer;
    char *uname;
    char *uname_p = NULL;

    os_strdup(getuname(), uname);

    OS_PassEmptyKeyfile();
    OS_ReadKeys(&keys, 0, 0, 0);
    if (keys.keysize) {
        agents = NULL;
        for (i = 0; i < keys.keysize; i++) {
            entry = keys.keyentries[i];
            if (agents) {
                os_calloc(1, sizeof(agent_software), agents->next);
                agents->next->prev = agents;
                agents = agents->next;
            } else {
                os_calloc(1, sizeof(agent_software), *agents_software);
                agents = *agents_software;
                agents->prev = NULL;
            }

            os_strdup(entry->id, agents->agent_id);
            os_strdup(entry->name, agents->agent_name);
            os_strdup(entry->ip->ip, agents->agent_ip);
            agents->OS = NULL;
            agents->info = 0;
            agents->next = NULL;
        }
    }

    os_calloc(1, sizeof(agent_software), agents);
    if (*agents_software) {
        (*agents_software)->prev = agents;
        agents->next = *agents_software;
    }
    *agents_software = agents;
    agents->prev = NULL;
    size = snprintf(agent_info, OS_MAXSTR, "%s", uname);
    if (buffer = strchr(agent_info, '|'), buffer) {
        uname_p = strchr(++buffer, '|');
        *uname_p = '\0';
    } else {
        free(uname);
        OS_FreeKeys(&keys);
        return OS_INVALID;
    }
    for (i = 0; buffer[i] != '\0'; i++) {
        if (buffer[i] == ' ') {
            buffer[i] = '\0';
            break;
        }
    }
    os_strdup("000", agents->agent_id);
    os_strdup("", agents->agent_ip);
    os_strdup(buffer, agents->agent_name);

    ++uname_p;

    // Extracts the operating system of the agents
    for (agents = *agents_software; agents;) {
        if (strcmp(agents->agent_id, "000")) {
            manager_found = 0;
            size = snprintf(agent_info, OS_MAXSTR, AGENT_INFO_FILEF, agents->agent_name, agents->agent_ip);
            agent_info[size] = '\0';
        } else {
            manager_found = 1;
            fp = NULL;
        }
        // The agent has never been connected
        if (!manager_found && !(fp = fopen(agent_info, "r" ))) {
            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AGENT_INFO_ERROR, agents->agent_name);
            if (agents = skip_agent(agents, agents_software), !agents) {
                break;
            } else {
                continue;
            }
        } else {
            if (manager_found) {
                strncpy(m_uname, uname_p, OS_MAXSTR -1);
                m_uname[OS_MAXSTR - 1] = '\0';
            }
            buffer = agent_info;
            size_t max = OS_MAXSTR;

            // Agent connected or disconnected
            if ((manager_found && ((size = snprintf(agent_info, OS_MAXSTR, "%s", m_uname)) > 0)) ||
                ((size = getline(&buffer, &max, fp)) > 0)) {
                buffer[size] = '\0';
                if (buffer = strchr(buffer, '['), buffer) {
                    buffer++;
                    *strchr(agent_info, ']') = '\0';
                    if (strcasestr(buffer, VU_UBUNTU)) {
                        if (strstr(buffer, " 16")) {
                            os_strdup(VU_XENIAL, agents->OS);
                        } else if (strstr(buffer, " 14")) {
                            os_strdup(VU_TRUSTY, agents->OS);
                        } else if (strstr(buffer, " 12")) {
                            os_strdup(VU_PRECISE, agents->OS);
                        } else {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, VU_UBUNTU, agents->agent_name);
                            if (agents = skip_agent(agents, agents_software), !agents) {
                                break;
                            } else {
                                continue;
                            }
                        }
                    } else if (strcasestr(buffer, VU_RHEL)) {
                        if (strstr(buffer, " 7")) {
                            os_strdup(VU_RHEL7, agents->OS);
                        } else if (strstr(buffer, " 6")) {
                            os_strdup(VU_RHEL6, agents->OS);
                        } else if (strstr(VU_RHEL5, " 5")) {
                            os_strdup(VU_RHEL5, agents->OS);
                        } else {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, VU_RHEL, agents->agent_name);
                            if (agents = skip_agent(agents, agents_software), !agents) {
                                break;
                            } else {
                                continue;
                            }
                        }
                    } else if (strcasestr(buffer, VU_CENTOS)) {
                        if (strstr(buffer, " 7")) {
                            os_strdup(VU_RHEL7, agents->OS);
                        } else if (strstr(buffer, " 6")) {
                            os_strdup(VU_RHEL6, agents->OS);
                        } else if (strstr(buffer, " 5")) {
                            os_strdup(VU_RHEL5, agents->OS);
                        } else {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, VU_CENTOS, agents->agent_name);
                            if (agents = skip_agent(agents, agents_software), !agents) {
                                break;
                            } else {
                                continue;
                            }
                        }
                    } else {
                        mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS, agents->agent_name);
                        if (agents = skip_agent(agents, agents_software), !agents) {
                            break;
                        }
                    }
                } else { // Operating system not supported in any of its versions
                    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AGENT_UNSOPPORTED, agents->agent_name);
                    if (agents = skip_agent(agents, agents_software), !agents) {
                        break;
                    } else {
                        continue;
                    }
                }
            } else { // Agent in pending state
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AGENT_PENDING, agents->agent_name);
                if (agents = skip_agent(agents, agents_software), !agents) {
                    break;
                } else {
                    continue;
                }
            }
            agents = agents->next;
        }
        if (fp) {
            fclose(fp);
        }
        fp = NULL;
    }

    if (fp) {
        fclose(fp);
    }

    free(uname);
    OS_FreeKeys(&keys);
    return 0;
}

void wm_vulnerability_detector_destroy(wm_vulnerability_detector_t * vulnerability_detector) {
    agent_software *agent;
    for (agent = vulnerability_detector->agents_software; agent;) {
        agent_software *agent_aux = agent->next;
        free(agent->agent_id);
        free(agent->agent_name);
        free(agent->agent_ip);
        free(agent->OS);
        free(agent);

        if (agent_aux) {
            agent = agent->next;
        } else {
            break;
        }
    }
    free(vulnerability_detector);
}

#endif
