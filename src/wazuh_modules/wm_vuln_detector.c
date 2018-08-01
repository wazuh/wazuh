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

#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define SOL_TCP     6
#endif

static void * wm_vulnerability_detector_main(wm_vulnerability_detector_t * vulnerability_detector);
static void wm_vulnerability_detector_destroy(wm_vulnerability_detector_t * vulnerability_detector);
static int wm_vulnerability_detector_socketconnect(char *host, in_port_t port);
static int wm_vulnerability_detector_updatedb(update_node **updates);
static char * wm_vulnerability_detector_preparser(char *path, distribution dist);
static int wm_vulnerability_update_oval(update_node *update);
static int wm_vulnerability_fetch_oval(update_node *update, const char *OS, int *need_update);
static int wm_vulnerability_detector_parser(OS_XML *xml, XML_NODE node, wm_vulnerability_detector_db *parsed_oval, update_node *update, vu_logic condition);
static int wm_vulnerability_detector_check_db();
static int wm_vulnerability_detector_insert(wm_vulnerability_detector_db *parsed_oval);
static int wm_vulnerability_detector_remove_OS_table(sqlite3 *db, char *TABLE, char *OS);
static int wm_vulnerability_detector_sql_error(sqlite3 *db, sqlite3_stmt *stmt);
static int wm_vulnerability_detector_get_software_info(agent_software *agent, sqlite3 *db, OSHash *agents_triag, unsigned long ignore_time);
static int wm_vulnerability_detector_report_agent_vulnerabilities(agent_software *agents, sqlite3 *db, int max);
static int wm_vulnerability_detector_check_agent_vulnerabilities(agent_software *agents, OSHash *agents_triag, unsigned long ignore_time);
static int wm_checks_package_vulnerability(char *version, const char *operation, char *operation_value);
static int wm_vulnerability_detector_step(sqlite3_stmt *stmt);
static int wm_vulnerability_create_file(const char *path, const char *source);
static int wm_vulnerability_check_update_period(update_node *upd);
static int wm_vulnerability_check_update(update_node *upd, const char *dist);
static int wm_vulnerability_ssl_request_size(char octet_stream, long int *octet_rem, SSL *ssl, long int oval_size, long int readed);
static int wm_vulnerability_run_update(update_node *upd, const char *dist, const char *tag);
static int wm_vulnerability_detector_compare(char *version_it, char *cversion_it);
static const char *wm_vulnerability_set_oval(const char *os_name, const char *os_version, update_node **updates, distribution *wm_vulnerability_set_oval);
static int wm_vunlnerability_detector_set_agents_info(agent_software **agents_software, update_node **updates);

int *vu_queue;
const wm_context WM_VULNDETECTOR_CONTEXT = {
    "vulnerability-detector",
    (wm_routine)wm_vulnerability_detector_main,
    (wm_routine)wm_vulnerability_detector_destroy
};

const char *vu_dist_tag[] = {
    "UBUNTU",
    "DEBIAN",
    "REDHAT",
    "CENTOS",
    "WINDOWS",
    "MACOS",
    "PRECISE",
    "TRUSTY",
    "XENIAL",
    "BIONIC",
    "JESSIE",
    "STRETCH",
    "WHEEZY",
    "RHEL5",
    "RHEL6",
    "RHEL7",
    "WXP",
    "W7",
    "W8",
    "W81",
    "W10",
    "WS2008",
    "WS2008R2",
    "WS2012",
    "WS2012R2",
    "WS2016",
    "MACOSX",
    "UNKNOWN"
};

const char *vu_dist_ext[] = {
    "Ubuntu",
    "Debian",
    "Red Hat",
    "CentOS",
    "Microsoft Windows",
    "Apple Mac OS",
    "Ubuntu Precise",
    "Ubuntu Trusty",
    "Ubuntu Xenial",
    "Ubuntu Bionic",
    "Debian Jessie",
    "Debian Stretch",
    "Debian Wheezy",
    "Red Hat Enterprise Linux 5",
    "Red Hat Enterprise Linux 6",
    "Red Hat Enterprise Linux 7",
    "Windows XP",
    "Windows 7",
    "Windows 8",
    "Windows 8.1",
    "Windows 10",
    "Windows Server 2008",
    "Windows Server 2008 R2",
    "Windows Server 2012",
    "Windows Server 2012 R2",
    "Windows Server 2016",
    "Mac OS X",
    "Unknown OS"
};

const char *wm_vulnerability_set_oval(const char *os_name, const char *os_version, update_node **updates, distribution *agent_dist) {
    const char *retval = NULL;
    int i;

    for (i = 0; i < OS_SUPP_SIZE; i++) {
        if (updates[i] && updates[i]->allowed_OS_list) {
            int j;
            char *allowed_os;
            char *allowed_ver;
            for (allowed_os = *updates[i]->allowed_OS_list, allowed_ver = *updates[i]->allowed_ver_list, j = 0; allowed_os; ++j) {
                if (strcasestr(os_name, allowed_os) && strcasestr(os_version, allowed_ver)) {
                    retval = updates[i]->dist_tag;
                    *agent_dist = updates[i]->dist_ref;
                    i = OS_SUPP_SIZE;
                    break;
                }
                allowed_os = updates[i]->allowed_OS_list[j];
                allowed_ver = updates[i]->allowed_ver_list[j];
            }
        }
    }

    return retval;
}

int wm_vulnerability_ssl_request_size(char octet_stream, long int *octet_rem, SSL *ssl, long int oval_size, long int readed) {
    char buffer[VU_SSL_BUFFER];

    if (octet_stream) {
        long int request;
        int size;
        if (!*octet_rem) {
            if (size = SSL_read(ssl, buffer, VU_SSL_BUFFER), size < 0) {
                return OS_INVALID;
            } else {
                buffer[size] = '\0';
                if (size == 2 && !strcmp(buffer, "\r\n")) {
                    if (size = SSL_read(ssl, buffer, VU_SSL_BUFFER), size < 0) {
                        return OS_INVALID;
                    }
                    buffer[size] = '\0';
                }
                request = strtol(buffer, NULL, 16);
                *octet_rem = request;
            }
        } else {
            // Not all the bytes of the last stream have been readed
            request = *octet_rem;
        }
        return (int) (request > VU_SSL_BUFFER)? VU_SSL_BUFFER : request;
    } else {
        return ((oval_size - readed) > VU_SSL_BUFFER)? VU_SSL_BUFFER : (oval_size - readed);
    }
}

int wm_vulnerability_check_update_period(update_node *upd) {
    return upd && (upd->last_update + (time_t) upd->interval) < time(NULL);
}
int wm_vulnerability_check_update(update_node *upd, const char *dist) {
    int need_update = 1;
    return wm_vulnerability_fetch_oval(upd, dist, &need_update) || (need_update && wm_vulnerability_update_oval(upd));
}

int wm_vulnerability_create_file(const char *path, const char *source) {
    const char *ROOT = "root";
    const char *sql;
    const char *tail;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int result;
    uid_t uid;
    gid_t gid;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_DB_ERROR);
        return wm_vulnerability_detector_sql_error(db, stmt);
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_DB_ERROR);
            return wm_vulnerability_detector_sql_error(db, stmt);
        }

        result = sqlite3_step(stmt);

        switch (result) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_DB_ERROR);
            return wm_vulnerability_detector_sql_error(db, stmt);
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

int wm_checks_package_vulnerability(char *version, const char *operation, char *operation_value) {
    int size;
    int v_result, r_result;
    int epoch, c_epoch;
    char version_cl[KEY_SIZE];
    char cversion_cl[KEY_SIZE];
    char *version_it, *release_it;
    char *cversion_it, *crelease_it;

    if (operation_value) {
        // Copy the original values
        if (size = snprintf(version_cl, KEY_SIZE, "%s", version), size >= KEY_SIZE) {
            return OS_INVALID;
        }
        if (size = snprintf(cversion_cl, KEY_SIZE, "%s", operation_value), size >= KEY_SIZE) {
            return OS_INVALID;
        }

        // Check EPOCH
        if (version_it = strchr(version_cl, ':'), version_it) {
            *(version_it++) = '\0';
            epoch = strtol(version_cl, NULL, 10);
        } else {
            version_it = version_cl;
            epoch = 0;
        }
        if (cversion_it = strchr(cversion_cl, ':'), cversion_it) {
            *(cversion_it++) = '\0';
            c_epoch = strtol(cversion_cl, NULL, 10);
        } else {
            cversion_it = cversion_cl;
            c_epoch = 0;
        }

        // Separate the version from the revision
        if (release_it = strchr(version_it, '-'), release_it) {
            if (*(release_it++) = '\0', *release_it == '\0') {
                release_it = NULL;
            }
        }

        if (crelease_it = strchr(cversion_it, '-'), crelease_it) {
            if (*(crelease_it++) = '\0', *crelease_it == '\0') {
                crelease_it = NULL;
            }
        }

        // Check version
        v_result = wm_vulnerability_detector_compare(version_it, cversion_it);
        // Check release
        r_result = wm_vulnerability_detector_compare(release_it, crelease_it);

        if (!strcmp(operation, "less than")) {
            if (epoch > c_epoch) {
                return VU_NOT_VULNERABLE;
            } else if (epoch < c_epoch) {
                return VU_VULNERABLE;
            }

            if (v_result == VU_LESS) {
                return VU_VULNERABLE;
            } else if (v_result == VU_HIGHER) {
                return VU_NOT_VULNERABLE;
            }

            if (r_result == VU_LESS) {
                return VU_VULNERABLE;
            }
        } else if (!strcmp(operation, "greater than or equal")) {
            if (epoch > c_epoch) {
                return VU_VULNERABLE;
            } else if (epoch < c_epoch) {
                return VU_NOT_VULNERABLE;
            }

            if (v_result == VU_LESS) {
                return VU_NOT_VULNERABLE;
            } else if (v_result == VU_HIGHER) {
                return VU_VULNERABLE;
            }

            if (r_result != VU_LESS) {
                return VU_VULNERABLE;
            }
        } else if (!strcmp(operation, "less than or equal")) {
            if (epoch < c_epoch) {
                return VU_VULNERABLE;
            } else if (epoch > c_epoch) {
                return VU_NOT_VULNERABLE;
            }

            if (v_result == VU_HIGHER) {
                return VU_NOT_VULNERABLE;
            } else if (v_result == VU_LESS) {
                return VU_VULNERABLE;
            }

            if (r_result != VU_HIGHER) {
                return VU_VULNERABLE;
            }
        } else if (!strcmp(operation, "equal") || !strcmp(operation, "equals")) {
            if (epoch != c_epoch) {
                return VU_NOT_VULNERABLE;
            }

            if (v_result != VU_EQUAL) {
                return VU_NOT_VULNERABLE;
            }

            if (r_result == VU_EQUAL) {
                return VU_VULNERABLE;
            }
        } else if (!strcmp(operation, "exists")) {
            return VU_VULNERABLE;
        } else {
            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OPERATION_NOT_REC, operation);
            return VU_NOT_VULNERABLE;
        }
        // The OVALs supported only contemplate the operation "less than" and "exists"
        return VU_NOT_VULNERABLE;
    }
    return VU_NOT_FIXED;
}

int wm_vulnerability_detector_compare(char *version_it, char *cversion_it) {
    char *found;
    int i, j;
    int version_found, cversion_found;
    int version_value, cversion_value;

    if (version_it && !cversion_it) {
        return VU_HIGHER;
    } else if (!version_it && cversion_it) {
        return VU_LESS;
    } else if (!version_it && !cversion_it) {
        return VU_EQUAL;
    }

    (found = strchr(version_it, '~'))? *found = '\0' : 0;
    (found = strchr(version_it, '-'))? *found = '\0' : 0;
    (found = strchr(version_it, '+'))? *found = '\0' : 0;
    (found = strchr(cversion_it, '~'))? *found = '\0' : 0;
    (found = strchr(cversion_it, '-'))? *found = '\0' : 0;
    (found = strchr(cversion_it, '+'))? *found = '\0' : 0;

    // For RedHat/CentOS packages
    (found = strstr(version_it, ".el"))? *found = '\0' : 0;
    (found = strstr(cversion_it, ".el"))? *found = '\0' : 0;

    // For Ubuntu packages
    (found = strstr(version_it, "ubuntu"))? *found = '\0' : 0;
    (found = strstr(cversion_it, "ubuntu"))? *found = '\0' : 0;

    // For Amazon Linux packages
    (found = strstr(version_it, ".amzn"))? *found = '\0' : 0;
    (found = strstr(cversion_it, ".amzn"))? *found = '\0' : 0;

    // Check version
    if (strcmp(version_it, cversion_it)) {
        for (i = 0, j = 0, version_found = 0, cversion_found = 0;;) {
            if (!version_found) {
                if (version_it[i] == '\0') {
                    version_found = 3;
                } else if (!isdigit(version_it[i])) {
                    if (i) {
                        version_found = 1;
                    } else {
                        if (isalpha(version_it[i]) && !isalpha(version_it[i + 1])) {
                            version_found = 2;
                        } else {
                            if (*version_it == '.') {
                                version_it++;
                            } else {
                                for (; *version_it != '\0' && !isdigit(*version_it); version_it++);
                            }
                            i = 0;
                        }
                    }
                } else {
                    i++;
                }
            }

            if (!cversion_found) {
                if (cversion_it[j] == '\0') {
                    cversion_found = 3;
                } else if (!isdigit(cversion_it[j])) {
                    if (j) {
                        cversion_found = 1;
                    } else {
                        if (isalpha(cversion_it[j]) && !isalpha(cversion_it[j + 1])) {
                            cversion_found = 2;
                        } else {
                            if (*cversion_it == '.') {
                                cversion_it++;
                            } else {
                                for (; *cversion_it != '\0' && !isdigit(*cversion_it); cversion_it++);
                            }
                            j = 0;
                        }
                    }
                } else {
                    j++;
                }
            }

            if (version_found && cversion_found) {
                if (version_found == 2 && version_found == cversion_found) {
                    // Check version letter
                    version_value = *version_it;
                    cversion_value = *cversion_it;
                } else {
                    version_value = strtol(version_it, NULL, 10);
                    cversion_value = strtol(cversion_it, NULL, 10);
                }
                if (version_value > cversion_value) {
                    return VU_HIGHER;
                } else if (version_value < cversion_value) {
                    return VU_LESS;
                } else if (version_found != cversion_found) {
                    // The version with more digits is higher
                    if (version_found < cversion_found) {
                        return VU_HIGHER;
                    } else {
                        return VU_LESS;
                    }
                } else if (version_found > 2) {
                    // The version is over
                    break;
                }
                version_found = 0;
                cversion_found = 0;
                version_it = &version_it[i];
                cversion_it = &cversion_it[j];
                i = 0;
                j = 0;
            }
        }
    }

    return VU_EQUAL;
}

int wm_vulnerability_detector_report_agent_vulnerabilities(agent_software *agents, sqlite3 *db, int max) {
    sqlite3_stmt *stmt = NULL;
    char alert_msg[OS_MAXSTR];
    char header[OS_SIZE_256];
    char condition[OS_SIZE_1024];
    const char *query;
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
    char *cvss2;
    char *cvss3;
    char *patch;
    char *arch_op;
    char *arch_val;
    int i;
    char send_queue;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    if (alert = cJSON_CreateObject(), !alert) {
        return OS_INVALID;
    }

    for (agents_it = agents, i = 0; agents_it && i < max; agents_it = agents_it->prev, i++) {
        if (!agents_it->info) {
            continue;
        }

        if (agents_it->dist != DIS_REDHAT) {
            query = vu_queries[VU_JOIN_QUERY];
        } else {
            query = vu_queries[VU_JOIN_PATCH_QUERY];
        }

        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
            cJSON_free(alert);
            return wm_vulnerability_detector_sql_error(db, stmt);
        }
        sqlite3_bind_int(stmt, 1,  strtol(agents_it->agent_id, NULL, 10));
        sqlite3_bind_text(stmt, 2, agents_it->agent_OS, -1, NULL);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            char *package;
            char *version;
            char *operation, *second_operation;
            char *operation_value, *second_operation_value;
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
            second_operation = (char *)sqlite3_column_text(stmt, 11);
            second_operation_value = (char *)sqlite3_column_text(stmt, 12);
            pending = sqlite3_column_int(stmt, 13);
            cvss2 = (char *)sqlite3_column_text(stmt, 14);
            cvss3 = (char *)sqlite3_column_text(stmt, 15);
            patch = (char *)sqlite3_column_text(stmt, 16);
            arch_op = (char *)sqlite3_column_text(stmt, 17);
            arch_val = (char *)sqlite3_column_text(stmt, 18);

            if (arch_op && arch_val) {
                if (!strcmp(arch_op, "pattern match") || !strcmp(arch_val, "equals")) {
                    if (!strstr(arch_val, agents_it->arch)) {
                        // This check is not for the agent architecture
                        continue;
                    }
                }
            }

            if (!(updated && *updated)) {
                updated = published;
            }

            if (pending) {
                snprintf(state, 30, "Pending confirmation");
            } else {
                if (v_type = wm_checks_package_vulnerability(version, operation, operation_value), v_type == OS_INVALID) {
                    return OS_INVALID;
                }
                if (v_type == VU_NOT_FIXED) {
                    snprintf(state, 15, "Unfixed");
                    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_PACK_VULN, package, cve);
                } else if (v_type == VU_NOT_VULNERABLE) {
                    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_NOT_VULN, package, agents_it->agent_id, cve, version, operation, operation_value);
                    continue;
                } else {
                    snprintf(state, 15, "Fixed");
                    if (!second_operation || *second_operation == '0') {
                        mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_PACK_VER_VULN, package, agents_it->agent_id, cve, version, operation, operation_value);
                    } else {
                        // The first condition is vulnerable, but the second also has to be
                        if (v_type = wm_checks_package_vulnerability(version, second_operation, second_operation_value), v_type == OS_INVALID) {
                            return OS_INVALID;
                        } else if (v_type == VU_VULNERABLE) {
                            mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_DOUBLE_VULN, package, agents_it->agent_id, cve, version, operation, operation_value, second_operation, second_operation_value);
                        } else {
                            mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_DOUBLE_NOT_VULN, package, agents_it->agent_id, cve, version, operation, operation_value, second_operation, second_operation_value);
                            continue;
                        }
                    }
                }
            }

            if (alert_cve = cJSON_CreateObject(), alert_cve) {
                cJSON * jPackage = cJSON_CreateObject();
                cJSON_AddStringToObject(alert_cve, "cve", cve);
                cJSON_AddStringToObject(alert_cve, "title", title);
                cJSON_AddStringToObject(alert_cve, "severity", (severity) ? severity : "Unknown");
                cJSON_AddStringToObject(alert_cve, "published", published);
                cJSON_AddStringToObject(alert_cve, "updated", updated);
                cJSON_AddStringToObject(alert_cve, "reference", reference);

                // Skip rationale if reference is provided
                if (!(reference && *reference)) {
                    cJSON_AddStringToObject(alert_cve, "rationale", rationale);
                }

                cJSON_AddStringToObject(alert_cve, "state", state);
                cJSON_AddItemToObject(alert_cve, "package", jPackage);
                cJSON_AddItemToObject(alert, "vulnerability", alert_cve);
                cJSON_AddStringToObject(jPackage, "name", package);
                cJSON_AddStringToObject(jPackage, "version", version);
                if (cvss2) {
                    cJSON_AddStringToObject(jPackage, "cvss2", cvss2);
                }
                if (cvss3) {
                    cJSON_AddStringToObject(jPackage, "cvss3", cvss3);
                }
                if (patch) {
                    cJSON_AddStringToObject(jPackage, "patch", patch);
                }
                if (!pending) {
                    if (operation_value) {
                        snprintf(condition, OS_SIZE_1024, "%s %s", operation, operation_value);
                        cJSON_AddStringToObject(jPackage, "condition", condition);
                    } else {
                        cJSON_AddStringToObject(jPackage, "condition", operation);
                    }
                }
            } else {
                cJSON_Delete(alert);
                return OS_INVALID;
            }

            str_json = cJSON_PrintUnformatted(alert);

            // Send an alert as a manager if there is no IP assigned
            if (agents_it->agent_ip) {
                snprintf(header, OS_SIZE_256, VU_ALERT_HEADER, agents_it->agent_id, agents_it->agent_name, agents_it->agent_ip);
                snprintf(alert_msg, OS_MAXSTR, VU_ALERT_JSON, str_json);
                send_queue = SECURE_MQ;
            } else {
                snprintf(header, OS_SIZE_256, "%s", VU_WM_NAME);
                snprintf(alert_msg, OS_MAXSTR, "%s", str_json);
                send_queue = LOCALFILE_MQ;
            }
            free(str_json);

            if (wm_sendmsg(usec, *vu_queue, alert_msg, header, send_queue) < 0) {
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


int wm_vulnerability_detector_check_agent_vulnerabilities(agent_software *agents, OSHash *agents_triag, unsigned long ignore_time) {
    agent_software *agents_it;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int result;
    int i;

    if (!agents) {
        mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AG_NO_TARGET);
        return 0;
    } else if (wm_vulnerability_detector_check_db()) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CHECK_DB_ERROR);
        return OS_INVALID;
    } else if (sqlite3_open_v2(CVE_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }

    if (sqlite3_prepare_v2(db, vu_queries[VU_REMOVE_AGENTS_TABLE], -1, &stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }
    if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }
    sqlite3_finalize(stmt);

    for (i = 1, agents_it = agents;; i++) {
        if (result = wm_vulnerability_detector_get_software_info(agents_it, db, agents_triag, ignore_time), result == OS_INVALID) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_GET_SOFTWARE_ERROR, agents_it->agent_id);
        }

        if (result != 2) {
            if (VU_AGENT_REQUEST_LIMIT && i == VU_AGENT_REQUEST_LIMIT) {
                if (wm_vulnerability_detector_report_agent_vulnerabilities(agents_it, db, i) == OS_INVALID) {
                    mterror(WM_VULNDETECTOR_LOGTAG, VU_REPORT_ERROR, agents_it->agent_id);
                }
                i = 0;
                if (sqlite3_prepare_v2(db, vu_queries[VU_REMOVE_AGENTS_TABLE], -1, &stmt, NULL) != SQLITE_OK) {
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }
                if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }
                sqlite3_finalize(stmt);
            }
        }
        if (agents_it->next) {
            agents_it = agents_it->next;
        } else {
            break;
        }
    }

    if (!VU_AGENT_REQUEST_LIMIT) {
        if (wm_vulnerability_detector_report_agent_vulnerabilities(agents_it, db, i) == OS_INVALID) {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_REPORT_ERROR, agents_it->agent_id);
        }
    }

    sqlite3_close_v2(db);
    return 0;
}

int wm_vulnerability_detector_sql_error(sqlite3 *db, sqlite3_stmt *stmt) {
    mterror(WM_VULNDETECTOR_LOGTAG, VU_SQL_ERROR, sqlite3_errmsg(db));
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    sqlite3_close_v2(db);
    return OS_INVALID;
}

int wm_vulnerability_detector_remove_OS_table(sqlite3 *db, char *TABLE, char *OS) {
    sqlite3_stmt *stmt = NULL;
    char sql[MAX_QUERY_SIZE];
    size_t size;

    if (size = snprintf(sql, MAX_QUERY_SIZE, vu_queries[VU_REMOVE_OS], TABLE), sql[size - 1] != ';') {
        return OS_INVALID;
    }

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }

    sqlite3_bind_text(stmt, 1, OS, -1, NULL);

    if (wm_vulnerability_detector_step(stmt) != SQLITE_DONE) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }
    sqlite3_finalize(stmt);

    return 0;
}

int wm_vulnerability_detector_insert(wm_vulnerability_detector_db *parsed_oval) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int result;
    const char *query;
    char *id;
    char *replace;
    char *second_replace;
    char operation_n;
    char p_query[MAX_QUERY_SIZE];
    oval_metadata *met_it = &parsed_oval->metadata;
    vulnerability *vul_it = parsed_oval->vulnerabilities;
    info_state *state_it = parsed_oval->info_states;
    info_test *test_it = parsed_oval->info_tests;
    info_cve *info_it = parsed_oval->info_cves;
    patch *patch_it = parsed_oval->patches;

    if (sqlite3_open_v2(CVE_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }
    if (wm_vulnerability_detector_remove_OS_table(db, CVE_TABLE, parsed_oval->OS)        ||
        wm_vulnerability_detector_remove_OS_table(db, METADATA_TABLE, parsed_oval->OS)   ||
        wm_vulnerability_detector_remove_OS_table(db, CVE_INFO_TABLE, parsed_oval->OS)) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }

    sqlite3_exec(db, vu_queries[BEGIN_T], NULL, NULL, NULL);

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_VU);

    // Adds the vulnerabilities
    while (vul_it) {
        // If you do not have this field, it has been discarded by the preparser and the OS is not affected
        if (vul_it->state_id) {
            if (sqlite3_prepare_v2(db, vu_queries[VU_INSERT_CVE], -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }

            sqlite3_bind_text(stmt, 1, vul_it->cve_id, -1, NULL);
            sqlite3_bind_text(stmt, 2, parsed_oval->OS, -1, NULL);
            sqlite3_bind_text(stmt, 3, vul_it->package_name, -1, NULL);
            sqlite3_bind_int(stmt, 4, vul_it->pending);
            sqlite3_bind_text(stmt, 5, vul_it->state_id, -1, NULL);
            sqlite3_bind_text(stmt, 6, NULL, -1, NULL);
            sqlite3_bind_text(stmt, 7, vul_it->second_state_id, -1, NULL);
            sqlite3_bind_text(stmt, 8, NULL, -1, NULL);
            if (!patch_it) {
                sqlite3_bind_text(stmt, 9, NULL, -1, NULL);
            } else {
                sqlite3_bind_text(stmt, 9, vul_it->cve_id, -1, NULL);
            }

            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            sqlite3_finalize(stmt);
        }

        vulnerability *vul_aux = vul_it;
        vul_it = vul_it->prev;
        free(vul_aux->cve_id);
        free(vul_aux->state_id);
        free(vul_aux->second_state_id);
        free(vul_aux->package_name);
        free(vul_aux);
    }

    if (patch_it) {
        mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_SOL_PATCHES);

        while (patch_it) {
            info_cve *cve_it;
            for (cve_it = patch_it->cve_ref; cve_it;) {
                // Insert the CVEs solved by the patch to vulnerability table
                snprintf(p_query, MAX_QUERY_SIZE, vu_queries[VU_INSERT_CVE_PATCH], cve_it->cveid);
                if (sqlite3_prepare_v2(db, p_query, -1, &stmt, NULL) != SQLITE_OK) {
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }
                sqlite3_bind_text(stmt, 1, *patch_it->patch_id, -1, NULL);

                if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE) {
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }
                sqlite3_finalize(stmt);

                // Insert the CVE info to vulnerability info table
                if (sqlite3_prepare_v2(db, vu_queries[VU_INSERT_CVE_INFO], -1, &stmt, NULL) != SQLITE_OK) {
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }

                sqlite3_bind_text(stmt, 1, cve_it->cveid, -1, NULL);
                sqlite3_bind_text(stmt, 2, NULL, -1, NULL);
                sqlite3_bind_text(stmt, 3, cve_it->severity, -1, NULL);
                sqlite3_bind_text(stmt, 4, cve_it->published, -1, NULL);
                sqlite3_bind_text(stmt, 5, NULL, -1, NULL);
                sqlite3_bind_text(stmt, 6, cve_it->reference, -1, NULL);
                sqlite3_bind_text(stmt, 7, parsed_oval->OS, -1, NULL);
                sqlite3_bind_text(stmt, 8, NULL, -1, NULL);
                sqlite3_bind_text(stmt, 9, cve_it->cvss2, -1, NULL);
                sqlite3_bind_text(stmt, 10, cve_it->cvss3, -1, NULL);
                sqlite3_bind_int(stmt, 11, 1);

                if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }
                sqlite3_finalize(stmt);

                info_cve *cve_aux = cve_it;
                cve_it = cve_it->prev;
                free(cve_aux->cveid);
                free(cve_aux->title);
                free(cve_aux->severity);
                free(cve_aux->published);
                free(cve_aux->reference);
                free(cve_aux->description);
                free(cve_aux->cvss2);
                free(cve_aux->cvss3);
                free(cve_aux);
            }

            // Remove the patch entry from vulnerability table
            if (sqlite3_prepare_v2(db, vu_queries[VU_REMOVE_PATCH], -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            sqlite3_bind_text(stmt, 1, *patch_it->patch_id, -1, NULL);

            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            sqlite3_finalize(stmt);

            patch *patch_aux = patch_it;
            patch_it = patch_it->prev;
            free(patch_aux);
        }
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_INS_TEST_SEC);

    // Links vulnerabilities to their conditions
    while (test_it) {
        id = test_it->id;
        replace = test_it->state;
        second_replace = test_it->second_state;
        if (second_replace || !replace) {
            // 1 test -> 1 or 2 states
            query = vu_queries[VU_UPDATE_DOUBLE_CVE];
            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            if (replace) {
                sqlite3_bind_text(stmt, 1, replace, -1, NULL);
                sqlite3_bind_text(stmt, 2, second_replace, -1, NULL);
                sqlite3_bind_text(stmt, 3, id, -1, NULL);
            } else {
                sqlite3_bind_text(stmt, 1, "exists", -1, NULL);
                sqlite3_bind_text(stmt, 2, NULL, -1, NULL);
                sqlite3_bind_text(stmt, 3, id, -1, NULL);
            }

            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            sqlite3_finalize(stmt);

        } else {
            // Only Windows uses dual conditions
            query = vu_queries[VU_UPDATE_CVE];
            operation_n = 0;

set_op:
            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            sqlite3_bind_text(stmt, 1, replace, -1, NULL);
            sqlite3_bind_text(stmt, 2, id, -1, NULL);
            if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            sqlite3_finalize(stmt);

            if (!operation_n) {
                operation_n = 1;
                query = vu_queries[VU_UPDATE_CVE_SEC];
                goto set_op;
            }
        }

        info_test *test_aux = test_it;
        test_it = test_it->prev;
        free(test_aux->id);
        free(test_aux->state);
        free(test_aux->second_state);
        free(test_aux);
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_VU_CO);

    // Sets the operators and values
    while (state_it) {
        query = vu_queries[VU_UPDATE_CVE_VAL];
        operation_n = 0;
        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
            return wm_vulnerability_detector_sql_error(db, stmt);
        }
        sqlite3_bind_text(stmt, 1, state_it->operation, -1, NULL);
        sqlite3_bind_text(stmt, 2, state_it->operation_value, -1, NULL);
        sqlite3_bind_text(stmt, 3, state_it->arch_operation, -1, NULL);
        sqlite3_bind_text(stmt, 4, state_it->arch_value, -1, NULL);
        sqlite3_bind_text(stmt, 5, state_it->id, -1, NULL);
        if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
            return wm_vulnerability_detector_sql_error(db, stmt);
        }
        sqlite3_finalize(stmt);

        info_state *state_aux = state_it;
        state_it = state_it->prev;
        free(state_aux->id);
        free(state_aux->operation);
        free(state_aux->operation_value);
        free(state_aux->arch_operation);
        free(state_aux->arch_value);
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

        if (sqlite3_prepare_v2(db, vu_queries[VU_INSERT_CVE_INFO], -1, &stmt, NULL) != SQLITE_OK) {
            return wm_vulnerability_detector_sql_error(db, stmt);
        }

        sqlite3_bind_text(stmt, 1, info_it->cveid, -1, NULL);
        sqlite3_bind_text(stmt, 2, info_it->title, -1, NULL);
        sqlite3_bind_text(stmt, 3, info_it->severity, -1, NULL);
        sqlite3_bind_text(stmt, 4, info_it->published, -1, NULL);
        sqlite3_bind_text(stmt, 5, info_it->updated, -1, NULL);
        sqlite3_bind_text(stmt, 6, info_it->reference, -1, NULL);
        sqlite3_bind_text(stmt, 7, parsed_oval->OS, -1, NULL);
        sqlite3_bind_text(stmt, 8, info_it->description, -1, NULL);
        sqlite3_bind_text(stmt, 9, info_it->cvss2, -1, NULL);
        sqlite3_bind_text(stmt, 10, info_it->cvss3, -1, NULL);
        sqlite3_bind_int(stmt, 11, 0);

        if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
            return wm_vulnerability_detector_sql_error(db, stmt);
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
        free(info_aux->cvss2);
        free(info_aux->cvss3);
        free(info_aux);
    }

    if (sqlite3_prepare_v2(db, vu_queries[VU_INSERT_METADATA], -1, &stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }
    sqlite3_bind_text(stmt, 1, parsed_oval->OS, -1, NULL);
    sqlite3_bind_text(stmt, 2, met_it->product_name, -1, NULL);
    sqlite3_bind_text(stmt, 3, met_it->product_version, -1, NULL);
    sqlite3_bind_text(stmt, 4, met_it->schema_version, -1, NULL);
    sqlite3_bind_text(stmt, 5, met_it->timestamp, -1, NULL);
    if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }
    sqlite3_finalize(stmt);

    free(met_it->product_name);
    free(met_it->product_version);
    free(met_it->schema_version);
    free(met_it->timestamp);
    free(parsed_oval->OS);

    sqlite3_exec(db, vu_queries[END_T], NULL, NULL, NULL);
    sqlite3_close_v2(db);
    return 0;
}

int wm_vulnerability_detector_check_db() {
    if (wm_vulnerability_create_file(CVE_DB, schema_vuln_detector_sql)) {
        return OS_INVALID;
    }
    return 0;
}

char * wm_vulnerability_detector_preparser(char *path, distribution dist) {
    FILE *input, *output = NULL;
    char *buffer = NULL;
    size_t size;
    size_t max_size = OS_MAXSTR;
    parser_state state = V_OVALDEFINITIONS;
    char *found;
    char *tmp_file;

    os_strdup(CVE_FIT_TEMP_FILE, tmp_file);

    if (input = fopen((!path)?CVE_TEMP_FILE:path, "r" ), !input) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_OPEN_FILE_ERROR, (!path)?CVE_TEMP_FILE:path);
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
        if (dist == DIS_UBUNTU) { //5.11.1
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
        } else if (dist == DIS_DEBIAN) { //5.3
            switch (state) {
                case V_OVALDEFINITIONS:
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
                    if (strstr(buffer, "oval:org.debian.oval:tst:1") ||
                        strstr(buffer, "oval:org.debian.oval:tst:2")) {
                        goto free_buffer;
                    } else if (found = strstr(buffer, "</definitions>"), found) {
                        state = V_STATES;
                    }
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
        } else if (dist == DIS_REDHAT) { //5.10
            switch (state) {
                case V_OVALDEFINITIONS:
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
                    if (strstr(buffer, "is signed with")) {
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
    if (input) {
        fclose(input);
    }
    if (output) {
        fclose(output);
    }
    return tmp_file;
}

int wm_vulnerability_detector_parser(OS_XML *xml, XML_NODE node, wm_vulnerability_detector_db *parsed_oval, update_node *update, vu_logic condition) {
    int i, j;
    int retval = 0;
    int check = 0;
    char double_condition = 0;
    vulnerability *vuln;
    char *found;
    XML_NODE chld_node;
    distribution dist = update->dist_ref;
    static const char *install_check = "is installed";
    static const char *XML_OVAL_DEFINITIONS = "oval_definitions";
    static const char *XML_GENERATOR = "generator";
    static const char *XML_DEFINITIONS = "definitions";
    static const char *XML_DEFINITION = "definition";
    static const char *XML_TITLE = "title";
    static const char *XML_CLASS = "class";
    static const char *XML_VULNERABILITY = "vulnerability"; //ub 15.11.1
    static const char *XML_PATH = "patch"; //rh 15.10
    static const char *XML_METADATA = "metadata";
    static const char *XML_OVAL_DEF_METADATA = "oval-def:metadata";
    static const char *XML_CRITERIA = "criteria";
    static const char *XML_REFERENCE = "reference";
    static const char *XML_REF_ID = "ref_id";
    static const char *XML_REF_URL = "ref_url";
    static const char *XML_OPERATOR = "operator";
    static const char *XML_OR = "OR";
    static const char *XML_AND = "AND";
    static const char *XML_COMMENT = "comment";
    static const char *XML_CRITERION = "criterion";
    static const char *XML_TEST_REF = "test_ref";
    static const char *XML_TESTS = "tests";
    static const char *XML_DPKG_LINUX_INFO_TEST = "linux-def:dpkginfo_test";
    static const char *XML_DPKG_INFO_TEST = "dpkginfo_test";
    static const char *XML_RPM_INFO_TEST = "red-def:rpminfo_test";
    static const char *XML_ID = "id";
    static const char *XML_LINUX_STATE = "linux-def:state";
    static const char *XML_STATE = "state";
    static const char *XML_RPM_STATE = "red-def:state";
    static const char *XML_STATE_REF = "state_ref";
    static const char *XML_STATES = "states";
    static const char *XML_DPKG_LINUX_INFO_STATE = "linux-def:dpkginfo_state";
    static const char *XML_DPKG_INFO_STATE = "dpkginfo_state";
    static const char *XML_RPM_INFO_STATE = "red-def:rpminfo_state";
    static const char *XML_LINUX_DEF_EVR = "linux-def:evr";
    static const char *XML_EVR = "evr";
    static const char *XML_RPM_DEF_EVR = "red-def:evr";
    static const char *XML_RPM_DEF_ARCH = "red-def:arch";
    static const char *XML_RPM_DEF_VERSION = "red-def:version";
    static const char *XML_RPM_DEF_SIGN = "red-def:signature_keyid";
    static const char *XML_OPERATION = "operation";
    static const char *XML_DATATYPE = "datatype";
    static const char *XML_OVAL_PRODUCT_NAME = "oval:product_name";
    static const char *XML_OVAL_PRODUCT_VERSION = "oval:product_version";
    static const char *XML_OVAL_SCHEMA_VERSION = "oval:schema_version";
    static const char *XML_OVAL_TIMESTAMP = "oval:timestamp";
    static const char *XML_ADVIDSORY = "advisory";
    static const char *XML_CVE = "cve";
    static const char *XML_CVSS2 = "cvss2";
    static const char *XML_CVSS3 = "cvss3";
    static const char *XML_HREF = "href";
    static const char *XML_IMPACT = "impact";
    static const char *XML_PUBLIC = "public";
    static const char *XML_SEVERITY = "severity";
    static const char *XML_PUBLIC_DATE = "public_date";
    static const char *XML_ISSUED = "issued";
    static const char *XML_UPDATED = "updated";
    static const char *XML_CWE = "cwe";
    static const char *XML_DESCRIPTION = "description";
    static const char *XML_DATE = "date";
    static const char *XML_DATES = "dates";
    static const char *XML_OVAL_DEF_DATES = "oval-def:dates";
    static const char *XML_RHEL_CHECK = "Red Hat Enterprise Linux ";
    static const char *XML_DEBIAN = "debian";
    static const char *XML_OVAL_REPOSITORY = "oval_repository";
    static const char *XML_OVAL_DEF_OV_REPO = "oval-def:oval_repository";

    for (i = 0; node[i]; i++) {
        chld_node = NULL;
        if (!node[i]->element) {
            mterror(WM_VULNDETECTOR_LOGTAG, XML_ELEMNULL);
            return OS_INVALID;
        }

        if ((dist == DIS_UBUNTU && !strcmp(node[i]->element, XML_DPKG_LINUX_INFO_STATE)) ||
            (dist == DIS_DEBIAN && !strcmp(node[i]->element, XML_DPKG_INFO_STATE))       ||
            (dist == DIS_REDHAT && !strcmp(node[i]->element, XML_RPM_INFO_STATE))) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_ID)) {
                    info_state *infos;
                    os_calloc(1, sizeof(info_state), infos);
                    os_strdup(node[i]->values[j], infos->id);
                    infos->operation = infos->operation_value = NULL;
                    infos->arch_operation = infos->arch_value = NULL;
                    infos->prev = parsed_oval->info_states;
                    parsed_oval->info_states = infos;
                    if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, condition) == OS_INVALID) {
                        goto end;
                    }
                }
            }
        } else if ((dist == DIS_UBUNTU && !strcmp(node[i]->element, XML_DPKG_LINUX_INFO_TEST)) ||
                   (dist == DIS_DEBIAN && !strcmp(node[i]->element, XML_DPKG_INFO_TEST))       ||
                   (dist == DIS_REDHAT && !strcmp(node[i]->element, XML_RPM_INFO_TEST))) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            info_test *infot;
            os_calloc(1, sizeof(info_test), infot);
            infot->state = NULL;
            infot->second_state = NULL;
            infot->prev = parsed_oval->info_tests;
            parsed_oval->info_tests = infot;

            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_ID)) {
                    os_strdup(node[i]->values[j], parsed_oval->info_tests->id);
                }
            }
            if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, VU_PACKG) == OS_INVALID) {
                goto end;
            }
        } else if ((dist == DIS_UBUNTU && !strcmp(node[i]->element, XML_LINUX_DEF_EVR))                        ||
                   (dist == DIS_DEBIAN && !strcmp(node[i]->element, XML_EVR))                                  ||
                   (dist == DIS_REDHAT && (!strcmp(node[i]->element, XML_RPM_DEF_EVR)                          ||
                   !strcmp(node[i]->element, XML_RPM_DEF_VERSION)                                              ||
                   !strcmp(node[i]->element, XML_RPM_DEF_SIGN)))) {
            if (node[i]->attributes) {
                for (j = 0; node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_OPERATION)) {
                        os_strdup(node[i]->values[j], parsed_oval->info_states->operation);
                        os_strdup(node[i]->content, parsed_oval->info_states->operation_value);
                    }
                }
                if (!parsed_oval->info_states->operation && !strcmp(*node[i]->attributes, XML_DATATYPE) && !strcmp(*node[i]->values, "version")) {
                    os_strdup("equal", parsed_oval->info_states->operation);
                    os_strdup(node[i]->content, parsed_oval->info_states->operation_value);
                }

            }
        } else if (dist == DIS_REDHAT && !strcmp(node[i]->element, XML_RPM_DEF_ARCH)) {
            if (node[i]->attributes) {
                for (j = 0; node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_OPERATION)) {
                        os_strdup(node[i]->values[j], parsed_oval->info_states->arch_operation);
                        os_strdup(node[i]->content, parsed_oval->info_states->arch_value);
                    }
                }
            }
        } else if ((condition == VU_PACKG) &&
                   ((dist == DIS_UBUNTU && !strcmp(node[i]->element, XML_LINUX_STATE))                                        ||
                   (dist == DIS_DEBIAN && !strcmp(node[i]->element, XML_STATE)) ||
                   (dist == DIS_REDHAT && !strcmp(node[i]->element, XML_RPM_STATE)))) {
            // Windows oval has multi-state tests
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_STATE_REF)) {
                    if (!parsed_oval->info_tests->state) {
                        os_strdup(node[i]->values[j], parsed_oval->info_tests->state);
                    } else if (!parsed_oval->info_tests->second_state) {
                        os_strdup(node[i]->values[j], parsed_oval->info_tests->second_state);
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_DEFINITION)) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            }
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_CLASS)) {
                    char is_patch = 0;
                    if (!strcmp(node[i]->values[j], XML_VULNERABILITY) || (is_patch = !strcmp(node[i]->values[j], XML_PATH))) {
                        vulnerability *vuln;
                        info_cve *cves;
                        os_calloc(1, sizeof(vulnerability), vuln);
                        os_calloc(1, sizeof(info_cve), cves);

                        vuln->cve_id = NULL;
                        vuln->state_id = NULL;
                        vuln->second_state_id = NULL;
                        vuln->pending = 0;
                        vuln->package_name = NULL;
                        vuln->prev = parsed_oval->vulnerabilities;
                        cves->cveid = NULL;
                        cves->title = NULL;
                        cves->severity = NULL;
                        cves->published = NULL;
                        cves->updated = NULL;
                        cves->reference = NULL;
                        cves->cvss2 = NULL;
                        cves->cvss3 = NULL;
                        cves->prev = parsed_oval->info_cves;

                        parsed_oval->vulnerabilities = vuln;
                        parsed_oval->info_cves = cves;

                        if (is_patch) {
                            patch *p;
                            os_calloc(1, sizeof(patch), p);
                            p->patch_id = &cves->cveid;
                            p->cve_ref = NULL;
                            p->prev = parsed_oval->patches;
                            parsed_oval->patches = p;
                        }

                        if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, condition) == OS_INVALID) {
                            retval = OS_INVALID;
                            goto end;
                        }
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_REFERENCE)) {
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!parsed_oval->info_cves->reference && !strcmp(node[i]->attributes[j], XML_REF_URL)) {
                    os_strdup(node[i]->values[j], parsed_oval->info_cves->reference);
                } else if (!strcmp(node[i]->attributes[j], XML_REF_ID)){
                    if (!parsed_oval->info_cves->cveid) {
                        os_strdup(node[i]->values[j], parsed_oval->info_cves->cveid);
                    }
                    if (!parsed_oval->vulnerabilities->cve_id) {
                        os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->cve_id);
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_TITLE)) {
                os_strdup(node[i]->content, parsed_oval->info_cves->title);
                // Debian Wheezy OVAL has its CVE of the title
                if (dist == DIS_DEBIAN && !strcmp(parsed_oval->OS, vu_dist_tag[DIS_WHEEZY])) {
                    if (!parsed_oval->info_cves->cveid) {
                        os_strdup(node[i]->content, parsed_oval->info_cves->cveid);
                    }
                    if (!parsed_oval->vulnerabilities->cve_id) {
                        os_strdup(node[i]->content, parsed_oval->vulnerabilities->cve_id);
                    }
                }
        } else if (!strcmp(node[i]->element, XML_CRITERIA)) {
            if (!node[i]->attributes) {
                if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                    goto invalid_elem;
                }
                if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, condition) == OS_INVALID) {
                    retval = OS_INVALID;
                    goto end;
                }
            } else {
                char operator_found = 0;
                for (j = 0; node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_OPERATOR)) {
                        int result = VU_TRUE;
                        operator_found = 1;
                        if (!strcmp(node[i]->values[j], XML_OR)) {
                            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                                continue;
                            } else if (result = wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, VU_OR), result == OS_INVALID) {
                                retval = OS_INVALID;
                                goto end;
                            }
                            if (result == VU_TRUE) {
                                retval = VU_TRUE;
                                check = 1;
                            }

                        } else if (!strcmp(node[i]->values[j], XML_AND)) {
                            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                                continue;
                            } else if (result = wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, VU_AND), result == OS_INVALID) {
                                retval = OS_INVALID;
                                goto end;
                            }
                        } else {
                            mterror(WM_VULNDETECTOR_LOGTAG, VU_INVALID_OPERATOR, node[i]->values[j]);
                            retval = OS_INVALID;
                            goto end;
                        }

                        if (result == VU_FALSE) {
                            if (condition == VU_AND) {
                                retval = VU_FALSE;
                                goto end;
                            } else if (condition == VU_OR && !check) {
                                retval = VU_FALSE;
                            }
                        }
                    }
                }
                // Checks for version comparasions without operators
                if (!operator_found && node[i]->attributes     &&
                    !strcmp(*node[i]->attributes, XML_COMMENT) &&
                    !strcmp(*node[i]->values, "file version")) {
                    if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                        continue;
                    } else if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, VU_AND) == OS_INVALID) {
                        retval = OS_INVALID;
                        goto end;
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_CRITERION)) {
            for (j = 0; node[i]->attributes[j]; j++) {
                if (!strcmp(node[i]->attributes[j], XML_TEST_REF)) {
                    static const char pending_state[] = "tst:10\0";

                    if (parsed_oval->vulnerabilities->state_id) {
                        if (double_condition != 2) {
                            os_calloc(1, sizeof(vulnerability), vuln);
                            os_strdup(parsed_oval->vulnerabilities->cve_id, vuln->cve_id);
                            vuln->prev = parsed_oval->vulnerabilities;
                            vuln->state_id = NULL;
                            vuln->second_state_id = NULL;
                            vuln->package_name = NULL;
                            parsed_oval->vulnerabilities = vuln;

                            if (strstr(node[i]->values[j], pending_state)) {
                                vuln->pending = 1;
                            } else {
                                vuln->pending = 0;
                            }
                            os_strdup(node[i]->values[j], vuln->state_id);
                        } else {
                            // It is a double condition
                            os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->second_state_id);
                            double_condition = 0;
                        }
                    } else {
                        if (strstr(node[i]->values[j], pending_state)) {
                            parsed_oval->vulnerabilities->pending = 1;
                        } else {
                            parsed_oval->vulnerabilities->pending = 0;
                        }
                        os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->state_id);
                    }
                } else if (!strcmp(node[i]->attributes[j], XML_COMMENT)) {
                    char success = 0;
                    if (dist == DIS_REDHAT && (strstr(node[i]->values[j], install_check)) &&
                        (found = strstr(node[i]->values[j], XML_RHEL_CHECK))) {
                        int ver;
                        found += strlen(XML_RHEL_CHECK);
                        ver = strtol(found, NULL, 10);
                        if ((!strcmp(parsed_oval->OS, vu_dist_tag[DIS_RHEL5]) && ver != 5) ||
                            (!strcmp(parsed_oval->OS, vu_dist_tag[DIS_RHEL6]) && ver != 6) ||
                            (!strcmp(parsed_oval->OS, vu_dist_tag[DIS_RHEL7]) && ver != 7)) {
                                retval = VU_FALSE;
                                goto end;
                        } else {
                            break;
                        }
                    }

                    // If the package of the condition has been extracted, we are checking another condition
                    if (parsed_oval->vulnerabilities->package_name) {
                        os_calloc(1, sizeof(vulnerability), vuln);
                        os_strdup(parsed_oval->vulnerabilities->cve_id, vuln->cve_id);
                        vuln->prev = parsed_oval->vulnerabilities;
                        vuln->state_id = NULL;
                        vuln->second_state_id = NULL;
                        vuln->package_name = NULL;
                        parsed_oval->vulnerabilities = vuln;
                    }

                    switch (dist) {
                        case DIS_UBUNTU:
                            if (found = strstr(node[i]->values[j], "'"), found) {
                                char *base = ++found;
                                if (found = strstr(found, "'"), found) {
                                    *found = '\0';
                                    os_strdup(base, parsed_oval->vulnerabilities->package_name);
                                    success = 1;
                                }
                            }
                        break;
                        case DIS_DEBIAN:
                            if (found = strstr(node[i]->values[j], " DPKG is earlier than"), found) {
                               *found = '\0';
                               os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->package_name);
                               success = 1;
                            }
                        break;
                        case DIS_REDHAT:
                            if (found = strstr(node[i]->values[j], " "), found) {
                                *found = '\0';
                                os_strdup(node[i]->values[j], parsed_oval->vulnerabilities->package_name);
                                success = 1;
                            }
                        break;
                        default:
                        break;
                    }

                    if (!success) {
                        mterror(WM_VULNDETECTOR_LOGTAG, VU_PACKAGE_NAME_ERROR);
                        goto end;
                    }
                }
            }
        } else if (!strcmp(node[i]->element, XML_DESCRIPTION)) {
            os_strdup(node[i]->content, parsed_oval->info_cves->description);
        } else if (!strcmp(node[i]->element, XML_OVAL_PRODUCT_VERSION)) {
            os_strdup(node[i]->content, parsed_oval->metadata.product_version);
        } else if (!strcmp(node[i]->element, XML_OVAL_PRODUCT_NAME)) {
            os_strdup(node[i]->content, parsed_oval->metadata.product_name);
        } else if (!strcmp(node[i]->element, XML_DATE)) {
            os_strdup(node[i]->content, parsed_oval->info_cves->published);
        } else if (!strcmp(node[i]->element, XML_OVAL_TIMESTAMP)) {
            os_strdup(node[i]->content, parsed_oval->metadata.timestamp);
            if (found = strstr(parsed_oval->metadata.timestamp, "T"), found) {
                *found = ' ';
            }
        } else if (!strcmp(node[i]->element, XML_OVAL_SCHEMA_VERSION)) {
            os_strdup(node[i]->content, parsed_oval->metadata.schema_version);
        } else if (dist == DIS_REDHAT && !strcmp(node[i]->element, XML_CVE)) {
            if (parsed_oval->patches) {
                patch *pat = parsed_oval->patches;
                info_cve *inf;
                os_calloc(1, sizeof(info_cve), inf);
                inf->prev = pat->cve_ref;
                pat->cve_ref = inf;
                os_strdup(node[i]->content, inf->cveid);
                inf->title = NULL;
                inf->severity = NULL;
                inf->published = NULL;
                inf->updated = NULL;
                inf->reference = NULL;
                inf->cvss2 = NULL;
                inf->cvss3 = NULL;
                inf->description = NULL;
                if (node[i]->attributes) {
                    for (j = 0; node[i]->attributes[j]; j++) {
                        if (!strcmp(node[i]->attributes[j], XML_CVSS2)) {
                            os_strdup(node[i]->values[j], inf->cvss2);
                        } else if (!strcmp(node[i]->attributes[j], XML_CVSS3)) {
                            os_strdup(node[i]->values[j], inf->cvss3);
                        } else if (!strcmp(node[i]->attributes[j], XML_HREF)) {
                            os_strdup(node[i]->values[j], inf->reference);
                        } else if (!strcmp(node[i]->attributes[j], XML_IMPACT)) {
                            *node[i]->values[j] = toupper(*node[i]->values[j]);
                            if (!strcmp(node[i]->values[j], VU_MODERATE)) {
                                os_strdup(VU_MEDIUM, inf->severity);
                            } else if (!strcmp(node[i]->values[j], VU_IMPORTANT)) {
                                os_strdup(VU_HIGH, inf->severity);
                            } else {
                                os_strdup(node[i]->values[j], inf->severity);
                            }
                        } else if (!strcmp(node[i]->attributes[j], XML_PUBLIC)) {
                            if (strlen(node[i]->values[j]) > 7) {
                                os_calloc(1, 11, inf->published);
                                snprintf(inf->published, 11, "%.4s-%.2s-%.2s", node[i]->values[j], node[i]->values[j] + 4, node[i]->values[j] + 6);
                            }
                        } else if (strcmp(node[i]->attributes[j], XML_CWE)) {
                            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNEXP_VALUE, node[i]->attributes[j]);
                        }
                    }
                }

                if (!inf->severity) {
                    os_strdup("Unknown", inf->severity);
                }
            }
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
                os_strdup("Unknown", parsed_oval->info_cves->severity);
            }
        } else if (!strcmp(node[i]->element, XML_UPDATED)) {
            if (node[i]->attributes) {
                for (j = 0; node[i]->attributes[j]; j++) {
                    if (!strcmp(node[i]->attributes[j], XML_DATE)) {
                        os_strdup(node[i]->values[j], parsed_oval->info_cves->updated);
                    }
                }
            }
        } else if ((dist == DIS_UBUNTU && !strcmp(node[i]->element, XML_PUBLIC_DATE)) ||
                   (dist == DIS_REDHAT && !strcmp(node[i]->element, XML_ISSUED))) {
                       if (dist == DIS_REDHAT) {
                           if (node[i]->attributes) {
                               for (j = 0; node[i]->attributes[j]; j++) {
                                   if (!strcmp(node[i]->attributes[j], XML_DATE)) {
                                       os_strdup(node[i]->values[j], parsed_oval->info_cves->published);
                                   }
                               }
                           }
                       } else {
                           os_strdup(node[i]->content, parsed_oval->info_cves->published);
                       }
        } else if (!strcmp(node[i]->element, XML_OVAL_DEFINITIONS)  ||
                   !strcmp(node[i]->element, XML_DEFINITIONS)       ||
                   !strcmp(node[i]->element, XML_METADATA)          ||
                   !strcmp(node[i]->element, XML_OVAL_DEF_METADATA) ||
                   !strcmp(node[i]->element, XML_TESTS)             ||
                   !strcmp(node[i]->element, XML_STATES)            ||
                   !strcmp(node[i]->element, XML_ADVIDSORY)         ||
                   !strcmp(node[i]->element, XML_DEBIAN)            ||
                   !strcmp(node[i]->element, XML_GENERATOR)         ||
                   !strcmp(node[i]->element, XML_OVAL_REPOSITORY)   ||
                   !strcmp(node[i]->element, XML_OVAL_DEF_OV_REPO)  ||
                   !strcmp(node[i]->element, XML_DATES)             ||
                   !strcmp(node[i]->element, XML_OVAL_DEF_DATES)) {
            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                goto invalid_elem;
            } else if (wm_vulnerability_detector_parser(xml, chld_node, parsed_oval, update, condition) == OS_INVALID) {
                retval = OS_INVALID;
                goto end;
            }
        }

        OS_ClearNode(chld_node);
        chld_node = NULL;
    }


end:
    OS_ClearNode(chld_node);
    return retval;

invalid_elem:
    mterror(WM_VULNDETECTOR_LOGTAG, XML_INVELEM, node[i]->element);
    return OS_INVALID;
}

int wm_vulnerability_update_oval(update_node *update) {
    OS_XML xml;
    XML_NODE node = NULL;
    XML_NODE chld_node = NULL;
    char *tmp_file = NULL;
    wm_vulnerability_detector_db parsed_oval;
    const char *OS_VERSION;
    char *path;
    char success = 0;

    memset(&xml, 0, sizeof(xml));
    OS_VERSION = update->dist_tag;

    path = update->path;
    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_PRE);
    if (tmp_file = wm_vulnerability_detector_preparser(path, update->dist_ref), !tmp_file) {
        goto free_mem;
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_PAR);
    if (OS_ReadXML(tmp_file, &xml) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_LOAD_CVE_ERROR, OS_VERSION, xml.err);
        goto free_mem;
    }

    if (node = OS_GetElementsbyNode(&xml, NULL), !node) {
        goto free_mem;
    };

    parsed_oval.vulnerabilities = NULL;
    parsed_oval.info_tests = NULL;
    parsed_oval.file_tests = NULL;
    parsed_oval.info_states = NULL;
    parsed_oval.info_cves = NULL;
    parsed_oval.metadata.product_name = NULL;
    parsed_oval.metadata.product_version = NULL;
    parsed_oval.metadata.schema_version = NULL;
    parsed_oval.metadata.timestamp = NULL;
    parsed_oval.patches = NULL;
    os_strdup(OS_VERSION, parsed_oval.OS);

    // Reduces a level of recurrence
    if (chld_node = OS_GetElementsbyNode(&xml, *node), !chld_node) {
        goto free_mem;
    }

    if (wm_vulnerability_detector_parser(&xml, chld_node, &parsed_oval, update, 0) == OS_INVALID) {
        goto free_mem;
    }

    if (wm_vulnerability_detector_check_db()) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CHECK_DB_ERROR);
        goto free_mem;
    }

    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_START_REFRESH_DB, update->dist_ext);

    if (wm_vulnerability_detector_insert(&parsed_oval)) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_REFRESH_DB_ERROR, OS_VERSION);
        goto free_mem;
    }
    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_STOP_REFRESH_DB, update->dist_ext);

    success = 1;
free_mem:
    if (tmp_file) {
        free(tmp_file);
    }
    OS_ClearNode(node);
    OS_ClearNode(chld_node);
    OS_ClearXML(&xml);
    if (remove(CVE_TEMP_FILE) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, "remove(%s): %s", CVE_TEMP_FILE, strerror(errno));
    }
    if (remove(CVE_FIT_TEMP_FILE) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, "remove(%s): %s", CVE_FIT_TEMP_FILE, strerror(errno));
    }

    if (success) {
        return 0;
    } else {
        return OS_INVALID;
    }
}

int wm_vulnerability_detector_socketconnect(char *url, in_port_t port) {
	struct sockaddr_in addr, *addr_it;
	int on = 1, sock;
    struct addrinfo hints, *host_info, *hinfo_it;
    char ip_addr[30];

    if(!port) {
        port = DEFAULT_OVAL_PORT;
    }

	*ip_addr = '\0';
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(url, "http" , &hints , &host_info)) {
        return OS_INVALID;
	}

	for(hinfo_it = host_info; hinfo_it != NULL; hinfo_it = hinfo_it->ai_next) {
		addr_it = (struct sockaddr_in *) hinfo_it->ai_addr;
		if (addr_it->sin_addr.s_addr) {
			strncpy(ip_addr , inet_ntoa(addr_it->sin_addr), sizeof(ip_addr));
            ip_addr[sizeof(ip_addr) - 1] = '\0';
		}
	}

    // https://bugzilla.redhat.com/show_bug.cgi?id=116526
	freeaddrinfo(host_info);

    if (*ip_addr == '\0') {
        return OS_INVALID;
	}

	inet_pton(AF_INET, ip_addr, &addr.sin_addr);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(sock < 0 || connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Cannot connect to %s:%i.", url, (int)port);
        close(sock);
        return OS_INVALID;
	}

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
	return sock;
}

int wm_vulnerability_fetch_oval(update_node *update, const char *OS, int *need_update) {
    int sock = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *found;
    char *timst;
    long int size;
    long int readed;
    long int oval_size;
    long int octet_rem = 0;
    char buffer[VU_SSL_BUFFER];
    char repo_file[OS_SIZE_2048];
    char repo[OS_SIZE_2048];
    char *low_repo;
    int i;
    FILE *fp = NULL;
    char timestamp_found = 0;
    char octet_stream;
    int attemps = 0;
    *need_update = 1;
    unsigned char success = 1;
    in_port_t port = update->port;

    if (update->path) {
        mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_LOCAL_FETCH, update->path);
        return 0;
    }

    if (!update->url) {
        if (!strcmp(update->dist, vu_dist_tag[DIS_UBUNTU])) {
            os_strdup(update->version, low_repo);
            for(i = 0; low_repo[i] != '\0'; i++) {
                low_repo[i] = tolower(low_repo[i]);
            }
            snprintf(repo_file, OS_SIZE_2048, UBUNTU_OVAL, low_repo);
            snprintf(repo, OS_SIZE_2048, "%s", CANONICAL_REPO);
            free(low_repo);
        } else if (!strcmp(update->dist, vu_dist_tag[DIS_DEBIAN])) {
            os_strdup(update->version, low_repo);
            for(i = 0; low_repo[i] != '\0'; i++) {
                low_repo[i] = tolower(low_repo[i]);
            }
            snprintf(repo_file, OS_SIZE_2048, DEBIAN_OVAL, low_repo);
            snprintf(repo, OS_SIZE_2048, "%s", DEBIAN_REPO);
            free(low_repo);
        } else if (!strcmp(update->dist, vu_dist_tag[DIS_REDHAT])) {
            snprintf(repo_file, OS_SIZE_2048, REDHAT_OVAL, update->version);
            snprintf(repo, OS_SIZE_2048, "%s", REDHAT_REPO);
        } else {
            mterror(WM_VULNDETECTOR_LOGTAG, VU_OS_VERSION_ERROR);
            return OS_INVALID;
        }
    } else {
        int offset = 0;
        char *limit;
        if (!strncasecmp(update->url, HTTPS_HEADER, strlen(HTTPS_HEADER))) {
            offset = strlen(HTTPS_HEADER);
        } else if (!strncasecmp(update->url, HTTP_HEADER, strlen(HTTP_HEADER))) {
            offset = strlen(HTTP_HEADER);
        }

        snprintf(repo, OS_SIZE_2048, "%s", update->url + offset);
        if (limit = strchr(repo, '/'), limit) {
            snprintf(repo_file, OS_SIZE_2048, "%s", limit);
            *limit = '\0';
        } else {
            snprintf(repo_file, OS_SIZE_2048, "/");
        }
    }

    snprintf(buffer, VU_SSL_BUFFER, OVAL_REQUEST, repo_file, repo);
    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_DOWNLOAD, OS);

    if (sock = wm_vulnerability_detector_socketconnect(repo, port), sock < 0) {
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

    memset(buffer,0,sizeof(buffer));

    if (size = SSL_read(ssl, buffer, WM_HEADER_SIZE), size < 1) {
        success = 0;
        goto free_mem;
    }

    if (oval_size = wm_read_http_size(buffer), oval_size) {
        octet_stream = 0;
    } else if (found = strstr(buffer, "Content-Type: application/octet-stream"), found){
        octet_stream = 1;
    } else {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_HTTP_HEADER_ERROR);
        success = 0;
        goto free_mem;
    }

    if((found = strstr(buffer, "<?xml version=")) || (found = strstr(buffer, "<oval_definitions"))) {
        // If the first request includes content in addition to headers
        readed = strlen(found);
        fwrite(found, 1, readed, fp);
        timestamp_found = 1;
        goto check_timestamp;
    }

    for (attemps = 0; attemps < VU_MAX_TIMESTAMP_ATTEMPS && (oval_size != readed || octet_stream) &&
           (size = wm_vulnerability_ssl_request_size(octet_stream, &octet_rem, ssl, oval_size, readed)) > 0 &&
           (size = SSL_read(ssl, buffer, size)) > 0; ++attemps) {
        buffer[size] = '\0';
        readed += size;
        octet_rem -= size;

        if (!timestamp_found) {
check_timestamp:
            if (timst = strstr(buffer, "timestamp>"), timst) {
                int update = 1;
                char stored_timestamp[KEY_SIZE];
                int i;
                sqlite3_stmt *stmt = NULL;
                sqlite3 *db;

                if (sqlite3_open_v2(CVE_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
                    update = 0;
                } else {
                    if (sqlite3_prepare_v2(db, vu_queries[TIMESTAMP_QUERY], -1, &stmt, NULL) != SQLITE_OK) {
                        success = 0;
                        sqlite3_finalize(stmt);
                        sqlite3_close_v2(db);
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
                }

                sqlite3_close_v2(db);

                if (update) {
                    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_DATE, OS, stored_timestamp);
                    *need_update = 0;
                    goto free_mem;
                }
            }

            if (!timestamp_found) {
                timestamp_found = 1;
            } else {
                continue;
            }
        }
        fwrite(buffer, 1, size, fp);
        memset(buffer,0,sizeof(buffer));
    }

    if (attemps == VU_MAX_TIMESTAMP_ATTEMPS) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_TIMESTAMP_LABEL_ERROR, VU_MAX_TIMESTAMP_ATTEMPS);
        close(sock);
        sock = -1;
        success = 0;
        goto free_mem;
    }

free_mem:
    CRYPTO_cleanup_all_ex_data();
    if (fp) {
        fclose(fp);
    }
    if (sock >= 0) {
        close(sock);
    }
    if (ssl) {
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (success) {
        return 0;
    } else {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_FETCH_ERROR, OS);
        return OS_INVALID;
    }
}

int wm_vulnerability_run_update(update_node *upd, const char *dist, const char *tag) {
    if (wm_vulnerability_check_update_period(upd)) {
        mtinfo(WM_VULNDETECTOR_LOGTAG, VU_STARTING_UPDATE, tag);
        if (wm_vulnerability_check_update(upd, dist)) {
            if (!upd->attempted) {
                upd->last_update = time(NULL) - upd->interval + WM_VULNDETECTOR_RETRY_UPDATE;
                upd->attempted = 1;
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_RETRY, upd->dist, upd->version, (long unsigned)WM_VULNDETECTOR_RETRY_UPDATE);
            } else {
                upd->last_update = time(NULL);
                upd->attempted = 0;
                mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UPDATE_RETRY, upd->dist, upd->version, upd->interval);
            }
            return OS_INVALID;
        } else {
            mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_OVA_UPDATED, tag);
            upd->last_update = time(NULL);
        }
    }
    return 0;
}


int wm_vulnerability_detector_updatedb(update_node **updates) {
        // Ubuntu
    if (wm_vulnerability_run_update(updates[CVE_BIONIC],   vu_dist_tag[DIS_BIONIC],   vu_dist_ext[DIS_BIONIC])   ||
        wm_vulnerability_run_update(updates[CVE_XENIAL],   vu_dist_tag[DIS_XENIAL],   vu_dist_ext[DIS_XENIAL])   ||
        wm_vulnerability_run_update(updates[CVE_TRUSTY],   vu_dist_tag[DIS_TRUSTY],   vu_dist_ext[DIS_TRUSTY])   ||
        wm_vulnerability_run_update(updates[CVE_PRECISE],   vu_dist_tag[DIS_PRECISE],  vu_dist_ext[DIS_PRECISE]) ||
        // Debian
        wm_vulnerability_run_update(updates[CVE_STRETCH],  vu_dist_tag[DIS_STRETCH],  vu_dist_ext[DIS_STRETCH])  ||
        wm_vulnerability_run_update(updates[CVE_JESSIE],   vu_dist_tag[DIS_JESSIE],   vu_dist_ext[DIS_JESSIE])   ||
        wm_vulnerability_run_update(updates[CVE_WHEEZY],   vu_dist_tag[DIS_WHEEZY],   vu_dist_ext[DIS_WHEEZY])   ||
        // RedHat
        wm_vulnerability_run_update(updates[CVE_RHEL5],    vu_dist_tag[DIS_RHEL5],    vu_dist_ext[DIS_RHEL5])    ||
        wm_vulnerability_run_update(updates[CVE_RHEL6],    vu_dist_tag[DIS_RHEL6],    vu_dist_ext[DIS_RHEL6])    ||
        wm_vulnerability_run_update(updates[CVE_RHEL7],    vu_dist_tag[DIS_RHEL7],    vu_dist_ext[DIS_RHEL7])) {
        return OS_INVALID;
    }

    return 0;
}

int wm_vulnerability_detector_get_software_info(agent_software *agent, sqlite3 *db, OSHash *agents_triag, unsigned long ignore_time) {
    int sock = 0;
    unsigned int i;
    int size;
    char buffer[OS_MAXSTR];
    char json_str[OS_MAXSTR];
    char scan_id[OS_SIZE_1024];
    int request = VU_SOFTWARE_REQUEST;
    char *found;
    int retval;
    sqlite3_stmt *stmt = NULL;
    cJSON *obj = NULL;
    cJSON *package_list = NULL;
    last_scan *scan;
    int result;
    mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_AGENT_SOFTWARE_REQ, agent->agent_id);

    for (i = 0; i < VU_MAX_WAZUH_DB_ATTEMPS && (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK_PATH, SOCK_STREAM, OS_MAXSTR)) < 0; i++) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Unable to connect to socket '%s'. Waiting %d seconds.", WDB_LOCAL_SOCK_PATH, i);
        sleep(i);
    }

    if (i == VU_MAX_WAZUH_DB_ATTEMPS) {
        mterror(WM_VULNDETECTOR_LOGTAG, "Unable to connect to socket '%s'.", WDB_LOCAL_SOCK_PATH);
        return OS_INVALID;
    }

    // Request the ID of the last scan
    size = snprintf(buffer, OS_MAXSTR, vu_queries[VU_SYSC_SCAN_REQUEST], agent->agent_id);
    if (send(sock, buffer, size + 1, 0) < size || (size = recv(sock, buffer, OS_MAXSTR, 0)) < 1) {
        close(sock);
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SYSC_SCAN_REQUEST_ERROR, agent->agent_id);
        return OS_INVALID;
    }

    buffer[size] = '\0';
    if (!strncmp(buffer, "ok", 2)) {
        buffer[0] = buffer[1] = ' ';
        // Check empty answers
        if ((found = strchr(buffer, '[')) && *(++found) != '\0' && *found == ']') {
            mtdebug1(WM_VULNDETECTOR_LOGTAG , VU_NO_SYSC_SCANS, agent->agent_id);
            retval = 2;
            goto end;
        }
        size = snprintf(json_str, OS_MAXSTR, "{\"data\":%s}", buffer);
        json_str[size] = '\0';
    } else {
        retval = OS_INVALID;
        goto end;
    }

    if (obj = cJSON_Parse(json_str), obj && cJSON_IsObject(obj)) {
        cJSON_GetObjectItem(obj, "data");
    } else {
        retval = OS_INVALID;
        goto end;
    }

    size = snprintf(scan_id, OS_SIZE_1024, "%i", (int) cJSON_GetObjectItem(obj, "data")->child->child->valuedouble);
    scan_id[size] = '\0';

    cJSON_Delete(obj);
    obj = NULL;

    // Check to see if the scan has already been reported
    if (scan = OSHash_Get(agents_triag, agent->agent_id), scan) {
            if ((scan->last_scan_time + (time_t) ignore_time) < time(NULL)) {
                scan->last_scan_time = time(NULL);
                request = VU_SOFTWARE_FULL_REQ;
            } else if (!strcmp(scan_id, scan->last_scan_id)) {
                // Nothing to do
                close(sock);
                mtdebug2(WM_VULNDETECTOR_LOGTAG, VU_SYS_CHECKED, agent->agent_id, scan_id);
                return 0;
            } else {
                free(scan->last_scan_id);
                os_strdup(scan_id, scan->last_scan_id);
            }
    } else {
        os_calloc(1, sizeof(last_scan), scan);
        os_strdup(scan_id, scan->last_scan_id);
        scan->last_scan_time = time(NULL);
        OSHash_Add(agents_triag, agent->agent_id, scan);
        request = VU_SOFTWARE_FULL_REQ; // Check all at the first time
    }

    // Request and store packages
    i = 0;
    size = snprintf(buffer, OS_MAXSTR, vu_queries[request], agent->agent_id, scan_id, VU_MAX_PACK_REQ, i);
    if (send(sock, buffer, size + 1, 0) < size) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SOFTWARE_REQUEST_ERROR, agent->agent_id);
        close(sock);
        return OS_INVALID;
    }

    while (size = recv(sock, buffer, OS_MAXSTR, 0), size) {
        if (size > 0) {
            if (size < 10) {
                break;
            }
            buffer[size] = '\0';
            if (!strncmp(buffer, "ok", 2)) {
                buffer[0] = buffer[1] = ' ';
                size = snprintf(json_str, OS_MAXSTR, "{\"data\":%s}", buffer);
                json_str[size] = '\0';
            } else {
                retval = OS_INVALID;
                goto end;
            }
            if (obj) {
                cJSON *new_obj;
                cJSON *data;
                if (new_obj = cJSON_Parse(json_str), !new_obj) {
                    retval = OS_INVALID;
                    goto end;
                } else if (!cJSON_IsObject(new_obj)) {
                    free(new_obj);
                    retval = OS_INVALID;
                    goto end;
                }
                data = cJSON_GetObjectItem(new_obj, "data");
                if (data) {
                    cJSON_AddItemToArray(package_list, data->child);
                    free(data->string);
                    free(data);
                }
                free(new_obj);
            } else if (obj = cJSON_Parse(json_str), obj && cJSON_IsObject(obj)) {
                package_list = cJSON_GetObjectItem(obj, "data");
                if (!package_list) {
                    retval = OS_INVALID;
                    goto end;
                }
            } else {
                retval = OS_INVALID;
                goto end;
            }

            i += VU_MAX_PACK_REQ;
            size = snprintf(buffer, OS_MAXSTR, vu_queries[request], agent->agent_id, scan_id, VU_MAX_PACK_REQ, i);
            if (send(sock, buffer, size + 1, 0) < size) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_SOFTWARE_REQUEST_ERROR, agent->agent_id);
                retval = OS_INVALID;
                goto end;
            }
        } else {
            retval = OS_INVALID;
            goto end;
        }
    }

    // Avoid checking the same packages again
    size = snprintf(buffer, OS_MAXSTR, vu_queries[VU_SYSC_UPDATE_SCAN], agent->agent_id, scan_id);
    if (send(sock, buffer, size + 1, 0) < size) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_SOFTWARE_REQUEST_ERROR, agent->agent_id);
        retval = OS_INVALID;
        goto end;
    }

    close(sock);
    sock = 0;

    if (package_list) {
        cJSON *name;
        cJSON *version;
        cJSON *architecture;
        sqlite3_exec(db, vu_queries[BEGIN_T], NULL, NULL, NULL);
        for (package_list = package_list->child; package_list; package_list = package_list->next) {
            if (sqlite3_prepare_v2(db, vu_queries[VU_INSERT_AGENTS], -1, &stmt, NULL) != SQLITE_OK) {
                close(sock);
                return wm_vulnerability_detector_sql_error(db, stmt);
            }
            if ((name = cJSON_GetObjectItem(package_list, "name")) &&
                (version = cJSON_GetObjectItem(package_list, "version")) &&
                (architecture = cJSON_GetObjectItem(package_list, "architecture"))) {

                sqlite3_bind_text(stmt, 1, agent->agent_id, -1, NULL);
                sqlite3_bind_text(stmt, 2, name->valuestring, -1, NULL);
                sqlite3_bind_text(stmt, 3, version->valuestring, -1, NULL);
                sqlite3_bind_text(stmt, 4, architecture->valuestring, -1, NULL);

                if (result = wm_vulnerability_detector_step(stmt), result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
                    close(sock);
                    return wm_vulnerability_detector_sql_error(db, stmt);
                }
            }
            sqlite3_finalize(stmt);

        }
        sqlite3_exec(db, vu_queries[END_T], NULL, NULL, NULL);
        agent->info = 1;
    } else {
        mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_NO_SOFTWARE, agent->agent_id);
    }

    retval = 0;
end:
    if (obj) {
        cJSON_Delete(obj);
    }
    if (sock) {
        close(sock);
    }
    return retval;
}

void * wm_vulnerability_detector_main(wm_vulnerability_detector_t * vulnerability_detector) {
    time_t time_sleep = 0;
    wm_vulnerability_detector_flags *flags = &vulnerability_detector->flags;
    update_node **updates = vulnerability_detector->updates;
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
        vulnerability_detector->last_detection = 0;
        for (i = 0; i < OS_SUPP_SIZE; i++) {
            if (updates[i]) {
                updates[i]->last_update = 0;
            }
        }
    } else {
        vulnerability_detector->last_detection = time(NULL);
        for (i = 0; i < OS_SUPP_SIZE; i++) {
            if (updates[i]) {
                updates[i]->last_update = time(NULL);
            }
        }
    }

    if (vulnerability_detector->agents_triag = OSHash_Create(), !vulnerability_detector->agents_triag) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_CREATE_HASH_ERRO);
        pthread_exit(NULL);
    }

    while (1) {
        // Update CVE databases
        if (flags->u_flags.update &&
            wm_vulnerability_detector_updatedb(vulnerability_detector->updates)) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_OVAL_UPDATE_ERROR);
        }

        if ((vulnerability_detector->last_detection + (time_t) vulnerability_detector->detection_interval) < time(NULL)) {
            mtinfo(WM_VULNDETECTOR_LOGTAG, VU_START_SCAN);

            if (wm_vunlnerability_detector_set_agents_info(&vulnerability_detector->agents_software, updates)) {
                mterror(WM_VULNDETECTOR_LOGTAG, VU_NO_AGENT_ERROR);
            } else {
                if (wm_vulnerability_detector_check_agent_vulnerabilities(vulnerability_detector->agents_software, vulnerability_detector->agents_triag, vulnerability_detector->ignore_time)) {
                    mterror(WM_VULNDETECTOR_LOGTAG, VU_AG_CHECK_ERR);
                } else {
                    mtinfo(WM_VULNDETECTOR_LOGTAG, VU_END_SCAN);
                }
                agent_software *agent;
                for (agent = vulnerability_detector->agents_software; agent;) {
                    agent_software *agent_aux = agent->next;
                    free(agent->agent_id);
                    free(agent->agent_name);
                    free(agent->agent_OS);
                    free(agent->arch);
                    free(agent->agent_ip);
                    free(agent);

                    if (agent_aux) {
                        agent = agent_aux;
                    } else {
                        break;
                    }
                }
                vulnerability_detector->agents_software = NULL;
            }

            vulnerability_detector->last_detection = time(NULL);
        }

        time_t t_now = time(NULL);
        time_sleep = (vulnerability_detector->last_detection + vulnerability_detector->detection_interval) - t_now;
        if (time_sleep < 0) {
            time_sleep = 0;
            i = OS_SUPP_SIZE;
        } else {
            i = 0;
        }

        // Check the remaining time for all updates and adjust the sleep time
        for (; i < OS_SUPP_SIZE; i++) {
            if (updates[i]) {
                time_t t_diff = (updates[i]->last_update + updates[i]->interval) - t_now;
                // Stop checking if we have any pending updates
                if (t_diff < 0) {
                    time_sleep = 0;
                    break;
                } else if (t_diff < time_sleep) {
                    time_sleep = t_diff;
                }
            }
        }

        sleep(time_sleep);
    }

}

int wm_vunlnerability_detector_set_agents_info(agent_software **agents_software, update_node **updates) {
    agent_software *agents = NULL;
    agent_software *f_agent = NULL;
    char global_db[OS_FLSIZE + 1];
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int dist_error;
    char *id;
    char *name;
    char *ip;
    char *os_name;
    char *os_version;
    char *arch;
    const char *agent_os;
    distribution agent_dist;

    snprintf(global_db, OS_FLSIZE, "%s%s/%s", isChroot() ? "/" : "", WDB_DIR, WDB_GLOB_NAME);

    if (sqlite3_open_v2(global_db, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        mterror(WM_VULNDETECTOR_LOGTAG, VU_GLOBALDB_OPEN_ERROR);
        return wm_vulnerability_detector_sql_error(db, stmt);
    }

    // Extracts the operating system of the agents
    if (sqlite3_prepare_v2(db, vu_queries[VU_GLOBALDB_REQUEST], -1, &stmt, NULL) != SQLITE_OK) {
        return wm_vulnerability_detector_sql_error(db, stmt);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        dist_error = -1;
        os_name = (char *) sqlite3_column_text(stmt, 0);
        os_version = (char *) sqlite3_column_text(stmt,1);
        name = (char *) sqlite3_column_text(stmt, 2);

        if (!os_name) {
            // The agent has never connected
            continue;
        }

        if (strcasestr(os_name, vu_dist_ext[DIS_UBUNTU])) {
            if (strstr(os_version, "18")) {
                agent_os = vu_dist_tag[DIS_BIONIC];
            } else if (strstr(os_version, "16")) {
                agent_os = vu_dist_tag[DIS_XENIAL];
            } else if (strstr(os_version, "14")) {
                agent_os = vu_dist_tag[DIS_TRUSTY];
            } else if (strstr(os_version, "12")) {
                agent_os = vu_dist_tag[DIS_PRECISE];
            } else {
                dist_error = DIS_UBUNTU;
            }
            agent_dist = DIS_UBUNTU;
        } else if (strcasestr(os_name, vu_dist_ext[DIS_DEBIAN])) {
            if (strstr(os_version, "7")) {
                agent_os = vu_dist_tag[DIS_WHEEZY];
            } else if (strstr(os_version, "8")) {
                agent_os = vu_dist_tag[DIS_JESSIE];
            } else if (strstr(os_version, "9")) {
                agent_os = vu_dist_tag[DIS_STRETCH];
            } else {
                dist_error = DIS_DEBIAN;
            }
            agent_dist = DIS_DEBIAN;
        } else if (strcasestr(os_name, vu_dist_ext[DIS_REDHAT])) {
            if (strstr(os_version, "7")) {
                agent_os = vu_dist_tag[DIS_RHEL7];
            } else if (strstr(os_version, "6")) {
                agent_os = vu_dist_tag[DIS_RHEL6];
            } else if (strstr(os_version, "5")) {
                agent_os = vu_dist_tag[DIS_RHEL5];
            } else {
                dist_error = DIS_REDHAT;
            }
            agent_dist = DIS_REDHAT;
        } else if (strcasestr(os_name, vu_dist_ext[DIS_CENTOS])) {
            if (strstr(os_version, "7")) {
                agent_os = vu_dist_tag[DIS_RHEL7];
            } else if (strstr(os_version, "6")) {
                agent_os = vu_dist_tag[DIS_RHEL6];
            } else if (strstr(os_version, "5")) {
                agent_os = vu_dist_tag[DIS_RHEL5];
            } else {
                dist_error = DIS_CENTOS;
            }
            agent_dist = DIS_REDHAT;
        } else {
            // Operating system not supported in any of its versions
            dist_error = -2;
        }

        if (dist_error != -1) {
            // Check if the agent OS can be matched with a OVAL
            if (agent_os = wm_vulnerability_set_oval(os_name, os_version, updates, &agent_dist), !agent_os) {
                if (dist_error == -2) {
                    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_AGENT_UNSOPPORTED, name);
                    continue;
                } else {
                    mtdebug1(WM_VULNDETECTOR_LOGTAG, VU_UNS_OS_VERSION, vu_dist_ext[dist_error], name);
                    continue;
                }
            }
        }

        id = (char *) sqlite3_column_text(stmt, 3);
        ip = (char *) sqlite3_column_text(stmt, 4);
        arch = (char *) sqlite3_column_text(stmt, 5);

        if (agents) {
            os_malloc(sizeof(agent_software), agents->next);
            agents->next->prev = agents;
            agents = agents->next;
        } else {
            os_malloc(sizeof(agent_software), agents);
            agents->prev = NULL;
            f_agent = agents;
        }

        os_strdup(id, agents->agent_id);
        if (strcmp(ip, "127.0.0.1")) {
            os_strdup(ip, agents->agent_ip);
        } else {
            agents->agent_ip = NULL;
        }
        os_strdup(name, agents->agent_name);
        os_strdup(agent_os, agents->agent_OS);
        os_strdup(arch, agents->arch);
        agents->dist = agent_dist;
        agents->info = 0;
        agents->next = NULL;
    }
    sqlite3_finalize(stmt);
    *agents_software = f_agent;
    sqlite3_close_v2(db);
    return 0;
}

void wm_vulnerability_detector_destroy(wm_vulnerability_detector_t * vulnerability_detector) {
    agent_software *agent;
    update_node **update;
    int i, j;

    if (vulnerability_detector->agents_triag) {
        OSHash_Free(vulnerability_detector->agents_triag);
    }

    for (i = 0, update = vulnerability_detector->updates; i < OS_SUPP_SIZE; i++) {
        if (update[i]) {
            free(update[i]->dist);
            free(update[i]->version);
            free(update[i]->url);
            free(update[i]->path);
            if (update[i]->allowed_OS_list) {
                for (j = 0; update[i]->allowed_OS_list[j]; j++) {
                    free(update[i]->allowed_OS_list[j]);
                }
                free(update[i]->allowed_OS_list);
            }
            free(update[i]);
        }
    }

    for (agent = vulnerability_detector->agents_software; agent;) {
        agent_software *agent_aux = agent->next;
        free(agent->agent_id);
        free(agent->agent_name);
        free(agent->agent_OS);
        free(agent->agent_ip);
        free(agent);

        if (agent_aux) {
            agent = agent_aux;
        } else {
            break;
        }
    }
    free(vulnerability_detector);
}

#endif
