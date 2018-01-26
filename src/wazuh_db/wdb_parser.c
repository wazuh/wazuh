/*
 * Wazuh Database Daemon
 * Copyright (C) 2018 Wazuh Inc.
 * January 16, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

int wdb_parse(char * input, char * output) {
    char * actor;
    char * id;
    char * query;
    char * sql;
    char * next;
    int agent_id;
    wdb_t * wdb;
    cJSON * data;
    char * out;
    int result = 0;

    // Clean string

    while (*input == ' ' || *input == '\n') {
        input++;
    }

    if (!*input) {
        mdebug1("Empty input query.");
        return -1;
    }

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return -1;
    }

    actor = input;
    *next++ = '\0';

    if (strcmp(actor, "agent") == 0) {
        id = next;

        if (next = strchr(id, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", id);
            return -1;
        }

        *next++ = '\0';
        query = next;

        if (agent_id = strtol(id, &next, 10), *next) {
            mdebug1("Invalid agent ID '%s'", id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid agent ID '%.32s'", id);
            return -1;
        }

        if (wdb = wdb_open_agent2(agent_id), !wdb) {
            merror("Couldn't open DB for agent '%d'", agent_id);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB for agent %d", agent_id);
            return -1;
        }

        mdebug2("Executing query: %s", query);

        if (next = strchr(query, ' '), next) {
            *next++ = '\0';
        }

        if (strcmp(query, "syscheck") == 0) {
            if (!next) {
                mdebug1("Invalid Syscheck query syntax.");
                mdebug2("Syscheck query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = -1;
            } else {
                result = wdb_parse_syscheck(wdb, next, output);
            }
        } else if (strcmp(query, "osinfo") == 0) {
            if (!next) {
                mdebug1("Invalid DB query syntax.");
                mdebug2("DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_osinfo(wdb, next, output) == 0){
                    mdebug2("Stored OS information in DB for agent '%d'", agent_id);
                }
            }
        } else if (strcmp(query, "sql") == 0) {
            if (!next) {
                mdebug1("Invalid DB query syntax.");
                mdebug2("DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                sql = next;

                if (data = wdb_exec(wdb->db, sql), data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Cannot execute SQL query.");
                    mdebug2("SQL query: %s", sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute SQL query");
                    result = -1;
                }
            }
        } else if (strcmp(query, "begin") == 0) {
            if (wdb_begin2(wdb) < 0) {
                mdebug1("Cannot begin transaction.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot begin transaction");
                result = -1;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
            }
        } else if (strcmp(query, "commit") == 0) {
            if (wdb_commit2(wdb) < 0) {
                mdebug1("Cannot end transaction.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot end transaction");
                result = -1;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
            }
        } else if (strcmp(query, "close") == 0) {
            wdb_leave(wdb);
            w_mutex_lock(&pool_mutex);

            if (wdb_close(wdb) < 0) {
                mdebug1("Cannot close database.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot close database");
                result = -1;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
                result = 0;
            }

            w_mutex_unlock(&pool_mutex);
            return result;
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = -1;
        }
        wdb_leave(wdb);
        return result;
    } else {
        mdebug1("Invalid DB query actor: %s", actor);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query actor: '%.32s'", actor);
        return -1;
    }
}

int wdb_parse_syscheck(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    int ftype;
    char * checksum;
    int result;
    char buffer[OS_MAXSTR + 1];

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Syscheck query syntax.");
        mdebug2("Syscheck query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "load") == 0) {
        if (result = wdb_syscheck_load(wdb, next, buffer, sizeof(buffer)), result < 0) {
            mdebug1("Cannot load Syscheck.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot load Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok %s", buffer);
        }

        return result;
    } else if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, ' '), !next) {
            mdebug1("Invalid Syscheck query syntax.");
            mdebug2("Syscheck query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';

        if (strcmp(curr, "file") == 0) {
            ftype = WDB_FILE_TYPE_FILE;
        } else if (strcmp(curr, "registry") == 0) {
            ftype = WDB_FILE_TYPE_REGISTRY;
        } else {
            mdebug1("Invalid Syscheck query syntax.");
            mdebug2("Syscheck query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return -1;
        }

        checksum = next;

        if (next = strchr(checksum, ' '), !next) {
            mdebug1("Invalid Syscheck query syntax.");
            mdebug2("Syscheck query: %s", checksum);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", checksum);
            return -1;
        }

        *next++ = '\0';

        if (result = wdb_syscheck_save(wdb, ftype, checksum, next), result < 0) {
            mdebug1("Cannot save Syscheck.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid Syscheck query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_osinfo (wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * hostname;
    char * architecture;
    char * os_name;
    char * os_version;
    char * os_codename;
    char * os_major;
    char * os_minor;
    char * os_build;
    char * os_platform;
    char * sysname;
    char * release;
    char * version;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid OS info query syntax.");
        mdebug2("OS info query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", scan_time);
            return -1;
        }

        hostname = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(hostname, "NULL"))
            hostname = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", hostname);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", hostname);
            return -1;
        }

        architecture = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(architecture, "NULL"))
            architecture = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", architecture);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", architecture);
            return -1;
        }

        os_name = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_name, "NULL"))
            os_name = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_name);
            return -1;
        }

        os_version = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_version, "NULL"))
            os_version = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_version);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_version);
            return -1;
        }

        os_codename = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_codename, "NULL"))
            os_codename = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_codename);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_codename);
            return -1;
        }

        os_major = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_major, "NULL"))
            os_major = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_major);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_major);
            return -1;
        }

        os_minor = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_minor, "NULL"))
            os_minor = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_minor);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_minor);
            return -1;
        }

        os_build = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_build, "NULL"))
            os_build = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_build);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_build);
            return -1;
        }

        os_platform = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(os_platform, "NULL"))
            os_platform = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_platform);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_platform);
            return -1;
        }

        sysname = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(sysname, "NULL"))
            sysname = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", sysname);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", sysname);
            return -1;
        }

        release = curr;
        *next++ = '\0';

        if (!strcmp(release, "NULL"))
            release = NULL;

        if (!strcmp(next, "NULL"))
            version = NULL;
        else
            version = next;

        if (result = wdb_osinfo_save(wdb, scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_build, os_platform, sysname, release, version), result < 0) {
            mdebug1("Cannot save OS information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save OS information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid OS info query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
        return -1;
    }
}
