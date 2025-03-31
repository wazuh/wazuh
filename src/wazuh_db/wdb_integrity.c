/**
 * @file wdb_integrity.c
 * @brief DB integrity synchronization library definition.
 * @date 2019-08-14
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cJSON.h"
#include "debug_op.h"
#include "os_err.h"
#include "wdb.h"
#include "os_crypto/sha1/sha1_op.h"
#include "pthreads_op.h"
#include "utils/flatbuffers/include/syscollector_deltas_schema.h"
#include "router.h"
#include <openssl/evp.h>
#include <stdarg.h>

static const char * COMPONENT_NAMES[] = {
    [WDB_FIM] = "fim",
    [WDB_FIM_FILE] = "fim_file",
    [WDB_FIM_REGISTRY] = "fim_registry",
    [WDB_FIM_REGISTRY_KEY] = "fim_registry_key",
    [WDB_FIM_REGISTRY_VALUE] = "fim_registry_value",
    [WDB_SYSCOLLECTOR_PROCESSES] = "syscollector-processes",
    [WDB_SYSCOLLECTOR_PACKAGES] = "syscollector-packages",
    [WDB_SYSCOLLECTOR_HOTFIXES] = "syscollector-hotfixes",
    [WDB_SYSCOLLECTOR_PORTS] = "syscollector-ports",
    [WDB_SYSCOLLECTOR_NETPROTO] = "syscollector-netproto",
    [WDB_SYSCOLLECTOR_NETADDRESS] = "syscollector-netaddress",
    [WDB_SYSCOLLECTOR_NETINFO] = "syscollector-netinfo",
    [WDB_SYSCOLLECTOR_HWINFO] = "syscollector-hwinfo",
    [WDB_SYSCOLLECTOR_OSINFO] = "syscollector-osinfo",
    [WDB_GENERIC_COMPONENT] = ""
};

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

os_sha1 global_group_hash;

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

void wdbi_report_removed(const char* agent_id, wdb_component_t component, sqlite3_stmt* stmt) {
    if (!router_fim_events_handle || !router_inventory_events_handle) {
        mdebug2("Router handle not available.");
        return;
    }

    cJSON* j_msg_to_send = NULL;
    cJSON* j_agent_info = NULL;
    cJSON* j_data = NULL;
    char* msg_to_send = NULL;
    int result = SQLITE_ERROR;

    do{
        ROUTER_PROVIDER_HANDLE router_handle = NULL;
        j_msg_to_send = cJSON_CreateObject();
        j_agent_info = cJSON_CreateObject();
        j_data = cJSON_CreateObject();

        cJSON_AddStringToObject(j_agent_info, "agent_id", agent_id);
        cJSON_AddItemToObject(j_msg_to_send, "agent_info", j_agent_info);

        switch (component)
        {
            case WDB_SYSCOLLECTOR_HOTFIXES:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteHotfix");
                cJSON_AddItemToObject(j_data, "hotfix", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_inventory_events_handle;
                break;
            case WDB_SYSCOLLECTOR_PACKAGES:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deletePackage");
                cJSON_AddItemToObject(j_data, "name", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                cJSON_AddItemToObject(j_data, "version", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 1)));
                cJSON_AddItemToObject(j_data, "architecture", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 2)));
                cJSON_AddItemToObject(j_data, "format", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 3)));
                cJSON_AddItemToObject(j_data, "location", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 4)));
                cJSON_AddItemToObject(j_data, "item_id", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 5)));
                router_handle = router_inventory_events_handle;
                break;
            case WDB_SYSCOLLECTOR_PROCESSES:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteProcess");
                cJSON_AddItemToObject(j_data, "pid", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_inventory_events_handle;
                break;
            case WDB_SYSCOLLECTOR_PORTS:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deletePort");
                cJSON_AddItemToObject(j_data, "protocol", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                cJSON_AddItemToObject(j_data, "local_ip", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 1)));
                cJSON_AddItemToObject(j_data, "local_port", cJSON_CreateNumber(sqlite3_column_int64(stmt, 2)));
                cJSON_AddItemToObject(j_data, "inode", cJSON_CreateNumber(sqlite3_column_int64(stmt, 3)));
                cJSON_AddItemToObject(j_data, "item_id", cJSON_CreateString(sqlite3_column_text(stmt, 4)));
                router_handle = router_inventory_events_handle;
                break;
<<<<<<< HEAD
            case WDB_SYSCOLLECTOR_HWINFO:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteHardware");
                cJSON_AddItemToObject(j_data, "board_serial", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_inventory_events_handle;
                break;
            case WDB_SYSCOLLECTOR_NETPROTO:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteNetProto");
                cJSON_AddItemToObject(j_data, "item_id", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_inventory_events_handle;
                break;
            case WDB_SYSCOLLECTOR_NETINFO:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteNetIface");
                cJSON_AddItemToObject(j_data, "item_id", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_inventory_events_handle;
                break;
=======
>>>>>>> d7a5890497 (change(ih): Rebase and improvement of documentation and code name)
            case WDB_SYSCOLLECTOR_NETADDRESS:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteNetworkAddress");
                cJSON_AddItemToObject(j_data, "item_id", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_inventory_events_handle;
                break;
            case WDB_FIM:
            case WDB_FIM_FILE:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteFile");
                cJSON_AddItemToObject(j_data, "path", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_fim_events_handle;
                break;
            case WDB_FIM_REGISTRY:
                {
                    const char *type = (const char*) sqlite3_column_text(stmt, 2);
                    if (type && strcmp(type, "registry_key") == 0) {
                        cJSON_AddStringToObject(j_msg_to_send, "action", "deleteRegistryKey");
                    } else {
                        cJSON_AddStringToObject(j_msg_to_send, "action", "deleteRegistryValue");
                        cJSON_AddItemToObject(j_data, "value_name", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 1)));
                    }
                    cJSON_AddItemToObject(j_data, "path", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                    router_handle = router_fim_events_handle;
                }
                break;
            case WDB_FIM_REGISTRY_KEY:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteRegistryKey");
                cJSON_AddItemToObject(j_data, "path", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                router_handle = router_fim_events_handle;
                break;

            case WDB_FIM_REGISTRY_VALUE:
                cJSON_AddStringToObject(j_msg_to_send, "action", "deleteRegistryValue");
                cJSON_AddItemToObject(j_data, "path", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 0)));
                cJSON_AddItemToObject(j_data, "value_name", cJSON_CreateString((const char*) sqlite3_column_text(stmt, 1)));
                router_handle = router_fim_events_handle;
                break;
            default:
                break;
        }

        cJSON_AddItemToObject(j_msg_to_send, "data", j_data);

        msg_to_send = cJSON_PrintUnformatted(j_msg_to_send);

        if (msg_to_send) {
            if (router_handle) {
                router_provider_send(router_handle, msg_to_send, strlen(msg_to_send));
            } else {
                merror("Invalid handle to send delete message. Agent %s", agent_id);
            }
        } else {
            mdebug2("Unable to dump delete message to publish. Agent %s", agent_id);
        }

        cJSON_Delete(j_msg_to_send);
        cJSON_free(msg_to_send);

        result = wdb_step(stmt);
    } while(result == SQLITE_ROW);
}

void wdbi_remove_by_pk(wdb_t *wdb, wdb_component_t component, const char *pk_value) {
    assert(wdb != NULL);

    if (!pk_value) {
        mwarn("PK value is NULL during the removal of the component '%s'", COMPONENT_NAMES[component]);
        return;
    }
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_BY_PK,
                            [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_DELETE_BY_PK,
                            [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_BY_PK,
                            [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_BY_PK };

    assert(component < sizeof(INDEXES) / sizeof(int));

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, INDEXES[component]) == OS_INVALID) {
        mdebug1("Cannot cache statement");
        return;
    }

    sqlite3_stmt *stmt = wdb->stmt[INDEXES[component]];

    if (sqlite3_bind_text(stmt, 1, pk_value, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return;
    }

    int result = wdb_step(stmt);

    if (result == SQLITE_ROW) {
        wdbi_report_removed(wdb->id, component, stmt);
    } else if (result != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

/**
 * @brief Run checksum of the whole result of an already prepared statement
 *
 * @param[in] wdb Database node.
 * @param[in] stmt Statement to be executed already prepared.
 * @param[in] component Name of the component.
 * @param[out] hexdigest
 * @param[in] pk_value Primary key value.
 * @retval 1 On success.
 * @retval 0 If no items were found.
 */
int wdb_calculate_stmt_checksum(wdb_t * wdb, sqlite3_stmt * stmt, wdb_component_t component, os_sha1 hexdigest, const char * pk_value) {
    assert(wdb != NULL);
    assert(stmt != NULL);
    assert(hexdigest != NULL);

    int step = wdb_step(stmt);

    if (step != SQLITE_ROW) {
        return 0;
    }

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    size_t row_count = 0;
    for (; step == SQLITE_ROW; step = wdb_step(stmt)) {
        ++row_count;

        char * checksum = (char *)sqlite3_column_text(stmt, 0);

        if (checksum == NULL) {
            mdebug1("DB(%s) has a NULL %s checksum.", wdb->id, COMPONENT_NAMES[component]);
            continue;
        }

        EVP_DigestUpdate(ctx, checksum, strlen((const char *)checksum));
    }

    // Get the hex SHA-1 digest
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);

    if (pk_value && row_count > 1) {
        mwarn("DB(%s) %s component has more than one element with the same PK value '%s'.",
              wdb->id,
              COMPONENT_NAMES[component],
              pk_value);
        wdbi_remove_by_pk(wdb, component, pk_value);
    } else {
        OS_SHA1_Hexdigest(digest, hexdigest);
    }

    return 1;
}

/**
 * @brief Run checksum of a database table
 *
 * @param[in] wdb Database node.
 * @param[in] component Name of the component.
 * @param[out] hexdigest
 * @retval 1 On success.
 * @retval 0 If no items were found.
 * @retval -1 On error.
 */
int wdbi_checksum(wdb_t * wdb, wdb_component_t component, os_sha1 hexdigest) {
    assert(wdb != NULL);
    assert(hexdigest != NULL);

    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_SELECT_CHECKSUM,
                            [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_SELECT_CHECKSUM,
                            [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM,
                            [WDB_FIM_REGISTRY_KEY] = WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM,
                            [WDB_FIM_REGISTRY_VALUE] = WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM,
                            [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM };

    assert(component < sizeof(INDEXES) / sizeof(int));

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        mdebug1("Cannot cache statement");
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];

    return wdb_calculate_stmt_checksum(wdb, stmt, component, hexdigest, NULL);
}

/**
 * @brief Run checksum of a database table range
 *
 * @param[in] wdb Database node.
 * @param[in] component Name of the component.
 * @param[in] begin First element.
 * @param[in] end Last element.
 * @param[out] hexdigest
 * @retval 1 On success.
 * @retval 0 If no items were found in that range.
 * @retval -1 On error.
 */
int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest) {
    assert(wdb != NULL);
    assert(hexdigest != NULL);

    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_SELECT_CHECKSUM_RANGE,
                            [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_SELECT_CHECKSUM_RANGE,
                            [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM_RANGE,
                            [WDB_FIM_REGISTRY_KEY] = WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM_RANGE,
                            [WDB_FIM_REGISTRY_VALUE] = WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM_RANGE };

    assert(component < sizeof(INDEXES) / sizeof(int));

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        mdebug1("Cannot cache statement");
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];
    sqlite3_bind_text(stmt, 1, begin, -1, NULL);
    sqlite3_bind_text(stmt, 2, end, -1, NULL);

    // If begin and end have the same value, a duplicity check will be performed.
    const char *unique_id = NULL;
    if (begin && end && !strcmp(begin, end)) {
        unique_id = begin;
    }

    return wdb_calculate_stmt_checksum(wdb, stmt, component, hexdigest, unique_id);
}

/**
 * @brief Delete old elements in a table
 *
 * This function shall delete every item in the corresponding table,
 * between end and tail (none of them included).
 *
 * Should tail be NULL, this function will delete every item from the first
 * element to 'begin' and from 'end' to the last element.
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param begin First valid element in the list.
 * @param end Last valid element. This is the previous element to the first item to delete.
 * @param tail Subsequent element to the last item to delete.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdbi_delete(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, const char * tail) {
    assert(wdb != NULL);

    const int INDEXES_AROUND[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_AROUND,
                                   [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_DELETE_AROUND,
                                   [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_DELETE_AROUND,
                                   [WDB_FIM_REGISTRY_KEY] = WDB_STMT_FIM_REGISTRY_KEY_DELETE_AROUND,
                                   [WDB_FIM_REGISTRY_VALUE] = WDB_STMT_FIM_REGISTRY_VALUE_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_AROUND };
    const int INDEXES_RANGE[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_RANGE,
                                  [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_DELETE_RANGE,
                                  [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_DELETE_RANGE,
                                  [WDB_FIM_REGISTRY_KEY] = WDB_STMT_FIM_REGISTRY_KEY_DELETE_RANGE,
                                  [WDB_FIM_REGISTRY_VALUE] = WDB_STMT_FIM_REGISTRY_VALUE_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_RANGE };

    assert(component < sizeof(INDEXES_AROUND) / sizeof(int));
    assert(component < sizeof(INDEXES_RANGE) / sizeof(int));

    int index = tail ? INDEXES_RANGE[component] : INDEXES_AROUND[component];

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, index) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[index];

    if (tail) {
        sqlite3_bind_text(stmt, 1, end, -1, NULL);
        sqlite3_bind_text(stmt, 2, tail, -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 1, begin, -1, NULL);
        sqlite3_bind_text(stmt, 2, end, -1, NULL);
    }

    int result = wdb_step(stmt);

    if (result == SQLITE_ROW) {
        wdbi_report_removed(wdb->id, component, stmt);
    } else if (result != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

void wdbi_update_attempt(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 last_agent_checksum, os_sha1 manager_checksum, bool legacy) {
    assert(wdb != NULL);

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, legacy ? WDB_STMT_SYNC_UPDATE_ATTEMPT_LEGACY : WDB_STMT_SYNC_UPDATE_ATTEMPT) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[legacy ? WDB_STMT_SYNC_UPDATE_ATTEMPT_LEGACY : WDB_STMT_SYNC_UPDATE_ATTEMPT];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, last_agent_checksum, -1, NULL);
    sqlite3_bind_text(stmt, 3, manager_checksum, -1, NULL);
    sqlite3_bind_text(stmt, 4, COMPONENT_NAMES[component], -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

void wdbi_update_completion(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 last_agent_checksum, os_sha1 manager_checksum) {
    assert(wdb != NULL);

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_UPDATE_COMPLETION) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_UPDATE_COMPLETION];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_int64(stmt, 2, timestamp);
    sqlite3_bind_text(stmt, 3, last_agent_checksum, -1, NULL);
    sqlite3_bind_text(stmt, 4, manager_checksum, -1, NULL);
    sqlite3_bind_text(stmt, 5, COMPONENT_NAMES[component], -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

/**
 * @brief This method updates the "last_completion" value.
 *
 * It should be called after a positive checksum comparison to avoid repeated calculations.
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param timestamp Synchronization event timestamp.
 */
void wdbi_set_last_completion(wdb_t * wdb, wdb_component_t component, long timestamp) {
    assert(wdb != NULL);

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_SET_COMPLETION) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_SET_COMPLETION];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, COMPONENT_NAMES[component], -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

// Query the checksum of a data range
integrity_sync_status_t wdbi_query_checksum(wdb_t * wdb, wdb_component_t component, dbsync_msg action, const char * payload) {
    integrity_sync_status_t status = INTEGRITY_SYNC_ERR;

    // Parse payloadchecksum
    cJSON * data = cJSON_Parse(payload);
    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->id, payload);
        return -1;
    }
    cJSON * item = cJSON_GetObjectItem(data, "begin");
    char * begin = cJSON_GetStringValue(item);
    if (begin == NULL) {
        mdebug1("No such string 'begin' in JSON payload.");
        goto end;
    }
    item = cJSON_GetObjectItem(data, "end");
    char * end = cJSON_GetStringValue(item);
    if (end == NULL) {
        mdebug1("No such string 'end' in JSON payload.");
        goto end;
    }
    item = cJSON_GetObjectItem(data, "checksum");
    char * checksum = cJSON_GetStringValue(item);
    if (checksum == NULL) {
        mdebug1("No such string 'checksum' in JSON payload.");
        goto end;
    }
    item = cJSON_GetObjectItem(data, "id");
    if (!cJSON_IsNumber(item)) {
        mdebug1("No such string 'id' in JSON payload.");
        goto end;
    }
    long timestamp = item->valuedouble;

    os_sha1 manager_checksum = {0};
    // Get the previously computed manager checksum
    if (INTEGRITY_CHECK_GLOBAL == action) {
        if (OS_SUCCESS == wdbi_get_last_manager_checksum(wdb, component, manager_checksum) && 0 == strcmp(manager_checksum, checksum)) {
            mdebug2("Agent '%s' %s range checksum avoided.", wdb->id, COMPONENT_NAMES[component]);
            status = INTEGRITY_SYNC_CKS_OK;
        }
    }

    // Get the actual manager checksum
    if (status != INTEGRITY_SYNC_CKS_OK) {
        struct timespec ts_start, ts_end;
        gettime(&ts_start);
        switch (wdbi_checksum_range(wdb, component, begin, end, manager_checksum)) {
        case -1:
            goto end;

        case 0:
            status = INTEGRITY_SYNC_NO_DATA;
            break;

        case 1:
            gettime(&ts_end);
            mdebug2("Agent '%s' %s range checksum: Time: %.3f ms.", wdb->id, COMPONENT_NAMES[component], time_diff(&ts_start, &ts_end) * 1e3);
            status = strcmp(manager_checksum, checksum) ? INTEGRITY_SYNC_CKS_FAIL : INTEGRITY_SYNC_CKS_OK;
        }
    }

    // Update sync status
    if (INTEGRITY_CHECK_GLOBAL == action) {
        wdbi_delete(wdb, component, begin, end, NULL);
        switch (status) {
        case INTEGRITY_SYNC_NO_DATA:
        case INTEGRITY_SYNC_CKS_FAIL:
            wdbi_update_attempt(wdb, component, timestamp, checksum, "", FALSE);
            break;

        case INTEGRITY_SYNC_CKS_OK:
            wdbi_update_completion(wdb, component, timestamp, checksum, manager_checksum);
            break;

        default:
            break;
        }
    }
    else if (INTEGRITY_CHECK_LEFT == action) {
        item = cJSON_GetObjectItem(data, "tail");
        wdbi_delete(wdb, component, begin, end, cJSON_GetStringValue(item));
    }

end:
    cJSON_Delete(data);
    return status;
}

// Query a complete table clear
int wdbi_query_clear(wdb_t * wdb, wdb_component_t component, const char * payload) {
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_CLEAR,
                            [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_CLEAR,
                            [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_CLEAR,
                            [WDB_FIM_REGISTRY_KEY] = WDB_STMT_FIM_REGISTRY_KEY_CLEAR,
                            [WDB_FIM_REGISTRY_VALUE] = WDB_STMT_FIM_REGISTRY_VALUE_CLEAR,
                            [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_CLEAR,
                            [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_CLEAR,
                            [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_CLEAR,
                            [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_CLEAR,
                            [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_CLEAR,
                            [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_CLEAR,
                            [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_CLEAR,
                            [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_CLEAR,
                            [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_CLEAR };

    assert(component < sizeof(INDEXES) / sizeof(int));

    int retval = -1;
    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->id, payload);
        goto end;
    }

    cJSON * item = cJSON_GetObjectItem(data, "id");

    if (!cJSON_IsNumber(item)) {
        mdebug1("No such string 'id' in JSON payload.");
        goto end;
    }

    long timestamp = item->valuedouble;

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        goto end;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];

    if (wdb_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        goto end;
    }

    wdbi_update_completion(wdb, component, timestamp, "", "");
    retval = 0;

end:
    cJSON_Delete(data);
    return retval;
}

int wdbi_get_last_manager_checksum(wdb_t *wdb, wdb_component_t component, os_sha1 manager_checksum) {
    int result = OS_INVALID;

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_GET_INFO) == -1) {
        mdebug1("Cannot cache statement");
        return result;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_GET_INFO];
    sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);

    cJSON* j_sync_info = wdb_exec_stmt(stmt);
    if (!j_sync_info) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
        return result;
    }

    cJSON* j_last_checksum = cJSON_GetObjectItem(j_sync_info->child, "last_manager_checksum");
    if (cJSON_IsString(j_last_checksum)) {
        strncpy(manager_checksum, cJSON_GetStringValue(j_last_checksum), sizeof(os_sha1));
        result = OS_SUCCESS;
    }

    cJSON_Delete(j_sync_info);
    return result;
}

/**
 * @brief Returns the syncronization status of a component from sync_info table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] component An enumeration member that was previously added to the table.
 * @return Returns 0 if data is not ready, 1 if it is, or -1 on error.
 */
int wdbi_check_sync_status(wdb_t *wdb, wdb_component_t component) {
    cJSON* j_sync_info = NULL;
    int result = 0;

    if (wdb_begin2(wdb) == -1) {
        mdebug1("Cannot begin transaction");
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_GET_INFO) == -1) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_GET_INFO];
    sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);

    j_sync_info = wdb_exec_stmt(stmt);

    if (!j_sync_info) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    cJSON* j_last_attempt = cJSON_GetObjectItem(j_sync_info->child, "last_attempt");
    cJSON* j_last_completion = cJSON_GetObjectItem(j_sync_info->child, "last_completion");
    cJSON* j_checksum = cJSON_GetObjectItem(j_sync_info->child, "last_agent_checksum");

    if ( cJSON_IsNumber(j_last_attempt) && cJSON_IsNumber(j_last_completion) && cJSON_IsString(j_checksum)) {
        int last_attempt = j_last_attempt->valueint;
        int last_completion = j_last_completion->valueint;
        char *checksum = cJSON_GetStringValue(j_checksum);

        // Return 0 if there was not at least one successful syncronization or
        // if the syncronization is in progress or there was an error in the syncronization
        if (last_completion != 0 && last_attempt <= last_completion) {
            result = 1;
        }
        else if (checksum && strcmp("", checksum)) {
            // Verifying the integrity checksum
            os_sha1 hexdigest;

            switch (wdbi_checksum(wdb, component, hexdigest)) {
            case -1:
                result = OS_INVALID;
                break;

            case 0:
                result = 0;
                break;

            case 1:
                result = !strcmp(hexdigest, checksum);
                // Updating last_completion timestamp to avoid calculating the checksum again
                if (1 == result) {
                    wdbi_set_last_completion(wdb, component, (unsigned)time(NULL));
                }
            }
        }
    } else {
        mdebug1("Failed to get agent's sync status data");
        result = OS_INVALID;
    }

    cJSON_Delete(j_sync_info);
    return result;
}

int wdb_get_global_group_hash(wdb_t * wdb, os_sha1 hexdigest) {
    if (OS_SUCCESS == wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_READ, hexdigest)) {
        mdebug2("Using global group hash from cache");
        return OS_SUCCESS;
    } else {
        if(!wdb) {
            mdebug1("Database structure not initialized. Unable to calculate global group hash.");
            return OS_INVALID;
        }

        sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_HASH_GET);
        if (!stmt) {
            return OS_INVALID;
        }

        if(wdb_calculate_stmt_checksum(wdb, stmt, WDB_GENERIC_COMPONENT, hexdigest, NULL)) {
            wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_WRITE, hexdigest);
            mdebug2("New global group hash calculated and stored in cache.");
            return OS_SUCCESS;
        } else {
            hexdigest[0] = 0;
            mdebug2("No group hash was found to calculate the global group hash.");
            return OS_SUCCESS;
        }
    }
}

int wdb_global_group_hash_cache(wdb_global_group_hash_operations_t operation, os_sha1 hexdigest) {
    #ifndef WAZUH_UNIT_TESTING
        static os_sha1 global_group_hash = {0};
    #endif

    if (WDB_GLOBAL_GROUP_HASH_READ == operation) {
        if (global_group_hash[0] == 0) {
            return OS_INVALID;
        } else {
            memcpy(hexdigest, global_group_hash, sizeof(os_sha1));
            return OS_SUCCESS;
        }
    } else if (WDB_GLOBAL_GROUP_HASH_WRITE == operation) {
        memcpy(global_group_hash, hexdigest, sizeof(os_sha1));
        return OS_SUCCESS;
    } else if (WDB_GLOBAL_GROUP_HASH_CLEAR == operation) {
        global_group_hash[0] = 0;
        return OS_SUCCESS;
    } else {
        mdebug2("Invalid mode for global group hash operation.");
        return OS_INVALID;
    }
}
