#include "wdb.h"


#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

STATIC bool wdb_dbsync_stmt_bind_from_string(sqlite3_stmt * stmt, int index, field_type_t type, const char * value,
                                             const char ** replace);

bool wdb_single_row_insert_dbsync(wdb_t * wdb, struct kv const *kv_value, const char *data) {
    bool ret_val = false;
    if (NULL != kv_value) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "DELETE FROM ");
        strcat(query, kv_value->value);
        strcat(query, ";");
        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            ret_val = SQLITE_DONE == wdb_step(stmt);
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
        ret_val = ret_val && wdb_insert_dbsync(wdb, kv_value, data);
    }
    return ret_val;
}

bool wdb_insert_dbsync(wdb_t * wdb, struct kv const *kv_value, const char *data) {
    bool ret_val = false;
    const char * treat_as_null[] = {"NULL", "", NULL};
    if (NULL != data && NULL != wdb && NULL != kv_value) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "INSERT INTO ");
        strcat(query, kv_value->value);
        strcat(query, " VALUES (");
        struct column_list const *column = NULL;

        for (column = kv_value->column_list; column ; column=column->next) {
            strcat(query, "?");
            if (column->next) {
                strcat(query, ",");
            }
        }
        strcat(query, ");");

        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);
        bool has_error = false;
        if (NULL != stmt) {
            char * data_temp = NULL;
            os_strdup(data, data_temp);
            char * curr = data_temp;
            char *next = strchr(curr, *FIELD_SEPARATOR_DBSYNC);
            for (column = kv_value->column_list; column ; column=column->next) {
                if (column->value.is_old_implementation) {
                    const char * defaults[] = {[FIELD_TEXT] = "", [FIELD_INTEGER] = "0", [FIELD_REAL] = "0", [FIELD_INTEGER_LONG] = "0"};
                    if (!wdb_dbsync_stmt_bind_from_string(stmt, column->value.index, column->value.type, defaults[column->value.type], NULL)) {
                        merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                        has_error = true;
                    }
                } else {
                    if (NULL != next) {
                        *next++ = '\0';
                        if (!wdb_dbsync_stmt_bind_from_string(stmt, column->value.index, column->value.type, curr, treat_as_null)) {
                            merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                            has_error = true;
                        }
                        if (column->next) {
                            curr = next;
                            next = strchr(curr, *FIELD_SEPARATOR_DBSYNC);
                        }
                    }
                }
            }

            ret_val = !has_error && SQLITE_DONE == wdb_step(stmt);
            os_free(data_temp);
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
    }
    return ret_val;
}

bool wdb_modify_dbsync(wdb_t * wdb, struct kv const *kv_value, const char *data)
{
    const char * treat_as_null[] = {"", NULL};
    bool ret_val = false;
    if (NULL != data && NULL != wdb && NULL != kv_value) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "UPDATE ");
        strcat(query, kv_value->value);
        strcat(query, " SET ");

        const size_t separator_count = os_strcnt(data, *FIELD_SEPARATOR_DBSYNC);
        const size_t field_values_size = sizeof(char *) * (separator_count > 0 ? separator_count : 1);
        // field_values vector will be used to point to the beginning of each field.
        char ** field_values = NULL;
        os_calloc(1, field_values_size + sizeof(char *), field_values);
        char **curr = field_values;

        char * data_temp = NULL;
        os_strdup(data, data_temp);
        *curr = data_temp;

        char *curr_data = data_temp;
        char *next = strchr(curr_data, *FIELD_SEPARATOR_DBSYNC);
        // This loop replace '|' with '\0' and assign the beggining of each string to field_values vector.
        while (NULL != next) {
            *curr = curr_data;
            *next++ = '\0';

            curr_data = next;
            next = strchr(curr_data, *FIELD_SEPARATOR_DBSYNC);
            ++curr;
        }

        bool first_condition_element = true;
        curr = field_values;
        struct column_list const *column = NULL;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (!column->value.is_old_implementation && curr && NULL != *curr) {
                if (!column->value.is_pk && strcmp(*curr, "NULL") != 0) {
                    if (first_condition_element) {
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                        first_condition_element = false;
                    } else {
                        strcat(query, ",");
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                    }
                }
                ++curr;
            }
        }
        strcat(query, " WHERE ");

        first_condition_element = true;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (column->value.is_pk && !column->value.is_old_implementation) {
                if (first_condition_element) {
                    strcat(query, column->value.name);
                    strcat(query, "=?");
                    first_condition_element = false;
                } else {
                    strcat(query, " AND ");
                    strcat(query, column->value.name);
                    strcat(query, "=?");
                }
            }
        }
        strcat(query, ";");

        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);
        bool has_error = false;
        if (NULL != stmt) {
            int index = 1;

            curr = field_values;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation && curr && NULL != *curr) {
                    if (!column->value.is_pk && strcmp(*curr, "NULL") != 0) {
                        if (!wdb_dbsync_stmt_bind_from_string(stmt, index, column->value.type, *curr, treat_as_null)) {
                            merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                            has_error = true;
                        }
                        ++index;
                    }
                    ++curr;
                }
            }

            curr = field_values;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation && curr && NULL != *curr) {
                    if (column->value.is_pk && strcmp(*curr, "NULL") != 0) {
                        if (!wdb_dbsync_stmt_bind_from_string(stmt, index, column->value.type, *curr, NULL)) {
                            merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                            has_error = true;
                        }
                        ++index;
                    }
                    ++curr;
                }
            }
            ret_val = !has_error && SQLITE_DONE == wdb_step(stmt) && sqlite3_changes(wdb->db) > 0;
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
        os_free(data_temp);
        os_free(field_values);
    }
    return ret_val;
}

bool wdb_delete_dbsync(wdb_t * wdb, struct kv const *kv_value, const char *data)
{
    bool ret_val = false;
    if (NULL != wdb && NULL != kv_value && NULL != data) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "DELETE FROM ");
        strcat(query, kv_value->value);
        strcat(query, " WHERE ");

        bool first_condition_element = true;
        struct column_list const *column = NULL;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (!column->value.is_old_implementation) {
                if (column->value.is_pk) {
                    if (first_condition_element) {
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                        first_condition_element = false;
                    } else {
                        strcat(query, " AND ");
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                    }
                }
            }
        }
        strcat(query, ";");

        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            char *data_temp = NULL;
            os_strdup(data, data_temp);

            char * curr = data_temp;
            char *next = strchr(curr, *FIELD_SEPARATOR_DBSYNC);

            struct column_list const *column = NULL;
            int index = 1;
            bool has_error = false;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation) {
                    if (NULL != next) {
                        *next++ = '\0';
                        if (column->value.is_pk) {
                            if (!wdb_dbsync_stmt_bind_from_string(stmt, index, column->value.type, curr, NULL)){
                                merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                                has_error = true;
                            }
                            ++index;
                        }
                        if (column->next) {
                            curr = next;
                            next = strchr(curr, *FIELD_SEPARATOR_DBSYNC);
                        }
                    }
                }
            }
            ret_val = !has_error && SQLITE_DONE == wdb_step(stmt) && sqlite3_changes(wdb->db) > 0;
            os_free(data_temp);
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
    }
    return ret_val;
}


void wdb_select_dbsync(wdb_t * wdb, struct kv const *kv_value, const char *data, char *output)
{
    if (NULL != wdb && NULL != data) {
        char query[OS_SIZE_2048] = { 0 };
        bool first_condition_element = true;
        struct column_list const *column = NULL;

        strcat(query, "SELECT ");
        for (column = kv_value->column_list; column ; column=column->next) {
            if (!column->value.is_old_implementation) {
                if (first_condition_element) {
                    first_condition_element = false;
                } else {
                    strcat(query, ", ");
                }
                strcat(query, column->value.name);
            }
        }
        strcat(query, " FROM ");
        strcat(query, kv_value->value);
        strcat(query, " WHERE ");

        first_condition_element = true;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (!column->value.is_old_implementation) {
                if (column->value.is_pk) {
                    if (first_condition_element) {
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                        first_condition_element = false;
                    } else {
                        strcat(query, " AND ");
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                    }
                }
            }
        }
        strcat(query, ";");
        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            char * data_temp = NULL;
            os_strdup(data, data_temp);
            char * curr = data_temp;
            char *next = strchr(curr, *FIELD_SEPARATOR_DBSYNC);

            struct column_list const *column = NULL;
            int index = 1;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation) {
                    if (NULL != next) {
                        *next++ = '\0';
                        if (column->value.is_pk) {
                            if (!wdb_dbsync_stmt_bind_from_string(stmt, index, column->value.type, curr, NULL)){
                                merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                            }
                            ++index;
                        }
                        if (column->next) {
                            curr = next;
                            next = strchr(curr, *FIELD_SEPARATOR_DBSYNC);
                        }
                    }
                }
            }
            index = 0;
            int len = strlen(output);
            switch (wdb_step(stmt)) {
            case SQLITE_ROW:
                for (column = kv_value->column_list; column; column = column->next) {
                    if (!column->value.is_old_implementation) {
                        char * value = wstr_replace((char *) sqlite3_column_text(stmt, index), FIELD_SEPARATOR_DBSYNC,
                                                    FIELD_SEPARATOR_DBSYNC_ESCAPE);
                        if (NULL != value) {
                            len += snprintf(output + len, OS_SIZE_6144 - len - WDB_RESPONSE_OK_SIZE - 1, "%s", value);
                            os_free(value);
                        }
                        len += snprintf(output + len, OS_SIZE_6144 - len - WDB_RESPONSE_OK_SIZE - 1,
                                        FIELD_SEPARATOR_DBSYNC);
                        ++index;
                    }
                }
                break;
            case SQLITE_DONE:
                break;
            default:
                merror(DB_AGENT_SQL_ERROR, wdb->id, sqlite3_errmsg(wdb->db));
                break;
            }

            os_free(data_temp);
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
    }
}

STATIC bool wdb_dbsync_stmt_bind_from_string(sqlite3_stmt * stmt, int index, field_type_t type, const char * value,
                                             const char ** replace) {

    bool ret_val = false;
    bool was_replaced = false;

    if (NULL != stmt && NULL != value) {

        if (NULL != replace && NULL !=  *replace) {
            const char ** current = replace;
            while (NULL != *current) {
                if (strcmp(value, *current) == 0) {
                    ret_val = sqlite3_bind_null(stmt, index) == SQLITE_OK ? true : false;
                    was_replaced = true;
                    break;
                }
                ++current;
            }
        }
        if (!was_replaced) {
            char * replaced_value_escape_null = wstr_replace(value, "_NULL_", "NULL");
            char * replaced_value_escape_pipe = wstr_replace(replaced_value_escape_null, FIELD_SEPARATOR_DBSYNC_ESCAPE,
                                                         FIELD_SEPARATOR_DBSYNC);
            os_free(replaced_value_escape_null);
            switch (type) {
            case FIELD_TEXT:
                if (SQLITE_OK == sqlite3_bind_text(stmt, index, replaced_value_escape_pipe, -1, SQLITE_TRANSIENT)) {
                    ret_val = true;
                }
                break;
            case FIELD_INTEGER: {
                char * endptr;
                const int integer_number = (int) strtol(replaced_value_escape_pipe, &endptr, 10);
                if (NULL != endptr && '\0' == *endptr && SQLITE_OK == sqlite3_bind_int(stmt, index, integer_number)) {
                    ret_val = true;
                }
                break;
            }
            case FIELD_REAL: {
                char * endptr;
                const double real_value = strtod(replaced_value_escape_pipe, &endptr);
                if (NULL != endptr && '\0' == *endptr && SQLITE_OK == sqlite3_bind_double(stmt, index, real_value)) {
                    ret_val = true;
                }
                break;
            }
            case FIELD_INTEGER_LONG: {
                char * endptr ;
                const long long long_value = strtoll(replaced_value_escape_pipe, &endptr, 10);
                if (NULL != endptr && '\0' == *endptr && SQLITE_OK == sqlite3_bind_int64(stmt, index, (sqlite3_int64) long_value)) {
                    ret_val = true;
                }
                break;
            }
            }
            os_free(replaced_value_escape_pipe);
        }
    }

    return ret_val;
}
