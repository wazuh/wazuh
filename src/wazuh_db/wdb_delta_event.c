#include "wdb.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#define QUERY_MAX_SIZE OS_SIZE_2048

#define GT(X, Y) (X > Y ? true : false)
#define LT(X, Y) (X < Y ? true : false)
#define EQ(X, Y) (X == Y ? true : false)
#define GE(X, Y) (X >= Y ? true : false)
#define LE(X, Y) (X <= Y ? true : false)

const char * HWINFO_FIELDS[] = {
    "cpu_cores",
    "cpu_mhz",
    "ram_total",
    "ram_free",
    "ram_usage"
};

const char * GROUPINFO_FIELDS[] = {
    "group_id"
};

const char * USERINFO_FIELDS[] = {
    "user_id",
    "user_group_id",
    "user_created",
    "user_last_login",
    "user_auth_failed_count",
    "user_auth_failed_timestamp",
    "user_password_last_set_time",
    "user_password_expiration_date",
    "user_password_inactive_days",
    "user_password_last_change",
    "user_password_max_days_between_changes",
    "user_password_min_days_between_changes",
    "user_password_warning_days_before_expiration", 
    "process_pid"
};

#define IS_VALID_GROUPS_VALUE(field_name, field_value) ( \
    !strncmp(field_name, GROUPINFO_FIELDS[0], strlen(GROUPINFO_FIELDS[0])) ? \
        GE(field_value, 0) : true \
)

#define IS_VALID_HWINFO_VALUE(field_name, field_value) ( \
    !strncmp(field_name, HWINFO_FIELDS[0], strlen(HWINFO_FIELDS[0])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, HWINFO_FIELDS[1], strlen(HWINFO_FIELDS[1])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, HWINFO_FIELDS[2], strlen(HWINFO_FIELDS[2])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, HWINFO_FIELDS[3], strlen(HWINFO_FIELDS[3])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, HWINFO_FIELDS[4], strlen(HWINFO_FIELDS[4])) ? \
        (GT(field_value, 0) && (LE(field_value, 100))): true \
)

#define IS_VALID_USERS_VALUE(field_name, field_value) ( \
    !strncmp(field_name, USERINFO_FIELDS[0], strlen(USERINFO_FIELDS[0])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[1], strlen(USERINFO_FIELDS[1])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[2], strlen(USERINFO_FIELDS[1])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[3], strlen(USERINFO_FIELDS[3])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[4], strlen(USERINFO_FIELDS[4])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[5], strlen(USERINFO_FIELDS[5])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[6], strlen(USERINFO_FIELDS[6])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[7], strlen(USERINFO_FIELDS[7])) ? \
        GT(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[8], strlen(USERINFO_FIELDS[8])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[9], strlen(USERINFO_FIELDS[9])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[10], strlen(USERINFO_FIELDS[10])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[11], strlen(USERINFO_FIELDS[11])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[12], strlen(USERINFO_FIELDS[12])) ? \
        GE(field_value, 0) : \
    !strncmp(field_name, USERINFO_FIELDS[13], strlen(USERINFO_FIELDS[13])) ? \
        GE(field_value, 0) : true \
)

#define IS_VALID_VALUE(table_name, field_name, field_value) (\
    !strncmp(table_name, "sys_hwinfo", 10) ? IS_VALID_HWINFO_VALUE(field_name, field_value) : \
    !strncmp(table_name, "sys_users", 9) ? IS_VALID_USERS_VALUE(field_name, field_value) : \
    !strncmp(table_name, "sys_groups", 10) ? IS_VALID_GROUPS_VALUE(field_name, field_value) : true \
)

STATIC bool wdb_dbsync_stmt_bind_from_json(sqlite3_stmt * stmt, int index, field_type_t type, const cJSON * value, const char * field_name,
                                           const char * table_name, bool convert_empty_string_as_null);

STATIC const char * wdb_dbsync_translate_field(const struct field * field) {
    return NULL == field->source_name ? field->target_name : field->source_name;
}

STATIC cJSON * wdb_dbsync_get_field_default(const struct field * field) {

    cJSON * retval = NULL;

    if (NULL != field) {
        switch (field->type) {
        case FIELD_INTEGER:
            retval = cJSON_CreateNumber(field->default_value.integer);
            break;
        case FIELD_TEXT:
            retval = cJSON_CreateString(field->default_value.text);
            break;
        case FIELD_INTEGER_LONG:
            retval = cJSON_CreateNumber(field->default_value.integer_long);
            break;
        case FIELD_REAL:
            retval = cJSON_CreateNumber(field->default_value.real);
            break;
        default:
            mdebug2("Invalid syscollector field type: %i", field->type);
            break;
        }
    }

    return retval;
}

bool wdb_upsert_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data) {
    bool ret_val = false;
    if (NULL != data && NULL != wdb && NULL != kv_value) {
        char query[QUERY_MAX_SIZE] = {0};
        int query_actual_size = 0;

        query_actual_size += snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1,
                                      "INSERT INTO %s VALUES( ", kv_value->value);

        struct column_list const * column = NULL;
        for (column = kv_value->column_list; column; column = column->next) {
            query_actual_size += snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1, "?");
            if (column->next) {
                query_actual_size += snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1, ",");
            }
        }

        query_actual_size +=
            snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1, ") ON CONFLICT DO UPDATE SET ");

        bool first_condition_element = true;
        for (column = kv_value->column_list; column; column = column->next) {
            const char * field_name = column->value.target_name;
            if (!column->value.is_aux_field && !column->value.is_pk) {
                if (first_condition_element) {
                    query_actual_size +=
                        snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1, "%s=?", field_name);
                    first_condition_element = false;
                } else {
                    query_actual_size +=
                        snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1, ",%s=?", field_name);
                }
            }
        }

        sqlite3_stmt * stmt = wdb_get_cache_stmt(wdb, query);
        bool has_error = false;
        if (NULL != stmt) {
            int index = 1;
            for (column = kv_value->column_list; column && !has_error; column = column->next) {
                bool is_default = false;
                cJSON * field_value = NULL;

                const char * field_name = wdb_dbsync_translate_field(&column->value);

                if (column->value.is_aux_field) {
                    field_value = wdb_dbsync_get_field_default(&column->value);
                    is_default = true;
                } else {
                    field_value = cJSON_GetObjectItem(data, field_name);
                    if (NULL == field_value || (NULL != field_value && cJSON_NULL == field_value->type)) {
                        field_value = wdb_dbsync_get_field_default(&column->value);
                        is_default = true;
                    }
                }

                if (NULL != field_value) {
                    if (!wdb_dbsync_stmt_bind_from_json(stmt, index, column->value.type, field_value, field_name,
                                                        kv_value->value, column->value.convert_empty_string_as_null)) {
                        merror(DB_INVALID_DELTA_MSG, wdb->id, field_name, kv_value->key);
                        has_error = true;
                    }
                    ++index;
                    if (is_default) {
                        cJSON_Delete(field_value);
                    }
                }
            }
            for (column = kv_value->column_list; column && !has_error; column = column->next) {
                if (!column->value.is_aux_field && !column->value.is_pk) {
                    const char * field_name = wdb_dbsync_translate_field(&column->value);
                    cJSON * field_value = cJSON_GetObjectItem(data, field_name);
                    if (NULL != field_value &&
                        !wdb_dbsync_stmt_bind_from_json(stmt, index, column->value.type, field_value, field_name,
                                                        kv_value->value, column->value.convert_empty_string_as_null)) {
                        merror(DB_INVALID_DELTA_MSG, wdb->id, field_name, kv_value->key);
                        has_error = true;
                    }
                    ++index;
                }
            }
            ret_val = !has_error && SQLITE_DONE == wdb_step(stmt);
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
    }
    return ret_val;
}

bool wdb_delete_dbsync(wdb_t * wdb, struct kv const * kv_value, cJSON * data) {
    bool ret_val = false;
    if (NULL != wdb && NULL != kv_value && NULL != data) {
        char query[OS_SIZE_2048] = {0};
        int query_actual_size = 0;

        query_actual_size += snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1,
                                      "DELETE FROM %s WHERE ", kv_value->value);

        bool first_condition_element = true;
        struct column_list const * column = NULL;

        for (column = kv_value->column_list; column; column = column->next) {
            const char * field_name = column->value.target_name;
            if (column->value.is_pk) {
                if (first_condition_element) {
                    query_actual_size +=
                        snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1, "%s=?", field_name);
                    first_condition_element = false;
                } else {
                    query_actual_size += snprintf(query + query_actual_size, QUERY_MAX_SIZE - query_actual_size - 1,
                                                  " AND %s=?", field_name);
                }
            }
        }

        sqlite3_stmt * stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            struct column_list const * column = NULL;
            bool has_error = false;
            int index = 1;
            for (column = kv_value->column_list; column && !has_error; column = column->next) {
                bool is_default = false;
                if (column->value.is_pk) {
                    const char * field_name = wdb_dbsync_translate_field(&column->value);
                    cJSON * field_value = cJSON_GetObjectItem(data, field_name);
                    if (NULL == field_value || (NULL != field_value && cJSON_NULL == field_value->type)) {
                        field_value = wdb_dbsync_get_field_default(&column->value);
                        is_default = true;
                    }
                    if (!wdb_dbsync_stmt_bind_from_json(stmt, index, column->value.type, field_value, field_name,
                                                        kv_value->value, column->value.convert_empty_string_as_null)) {
                        merror(DB_INVALID_DELTA_MSG, wdb->id, field_name, kv_value->key);
                        has_error = true;
                    }
                    ++index;
                    if (is_default) {
                        cJSON_Delete(field_value);
                    }
                }
            }
            ret_val = !has_error && SQLITE_DONE == wdb_step(stmt);
        } else {
            merror(DB_CACHE_NULL_STMT);
        }
    }
    return ret_val;
}

STATIC bool wdb_dbsync_stmt_bind_from_json(sqlite3_stmt * stmt, int index, field_type_t type, const cJSON * value, const char * field_name,
                                           const char * table_name, bool convert_empty_string_as_null) {

    bool ret_val = false;

    if (NULL != stmt && NULL != value) {
        if (cJSON_NULL == value->type) {
            ret_val = sqlite3_bind_null(stmt, index) == SQLITE_OK ? true : false;
        } else {
            switch (type) {
            case FIELD_TEXT: {
                switch (value->type) {
                case cJSON_String:
                    if ('\0' == *value->valuestring && convert_empty_string_as_null) {
                        ret_val = sqlite3_bind_null(stmt, index) == SQLITE_OK ? true : false;
                    } else if (SQLITE_OK == sqlite3_bind_text(stmt, index, value->valuestring, -1, SQLITE_TRANSIENT)) {
                        ret_val = true;
                    }
                    break;
                case cJSON_Number: {
                    char text[OS_SIZE_1024] = {0};
                    if ((double) value->valueint == value->valuedouble) {
                        snprintf(text, OS_SIZE_1024, "%d", value->valueint);
                    } else {
                        snprintf(text, OS_SIZE_1024, "%f", value->valuedouble);
                    }
                    if (SQLITE_OK == sqlite3_bind_text(stmt, index, text, -1, SQLITE_TRANSIENT)) {
                        ret_val = true;
                    }
                    break;
                }
                }
            } break;
            case FIELD_INTEGER:
                switch (value->type) {
                case cJSON_String: {
                    char * endptr;
                    const int integer_number = (int) strtol(value->valuestring, &endptr, 10);
                    int sqlite3_bind = SQLITE_ERROR;
                    if (NULL != endptr && '\0' == *endptr) {
                        if (IS_VALID_VALUE(table_name, field_name, integer_number)) {
                            sqlite3_bind = sqlite3_bind_int(stmt, index, integer_number);
                        } else {
                            sqlite3_bind = sqlite3_bind_null(stmt, index);
                        }
                    }

                    if (SQLITE_OK == sqlite3_bind) {
                        ret_val = true;
                    }

                    break;
                }
                case cJSON_Number: {
                    int sqlite3_bind = SQLITE_ERROR;
                    if (IS_VALID_VALUE(table_name, field_name, value->valueint)) {
                        sqlite3_bind = sqlite3_bind_int(stmt, index, value->valueint);
                    } else {
                        sqlite3_bind = sqlite3_bind_null(stmt, index);
                    }

                    if (SQLITE_OK == sqlite3_bind) {
                        ret_val = true;
                    }
                    break;
                }
                }
                break;
            case FIELD_REAL:
                switch (value->type) {
                case cJSON_String: {
                    char * endptr;
                    const double real_value = strtod(value->valuestring, &endptr);
                    int sqlite3_bind = SQLITE_ERROR;
                    if (NULL != endptr && '\0' == *endptr) {
                        if (IS_VALID_VALUE(table_name, field_name, real_value)) {
                            sqlite3_bind = sqlite3_bind_double(stmt, index, real_value);
                        } else {
                            sqlite3_bind = sqlite3_bind_null(stmt, index);
                        }
                    }

                    if (SQLITE_OK == sqlite3_bind) {
                        ret_val = true;
                    }
                    break;
                }
                case cJSON_Number: {
                    int sqlite3_bind = SQLITE_ERROR;
                    if (IS_VALID_VALUE(table_name, field_name, value->valuedouble)) {
                        sqlite3_bind = sqlite3_bind_double(stmt, index, value->valuedouble);
                    } else {
                        sqlite3_bind = sqlite3_bind_null(stmt, index);
                    }
                    if (SQLITE_OK == sqlite3_bind) {
                        ret_val = true;
                    }
                    break;
                }
                }
                break;
            case FIELD_INTEGER_LONG:
                switch (value->type) {
                case cJSON_String: {
                    char * endptr;
                    const long long long_value = strtoll(value->valuestring, &endptr, 10);
                    int sqlite3_bind = SQLITE_ERROR;
                    if (NULL != endptr && '\0' == *endptr) {
                        if (IS_VALID_VALUE(table_name, field_name, long_value)) {
                            sqlite3_bind = sqlite3_bind_int64(stmt, index, (sqlite3_int64) long_value);
                        } else {
                            sqlite3_bind = sqlite3_bind_null(stmt, index);
                        }

                        if (SQLITE_OK == sqlite3_bind) {
                            ret_val = true;
                        }
                    }
                    break;
                }
                case cJSON_Number: {
                    int sqlite3_bind = SQLITE_ERROR;
                    if (IS_VALID_VALUE(table_name, field_name, value->valuedouble)) {
                        sqlite3_bind = sqlite3_bind_int64(stmt, index, (sqlite3_int64) value->valuedouble);
                    } else {
                        sqlite3_bind = sqlite3_bind_null(stmt, index);
                    }

                    if (SQLITE_OK == sqlite3_bind) {
                        ret_val = true;
                    }
                    break;
                }
                }
                break;
            }
        }
    }

    return ret_val;
}
