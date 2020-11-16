/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 12, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "integrity_op.h"

#ifdef WAZUH_UNIT_TESTING
/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

const char * INTEGRITY_COMMANDS[] = {
    [INTEGRITY_CHECK_LEFT] = "integrity_check_left",
    [INTEGRITY_CHECK_RIGHT] = "integrity_check_right",
    [INTEGRITY_CHECK_GLOBAL] = "integrity_check_global",
    [INTEGRITY_CLEAR] = "integrity_clear"
};

// Create a data synchronization check/clear message

char * dbsync_check_msg(const char * component, dbsync_msg msg, long id, const char * start, const char * top, const char * tail, const char * checksum) {
    assert(msg < sizeof(INTEGRITY_COMMANDS) / sizeof(char *));
    assert(id > 0);

    cJSON * root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "component", component);
    cJSON_AddStringToObject(root, "type", INTEGRITY_COMMANDS[msg]);

    cJSON * data = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "data", data);
    cJSON_AddNumberToObject(data, "id", id);

    if (msg != INTEGRITY_CLEAR) {
        assert(start != NULL);
        assert(top != NULL);
        assert(checksum != NULL);

        cJSON_AddStringToObject(data, "begin", start);
        cJSON_AddStringToObject(data, "end", top);

        if (msg == INTEGRITY_CHECK_LEFT) {
            assert(tail != NULL);
            cJSON_AddStringToObject(data, "tail", tail);
        }

        cJSON_AddStringToObject(data, "checksum", checksum);
    }

    char * payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return payload;
}

// Create a data synchronization state message

char * dbsync_state_msg(const char * component, cJSON * data) {
    cJSON * root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "component", component);
    cJSON_AddStringToObject(root, "type", "state");
    cJSON_AddItemToObject(root, "data", data);

    char * msg = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return msg;
}
