/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "state.h"
#include "shared.h"

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief state storage structure
 * key: location option value. value: lc_state_file_t
 */
typedef struct {
    time_t start;    ///< initial state timestamp
    OSHash * states; ///< state storage
} lc_states_t;

/**
 * @brief target state storage
 *
 */
typedef struct {
    char * name;    ///< target name
    uint64_t drops; ///< drop count
} lc_state_target_t;

/**
 * @brief file state storage
 *
 */
typedef struct {
    uint64_t bytes;               ///< bytes count
    uint64_t events;              ///< events count
    lc_state_target_t ** targets; ///< array of poiters to file's different targets
} lc_state_file_t;

char * g_lc_pritty_stats;           ///< string that store single line formated JSON with states
lc_states_t * g_lc_states_global;   ///< global state struct storage
lc_states_t * g_lc_states_interval; ///< interval state struct storage
pthread_mutex_t g_lc_raw_stats_mutex = PTHREAD_MUTEX_INITIALIZER; ///< g_lc_pritty_stats mutual exclusion mechanism
pthread_mutex_t g_lc_pritty_stats_mutex =
    PTHREAD_MUTEX_INITIALIZER; ///< g_lc_states_* structs mutual exclusion mechanism

const char * LOGCOLLECTOR_STATE_DESCRIPTION = "logcollector_state"; ///< String identifier for errors

/**
 * @brief Trigger the generation of states
 *
 */
STATIC void w_logcollector_generate_state();

/**
 * @brief Generate and process the current states information
 *
 * @param state state to generate
 * @param restart restart counters and date after generating
 * @return cJSON * json decription with state information
 */
STATIC cJSON * _w_logcollector_generate_state(lc_states_t * state, bool restart);

/**
 * @brief Update/register current event and byte count for a particular file/location
 *
 * @param state state to be used
 * @param fpath file path or locafile location value
 * @param bytes amount of bytes
 */
STATIC void _w_logcollector_state_update_file(lc_states_t * state, char * fpath, uint64_t bytes);

/**
 * @brief Update/register current drop count for a target belonging to a particular file
 *
 * @param state state to be used
 * @param fpath file path or locafile location value
 * @param target target name
 * @param dropped true if want to register a drop.
 */
STATIC void _w_logcollector_state_update_target(lc_states_t * state, char * fpath, char * target, bool dropped);

/**
 * @brief Dump state information to file
 *
 */
STATIC void w_logcollector_state_dump();

#ifdef WIN32
DWORD WINAPI w_logcollector_state_main(__attribute__((unused)) void * args) {
#else
void * w_logcollector_state_main(__attribute__((unused)) void * args) {
#endif

    int interval = getDefine_Int("logcollector", "state_interval", 1, 3600);

    while (1) {
        sleep(interval);
        w_logcollector_generate_state();
        w_logcollector_state_dump();
    }
#ifndef WIN32
    return NULL;
#endif
}

static void w_logcollector_state_dump() {

    char * lc_state_str = w_logcollector_state_get();

    FILE * lc_state_file = NULL;

    if (lc_state_file = fopen(LOGCOLLECTOR_STATE_PATH, "w"), lc_state_file != NULL) {
        if (fwrite(lc_state_str, sizeof(char), strlen(lc_state_str), lc_state_file) < 1) {
            merror(FREAD_ERROR, LOGCOLLECTOR_STATE_PATH, errno, strerror(errno));
        }
        fclose(lc_state_file);
    }

    os_free(lc_state_str);
}

void w_logcollector_state_init() {

    os_calloc(1, sizeof(lc_states_t), g_lc_states_global);
    os_calloc(1, sizeof(lc_states_t), g_lc_states_interval);

    g_lc_states_global->start = time(NULL);
    g_lc_states_interval->start = time(NULL);

    if (g_lc_states_global->states = OSHash_Create(), g_lc_states_global->states == NULL) {
        merror_exit(HCREATE_ERROR, LOGCOLLECTOR_STATE_DESCRIPTION);
    }

    if (g_lc_states_interval->states = OSHash_Create(), g_lc_states_interval->states == NULL) {
        merror_exit(HCREATE_ERROR, LOGCOLLECTOR_STATE_DESCRIPTION);
    }

    if (OSHash_setSize(g_lc_states_global->states, LOGCOLLECTOR_STATE_FILES_MAX) == 0) {
        merror_exit(HSETSIZE_ERROR, LOGCOLLECTOR_STATE_DESCRIPTION);
    }

    if (OSHash_setSize(g_lc_states_interval->states, LOGCOLLECTOR_STATE_FILES_MAX) == 0) {
        merror_exit(HSETSIZE_ERROR, LOGCOLLECTOR_STATE_DESCRIPTION);
    }
}

void w_logcollector_state_update_target(char * fpath, char * target, bool dropped) {

    if (fpath == NULL || target == NULL) {
        return;
    }

    w_mutex_lock(&g_lc_raw_stats_mutex);

    _w_logcollector_state_update_target(g_lc_states_global, fpath, target, dropped);
    _w_logcollector_state_update_target(g_lc_states_interval, fpath, target, dropped);

    w_mutex_unlock(&g_lc_raw_stats_mutex);
}

void w_logcollector_state_update_file(char * fpath, uint64_t bytes) {

    if (fpath == NULL) {
        return;
    }

    w_mutex_lock(&g_lc_raw_stats_mutex);

    _w_logcollector_state_update_file(g_lc_states_global, fpath, bytes);
    _w_logcollector_state_update_file(g_lc_states_interval, fpath, bytes);

    w_mutex_unlock(&g_lc_raw_stats_mutex);
}

void _w_logcollector_state_update_file(lc_states_t * state, char * fpath, uint64_t bytes) {

    lc_state_file_t * data = NULL;

    // Try to get file stats. Create it if not initialized yet,
    if (data = (lc_state_file_t *) OSHash_Get(state->states, fpath), data == NULL) {
        os_calloc(1, sizeof(lc_state_file_t), data);
        os_calloc(1, sizeof(lc_state_target_t *), data->targets);
    }

    data->events++;
    data->bytes += bytes;

    if (OSHash_Update(state->states, fpath, data) != 1) {
        OSHash_Add(state->states, fpath, data);
    }
}
void _w_logcollector_state_update_target(lc_states_t * state, char * fpath, char * target, bool dropped) {

    lc_state_file_t * data = NULL;
    lc_state_target_t ** current_target = NULL;
    int len = 0;

    // Try to get file stats. Create it if not initialized yet,
    if (data = (lc_state_file_t *) OSHash_Get(state->states, fpath), data == NULL) {
        os_calloc(1, sizeof(lc_state_file_t), data);
        os_calloc(1, sizeof(lc_state_target_t *), data->targets);
    }

    // Try to find target
    for (len = 0, current_target = data->targets; *current_target != NULL; len++, current_target++) {
        if (strcmp(target, (*current_target)->name) == 0) {
            break;
        }
    }

    // If target was not found, create it.
    if (*current_target == NULL) {
        os_realloc(data->targets, (len + 2) * sizeof(lc_state_target_t *), data->targets);
        os_calloc(1, sizeof(lc_state_target_t), data->targets[len]);
        data->targets[len + 1] = NULL;
        current_target = &data->targets[len];
        os_strdup(target, (*current_target)->name);
    }

    if (dropped) {
        (*current_target)->drops++;
    }

    if (OSHash_Update(state->states, fpath, data) != 1) {
        OSHash_Add(state->states, fpath, data);
    }
}

void w_logcollector_generate_state() {

    w_mutex_lock(&g_lc_pritty_stats_mutex);
    w_mutex_lock(&g_lc_raw_stats_mutex);

    os_free(g_lc_pritty_stats);

    cJSON * lc_stats_json = cJSON_CreateObject();
    cJSON * lc_stats_json_global = _w_logcollector_generate_state(g_lc_states_global, false);
    cJSON_AddItemToObject(lc_stats_json, "global", lc_stats_json_global);
    cJSON * lc_stats_json_interval = _w_logcollector_generate_state(g_lc_states_interval, true);
    cJSON_AddItemToObject(lc_stats_json, "interval", lc_stats_json_interval);

    g_lc_pritty_stats = cJSON_PrintUnformatted(lc_stats_json);

    cJSON_Delete(lc_stats_json);

    w_mutex_unlock(&g_lc_raw_stats_mutex);
    w_mutex_unlock(&g_lc_pritty_stats_mutex);
}

char * w_logcollector_state_get() {

    char * state_str = NULL;

    w_mutex_lock(&g_lc_pritty_stats_mutex);

    os_strdup(g_lc_pritty_stats, state_str);

    w_mutex_unlock(&g_lc_pritty_stats_mutex);

    return state_str;
}

cJSON * _w_logcollector_generate_state(lc_states_t * state, bool restart) {

    OSHashNode * hash_node = NULL;
    unsigned int index = 0;

    if (hash_node = OSHash_Begin(state->states, &index), hash_node == NULL) {
        return NULL;
    }

    cJSON * lc_stats_json = cJSON_CreateObject();
    cJSON * lc_stats_files_array = cJSON_CreateArray();

    // Iterate for each file
    while (hash_node) {
        lc_state_file_t * data = hash_node->data;

        // Target logic
        cJSON * lc_stats_targets_array = cJSON_CreateArray();
        lc_state_target_t ** target = data->targets;
        while (*target != NULL) {
            cJSON * lc_stats_target = cJSON_CreateObject();
            cJSON_AddStringToObject(lc_stats_target, "name", (*target)->name);
            cJSON_AddNumberToObject(lc_stats_target, "drops", (*target)->drops);
            cJSON_AddItemToArray(lc_stats_targets_array, lc_stats_target);
            if (restart) {
                (*target)->drops = 0;
            }
            target++;
        }

        // Files
        cJSON * lc_stats_file = cJSON_CreateObject();
        cJSON_AddItemToObject(lc_stats_file, "targets", lc_stats_targets_array);
        cJSON_AddStringToObject(lc_stats_file, "location", hash_node->key);
        cJSON_AddNumberToObject(lc_stats_file, "bytes", data->bytes);
        cJSON_AddNumberToObject(lc_stats_file, "events", data->events);
        if (restart) {
            data->bytes = 0;
            data->events = 0;
        }
        cJSON_AddItemToArray(lc_stats_files_array, lc_stats_file);
        hash_node = OSHash_Next(state->states, &index, hash_node);
    }

    // Convert timestamp to string, removing newline from ctime return
    time_t now = time(NULL);
    char * now_str = NULL;
    char * start_str = NULL;
    os_strdup(ctime(&now), now_str);
    os_strdup(ctime(&state->start), start_str);

    now_str[strlen(now_str) - 1] = '\0';
    start_str[strlen(start_str) - 1] = '\0';

    cJSON_AddStringToObject(lc_stats_json, "start", start_str);
    cJSON_AddStringToObject(lc_stats_json, "end", now_str);
    cJSON_AddItemToObject(lc_stats_json, "files", lc_stats_files_array);

    os_free(now_str);
    os_free(start_str);

    if (restart) {
        state->start = time(NULL);
    }
    return lc_stats_json;
}
