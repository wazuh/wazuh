/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * July 12, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef INTEGRITY_OP_H
#define INTEGRITY_OP_H

#include "shared.h"

/*
#include <openssl/sha.h>
#include <math.h>

#include "hash_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "debug_op.h"
*/

typedef enum dbsync_msg {
    INTEGRITY_CHECK_LEFT,
    INTEGRITY_CHECK_RIGHT,
    INTEGRITY_CHECK_GLOBAL,
    INTEGRITY_CLEAR
} dbsync_msg;

extern const char * INTEGRITY_COMMANDS[];

/**
 * @brief Create a data synchronization check/clear message
 *
 * Format (check):
 * {
 *   component:     string
 *   type:          "check"
 *   data: {
 *     id:          number
 *     begin:       string
 *     end:         string
 *     tail:        string [Optional]
 *     checksum:    string
 *   }
 * }
 *
 * Format (clear):
 * {
 *   component: string
 *   type:      "clear"
 * }
 *
 * @param component Name of the component.
 * @param id Sync session counter (timetamp).
 * @param start First key in the list.
 * @param top Last key in the list.
 * @param tail Key of the first key in the next sublist.
 * @param checksum Checksum of this list.
 * @return Pointer to dynamically allocated string.
 */

char * dbsync_check_msg(const char * component, dbsync_msg msg, long id, const char * start, const char * top, const char * tail, const char * checksum);

/**
 * @brief Create a data synchronization state message
 *
 * Format:
 * {
 *   component:         string
 *   type:              "state"
 *   data:              object
 * }
 *
 * @param component Name of the component.
 * @param data Synchronization data.
 * @post data is destroyed.
 * @return Pointer to dynamically allocated string.
 */
char * dbsync_state_msg(const char * component, cJSON * data);

#endif /* INTEGRITY_OP_H */
