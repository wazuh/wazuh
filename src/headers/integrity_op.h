/*
 * Copyright (C) 2015, Wazuh Inc.
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

/**
 * @brief Synchronization status codes
 */
typedef enum integrity_sync_status_t {
    INTEGRITY_SYNC_ERR      = -1,
    INTEGRITY_SYNC_NO_DATA  = 0,
    INTEGRITY_SYNC_CKS_FAIL = 1,
    INTEGRITY_SYNC_CKS_OK   = 2,
} integrity_sync_status_t;

/**
 * @brief Synchronization message type
 */
typedef enum dbsync_msg {
    INTEGRITY_CHECK_LEFT,       ///< Splitted chunk: left part.
    INTEGRITY_CHECK_RIGHT,      ///< Splitted chunk: right part.
    INTEGRITY_CHECK_GLOBAL,     ///< Global chunk (all files).
    INTEGRITY_CLEAR             ///< Clear data (no files at all).
} dbsync_msg;

extern const char * INTEGRITY_COMMANDS[];

/**
 * @brief Create a data synchronization check/clear message
 *
 * Format (check):
 * {
 *   component:     string
 *   type:          "integrity_check_global"|"integrity_check_left"|"integrity_check_right"
 *   data: {
 *     id:          number
 *     begin:       string
 *     end:         string
 *     tail:        string [Only if type="integrity_check_left"]
 *     checksum:    string
 *   }
 * }
 *
 * Format (clear):
 * {
 *   component: string
 *   type:      "integrity_clear"
 *   data: {
 *     id:      number
 *   }
 * }
 *
 * @param component Name of the component.
 * @param msg Type of the message.
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
