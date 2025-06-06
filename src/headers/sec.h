/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SEC_H
#define SEC_H

#include <time.h>
#include <pthread.h>
#include "shared.h"
#include "../os_crypto/sha1/sha1_op.h"

/* Defines to switch according to different OS_AddSocket or, failing that, the case of using UDP protocol */
#define OS_ADDSOCKET_ERROR          0   ///< OSHash_Set_ex returns 0 on error (* see OS_AddSocket and OSHash_Set_ex)
#define OS_ADDSOCKET_KEY_UPDATED    1   ///< OSHash_Set_ex returns 1 when key existed, so it is update (*)
#define OS_ADDSOCKET_KEY_ADDED      2   ///< OSHash_Set_ex returns 2 when key didn't existed, so it is added  (*)

#define USING_UDP_NO_CLIENT_SOCKET  -1  ///< When using UDP, no valid client socket FD is set

typedef enum _crypt_method {
    W_METH_BLOWFISH, W_METH_AES
} crypt_method;

/**
 * @brief Enumerator that defines the key initialization modes.
 */
typedef enum _key_mode {
    W_RAW_KEY, W_ENCRYPTION_KEY, W_DUAL_KEY
} key_mode_t;

typedef struct keystore_flags_t {
    unsigned int key_mode:2;        // Type of key to be initialized
    unsigned int save_removed:1;    // Save removed keys into list
} keystore_flags_t;

/* Unique key for each agent */
typedef struct _keyentry {
    _Atomic (time_t) rcvd;
    unsigned int local;
    unsigned int keyid;
    unsigned int global;
    time_t updating_time;

    char *id;
    char *raw_key;
    char *encryption_key;
    char *name;
    _Atomic (bool) is_startup;

    ino_t inode;

    os_ip *ip;
    int sock;                           ///< File descriptor of client's TCP socket
    _Atomic (int) net_protocol;         ///< Client current protocol
    time_t time_added;
    pthread_mutex_t mutex;
    struct sockaddr_storage peer_info;
    FILE *fp;
    _Atomic (crypt_method) crypto_method;

    w_linked_queue_node_t *rids_node;
} keyentry;

/* Key storage */
typedef struct _keystore {
    /* Array with all the keys */
    keyentry **keyentries;

    /* Hashes, based on the ID/IP to look up the keys */
    rb_tree *keytree_id;
    rb_tree *keytree_ip;
    rb_tree *keytree_sock;

    /* Total key size */
    unsigned int keysize;

    /* Key file stat */
    time_t file_change;
    ino_t inode;

    /* ID counter */
    int id_counter;

    keystore_flags_t flags;

    /* Removed keys storage */
    char **removed_keys;
    size_t removed_keys_size;

    w_linked_queue_t *opened_fp_queue;

    /* Mutexes */
    pthread_mutex_t keytree_sock_mutex;
} keystore;

typedef enum key_states {
    KS_VALID,
    KS_RIDS,
    KS_CORRUPT,
    KS_ENCKEY
} key_states;

#define KEYSTORE_INITIALIZER { NULL, NULL, NULL, NULL, 0, 0, 0, 0, { 0, 0 }, NULL, 0, NULL, PTHREAD_MUTEX_INITIALIZER }

/** Function prototypes -- key management **/

/* Check if the authentication keys are present */
int OS_CheckKeys(void);

/* Read the keys */
void OS_ReadKeys(keystore *keys, key_mode_t key_mode, int save_removed) __attribute((nonnull));

void OS_FreeKey(keyentry *key);

/* Free the auth keys */
void OS_FreeKeys(keystore *keys) __attribute((nonnull));

/* Check if key changed */
int OS_CheckUpdateKeys(const keystore *keys) __attribute((nonnull));

/* Update the keys if they changed on the system */
void OS_UpdateKeys(keystore *keys) __attribute((nonnull));

/* Start counter for all agents */
void OS_StartCounter(keystore *keys) __attribute((nonnull));

/* Remove counter for id */
void OS_RemoveCounter(const char *id) __attribute((nonnull));

/* Configure to pass if keys file is empty */
void OS_PassEmptyKeyfile();

/* Add new key */
int OS_AddKey(keystore *keys, const char *id, const char *name, const char *ip, const char *key, time_t time_added) __attribute((nonnull));

/* Delete a key */
int OS_DeleteKey(keystore *keys, const char *id, int purge);

/* Write keystore on client keys file */
int OS_WriteKeys(const keystore *keys);

/* Duplicate keystore except key hashes and file pointer */
keystore* OS_DupKeys(const keystore *keys);

/* Duplicate key entry except key hashes and file pointer */
keyentry * OS_DupKeyEntry(const keyentry * key);

/** Function prototypes -- agent authorization **/

/* Check if the IP is allowed */
int OS_IsAllowedIP(keystore *keys, const char *srcip) __attribute((nonnull(1)));

/* Check if the ID is allowed */
int OS_IsAllowedID(keystore *keys, const char *id) __attribute((nonnull(1)));

/* Check if the name is valid */
int OS_IsAllowedName(const keystore *keys, const char *name) __attribute((nonnull));

/* Check if the id is valid and dynamic */
int OS_IsAllowedDynamicID(keystore *keys, const char *id, const char *srcip) __attribute((nonnull(1)));

/**
 * @brief Parse the agent timestamps file into the keystore structure
 *
 * @param keys Pointer to a keystore structure.
 * @return Status of the operation.
 * @retval 0 On success.
 * @retval -1 On failure.
 */
int OS_ReadTimestamps(keystore * keys);

/**
 * @brief  Write the agent timestamp data into the timestamps file
 *
 * @param keys Pointer to a keystore structure.
 * @return Status of the operation.
 * @retval 0 On success.
 * @retval -1 On failure.
 */
int OS_WriteTimestamps(keystore * keys);

/** Function prototypes -- send/recv messages **/

/* Decrypt and decompress a remote message */
int ReadSecMSG(keystore *keys, char *buffer, char *cleartext, int id, unsigned int buffer_size, size_t *final_size, const char *ip, char **output) __attribute((nonnull));

/* Create an OSSEC message (encrypt and compress) */
size_t CreateSecMSG(const keystore *keys, const char *msg, size_t msg_length, char *msg_encrypted, unsigned int id) __attribute((nonnull));

// Add socket number into keystore
int OS_AddSocket(keystore * keys, unsigned int i, int sock);

// Delete socket number from keystore
int OS_DeleteSocket(keystore * keys, int sock);

/**
 * @brief Get agent's network protocol from keystore given its agent id
 *
 * @param keys Contains information related with the agents
 * @param agent_id This variable is used to index the keys array
 * @retval -1 if protocol could not be found
 * @retval REMOTED_NET_PROTOCOL_TCP if agent protocol is TCP
 * @retval REMOTED_NET_PROTOCOL_UDP if agent protocol is UDP
 */
int w_get_agent_net_protocol_from_keystore(keystore * keys, const char * agent_id);

/**
 * @brief Receives a keyentry structure and returns the SHA1 value of the agent's key.
 *
 * @param key_entry The agent's key structure
 * @param output The variable where the hashed key will be stored
 * @retval Returns OS_SUCCESS on success or OS_INVALID on error.
 **/
int w_get_key_hash(keyentry *key_entry, os_sha1 output);

/* Set the agent crypto method read from the ossec.conf file */
void os_set_agent_crypto_method(keystore * keys,const int method);

/** Remote IDs directories and internal definitions */
#ifndef WIN32
#define RIDS_DIR        "queue/rids"
#else
#define RIDS_DIR        "rids"
#endif

#define SENDER_COUNTER  "sender_counter"
#define KEYSIZE         128

extern unsigned int _s_comp_print;
extern unsigned int _s_recv_flush;
extern int _s_verify_counter;

#endif /* SEC_H */
