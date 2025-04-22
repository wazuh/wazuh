/*
 * Wazuh DB pool handler headers
 * Copyright (C) 2015, Wazuh Inc.
 * February 16, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "wdb.h"

typedef struct {
    rb_tree * nodes;
    pthread_mutex_t mutex;
    _Atomic(unsigned) size;
} wdb_pool_t;

/**
 * @brief Initialize global pool.
 */
void wdb_pool_init();

/**
 * @brief Find a node in the pool by name.
 *
 * @param name Database identifier
 * @post The node's reference counter gets incremented.
 * @post The node's mutex gets locked (when found).
 * @return Pointer to the selected database node
 * @retval null The database does not exist in the pool.
 */
wdb_t * wdb_pool_get(const char * name);

/**
 * @brief Find a node in the pool by name, or create if it does not exist.
 *
 * @param name Database identifier
 * @post The node's reference counter gets incremented.
 * @post The node's mutex gets locked.
 * @return Pointer to the selected database node
 */
wdb_t * wdb_pool_get_or_create(const char * name);
wdb_t * wdb_pool_get_or_create_global(const char * nam, bool read);
/**
 * @brief Leave a node
 *
 * @param node Pointer to a database node.
 * @pre The node's mutex must stay locked.
 * @post The node's reference counter gets decremented.
 * @post The node's mutex gets unlocked.
 */
void wdb_pool_leave(wdb_t * node);
void wdb_pool_leave_global(wdb_t * node);

/**
 * @brief Get all the existing names in the pool.
 *
 * @return String array containing the names of all contained nodes.
 */
char ** wdb_pool_keys();

/**
 * @brief Remove closed databases from the pool.
 *
 * Scans the pool and destroys all nodes associated to closed databases.
 */
void wdb_pool_clean();

/**
 * @brief Get the current pool size.
 *
 * This function returns how many nodes are currently in the pool, no matter if
 * the databases are open or closed.
 *
 * @return Number of nodes in the pool.
 */
unsigned wdb_pool_size();
