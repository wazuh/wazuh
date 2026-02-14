/*
 * Copyright (C) 2015, Wazuh Inc.
 * November, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BUFFER_OP_H
#define BUFFER_OP_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char *data;
    size_t size;
    size_t used;
    bool status;
} buffer_t;


/**
 * @brief function to initialize buffer char array.
 *
 * @param size Size to allocate in buffer memory.
 *
 * @retval 0 != on success, Buffer(buffer_t) structure that contain context.
 * @retval 0 on error
 */
buffer_t *buffer_initialize(const size_t size);

/**
 * @brief function to append data on initialized buffer. 
 *
 * @param buffer Buffer(buffer_t) structure that contain context.
 * @param src source data to append in buffer_t destination buffer.
 * @param src_size source data size to append in buffer_t destination buffer.
 *
 */
void buffer_push(buffer_t * const buffer, const char* const src, const size_t src_size);
/**
 * @brief function to deallocate buffer char array.
 *
 * @param buffer Buffer(buffer_t) structure that contain context.
 *
 */
void buffer_free(buffer_t *buffer);

#endif /* BUFFER_OP_H */
