/*
 * Copyright (C) 2015, Wazuh Inc.
 * November, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../headers/shared.h"


buffer_t *buffer_initialize(const size_t size){
    buffer_t * buffer;
    os_calloc(1,sizeof(buffer_t),buffer);
    os_calloc(size,sizeof(char),buffer->data);
    buffer->size = size;
    buffer->used = 0;
    buffer->status = TRUE;
    return buffer;
}

void buffer_push(buffer_t * const buffer, const char* const src, const size_t src_size) {
    if (NULL != buffer) {
        if (NULL != src) {
            if((buffer->size - buffer->used) > src_size && NULL != buffer->data) {
                memcpy(buffer->data + buffer->used, src, src_size);
                buffer->used += src_size;
            } else {
                buffer->status = FALSE;
            }
        } else {
            buffer->status = FALSE;
        }
    }
}

void buffer_free(buffer_t *buffer) {
    if (NULL != buffer) {
        if (buffer->data) {
            os_free(buffer->data);
        }
        os_free(buffer);
    }
}
