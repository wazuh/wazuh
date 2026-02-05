/**
 * @file bqueue_op.h
 * @brief Binary queue type declaration
 * @date 2020-09-20
 *
 * @copyright Copyright (C) 2015 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BQUEUE_OP_H
#define BQUEUE_OP_H

#include <shared.h>

/// bqueue flag set
typedef enum {
    BQUEUE_NOFLAG = 0,  ///< No options defined
    BQUEUE_WAIT   = 1,  ///< Block push if the queue is full, or pop/peek if the queue is empty
    BQUEUE_SHRINK = 2   ///< Shrink queue on pop/peek, if more than a half of the queue is unused
} bqflag_t;

/**
 * @brief Binary string queue type
 *
 * Circular buffer which holds binary strings (byte-arrays). The data is not delimited or zero-terminated.
 * The maximum capacity is max_length - 1, so the minimum value for max_length is 2.
 * Operations are serialized by mutual exclusion.
 */
typedef struct {
    void * memory;              ///< Pointer to the data segment
    void * head;                ///< Pointer to the first avilable byte to read
    void * tail;                ///< Pointer to the first available byte write
    size_t length;              ///< Current queue length
    size_t max_length;          ///< Maximum length limit
    unsigned flags;             ///< Queue-wide flag set
    pthread_mutex_t mutex;      ///< Internal lock
    pthread_cond_t cond_pushed; ///< Some data has been pushed, pop/peek may be available
    pthread_cond_t cond_popped; ///< Some data has been popped, push may be available
} bqueue_t;

/**
 * @brief Allocate and inititialize a new queue
 *
 * @param max_length Maximum allowed length of the queue.
 * @param flags Queue options: BQUEUE_NOFLAG or BQUEUE_SHRINK.
 * @return Pointer to a newly allocated queue.
 * @retval NULL No queue allocated, parameter value error.
 */
bqueue_t * bqueue_init(size_t max_length, unsigned flags);

/**
 * @brief Free a queue
 *
 * @param queue Pointer to a queue, NULL is allowed.
 */
void bqueue_destroy(bqueue_t * queue);

/**
 * @brief Push data into the queue
 *
 * @param queue Pointer to a queue.
 * @param data Pointer to the source data.
 * @param length Number of bytes to insert.
 * @param flags Operation options: BQUEUE_NOFLAG or BQUEUE_WAIT.
 * @retval 0 On success.
 * @retval -1 No sparece available.
 */
int bqueue_push(bqueue_t * queue, const void * data, size_t length, unsigned flags);

/**
 * @brief Get and remove data from the queue
 *
 * Read at most length bytes from the queue and make their space available for
 * upcoming insertions. If BQUEUE_WAIT defined, this operation shall block until
 * at less one byte is readable.
 *
 * If BQUEUE_SHRINK was defined on initialization, the queue will be resized
 * down when the used space is less than half of the current capacity. In any
 * case, the internal buffer will be deallocated if the queue gets empty.
 *
 * This operation is equivalent to call peek + drop atomically.
 *
 * @param queue Pointer to a queue.
 * @param buffer Pointer to the destination buffer.
 * @param length Maximum number of bytes that should be popped.
 * @param flags Operation options: BQUEUE_NOFLAG or BQUEUE_WAIT.
 * @return Number of bytes popped from the queue.
 */
size_t bqueue_pop(bqueue_t * queue, void * buffer, size_t length, unsigned flags);

/**
 * @brief Get data from the queue
 *
 * Read at most length bytes from the queue but do not remove them.
 * If BQUEUE_WAIT defined, this operation shall block until at less one byte is
 * readable.
 *
 * @param queue Pointer to a queue.
 * @param buffer Pointer to the destination buffer.
 * @param length Maximum number of bytes that should be peeked.
 * @param flags Operation options: BQUEUE_NOFLAG or BQUEUE_WAIT.
 * @return Number of bytes read from the queue.
 */
size_t bqueue_peek(bqueue_t * queue, char * buffer, size_t length, unsigned flags);

/**
 * @brief Drop data from the queue
 *
 * Remove length bytes from the queue. That requires that the queue contains at
 * less length bytes.
 *
 * If BQUEUE_SHRINK was defined on initialization, the queue will be resized
 * down when the used space is less than half of the current capacity. In any
 * case, the internal buffer will be deallocated if the queue gets empty.
 *
 * @param queue Pointer to a queue.
 * @param length Number of bytes that shall be removed.
 * @retval 0 On success.
 * @retval -1 length is greater than the currently used space.
 */
int bqueue_drop(bqueue_t * queue, size_t length);

/**
 * @brief Get the current queue size
 *
 * @param queue Pointer to a queue.
 * @return Number of bytes stored in the queue.
 */
size_t bqueue_used(bqueue_t * queue);

/**
 * @brief Clear the queue
 *
 * Discard all data in the queue and deallocate the internal buffer.
 *
 * @param queue Pointer to a queue.
 */
void bqueue_clear(bqueue_t * queue);

#endif
