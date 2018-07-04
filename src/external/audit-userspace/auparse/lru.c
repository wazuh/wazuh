/*
 * lru.c - LRU cache implementation
 * Copyright (c) 2016,2017 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved. 
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "lru.h"

//#define DEBUG

#ifdef DEBUG
#include <syslog.h>
#endif
 
// Local declarations
static void dequeue(Queue *queue);

// The Queue Node will store the 'str' being cached
static QNode *new_QNode(void)
{
	QNode *temp = malloc(sizeof(QNode));
	if (temp == NULL)
		return temp;
	temp->str = NULL;
	temp->id = (unsigned int)-1;
	temp->uses = 1;	// Setting to 1 because its being used
 
	// Initialize prev and next as NULL
	temp->prev = temp->next = NULL;
 
	return temp;
}
 
static Hash *create_hash(unsigned int hsize)
{
	unsigned int i;

	Hash *hash = malloc(sizeof(Hash));
	if (hash == NULL)
		return hash;

	hash->array = malloc(hsize * sizeof(QNode*));
	if (hash->array == NULL) {
		free(hash);
		return NULL;
	}
 
	// Initialize all hash entries as empty
	for (i = 0; i < hsize; i++)
		hash->array[i] = NULL;
 
	return hash;
}

static void destroy_hash(Hash *hash)
{
	free(hash->array);
	free(hash);
}
 
#ifdef DEBUG
static void dump_queue_stats(const Queue *q)
{
	syslog(LOG_DEBUG, "%s queue size: %u", q->name, q->total);
	syslog(LOG_DEBUG, "%s slots in use: %u", q->name, q->count);
	syslog(LOG_DEBUG, "%s hits: %lu", q->name, q->hits);
	syslog(LOG_DEBUG, "%s misses: %lu", q->name, q->misses);
	syslog(LOG_DEBUG, "%s evictions: %lu", q->name, q->evictions);
}
#endif

static Queue *create_queue(unsigned int qsize, const char *name)
{
	Queue *queue = malloc(sizeof(Queue));
	if (queue == NULL)
		return queue;
 
	// The queue is empty
	queue->count = 0;
	queue->hits = 0;
	queue->misses = 0;
	queue->evictions = 0;
	queue->front = queue->end = NULL;
 
	// Number of slots that can be stored in memory
	queue->total = qsize;

	queue->name = name;
 
	return queue;
}

static void destroy_queue(Queue *queue)
{
#ifdef DEBUG
	dump_queue_stats(queue);
#endif

	while (queue->count)
		dequeue(queue);

	free(queue);
}
 
static unsigned int are_all_slots_full(const Queue *queue)
{
	return queue->count == queue->total;
}
 
static unsigned int queue_is_empty(const Queue *queue)
{
	return queue->end == NULL;
}

#ifdef DEBUG
static void sanity_check_queue(Queue *q, const char *id)
{
	unsigned int i;
	QNode *n = q->front;
	if (n == NULL)
		return;

	// Walk bottom to top
	i = 0;
	while (n->next) {
		if (n->next->prev != n) {
			syslog(LOG_DEBUG, "%s - corruption found %u", id, i);
			abort();
		}
		if (i == q->count) {
			syslog(LOG_DEBUG, "%s - forward loop found %u", id, i);
			abort();
		}
		i++;
		n = n->next;
	}

	// Walk top to bottom
	n = q->end;
	while (n->prev) {
		if (n->prev->next != n) {
			syslog(LOG_DEBUG, "%s - Corruption found %u", id, i);
			abort();
		}
		if (i == 0) {
			syslog(LOG_DEBUG, "%s - backward loop found %u", id, i);
			abort();
		}
		i--;
		n = n->prev;
	}
}
#else
#define sanity_check_queue(a, b) do {} while(0)
#endif

static void insert_before(Queue *queue, QNode *node, QNode *new_node)
{
	sanity_check_queue(queue, "1 insert_before");
	new_node->prev = node->prev;
	new_node->next  = node;
	if (node->prev == NULL)
		queue->front = new_node;
	else
		node->prev->next = new_node;
	node->prev = new_node;
	sanity_check_queue(queue, "2 insert_before");
}

static void insert_beginning(Queue *queue, QNode *new_node)
{
	sanity_check_queue(queue, "1 insert_beginning");
	if (queue->front == NULL) {
		queue->front = new_node;
		queue->end = new_node;
		new_node->prev = NULL;
		new_node->next = NULL;
	} else
		insert_before(queue, queue->front, new_node);
	sanity_check_queue(queue, "2 insert_beginning");
}

static void remove_node(Queue *queue, QNode *node)
{
	// If we are at the beginning
	sanity_check_queue(queue, "1 remove_node");
	if (node->prev == NULL) {
		queue->front = node->next;
		if (queue->front)
			queue->front->prev = NULL;
		goto out;
	} else {
		if (node->prev->next != node) {
#ifdef DEBUG
			syslog(LOG_ERR, "Linked list corruption detected %s",
				queue->name);
#endif
			abort();
		}
		node->prev->next = node->next;
	}

	// If we are at the end
	if (node->next == NULL) {
		queue->end = node->prev;
		if (queue->end)
			queue->end->next = NULL;
	} else {
		if (node->next->prev != node) {
#ifdef DEBUG
			syslog(LOG_ERR, "Linked List corruption detected %s",
				queue->name);
#endif
			abort();
		}
		node->next->prev = node->prev;
	}
out:
	sanity_check_queue(queue, "2 remove_node");
}

// Remove from the end of the queue 
static void dequeue(Queue *queue)
{
	QNode *temp = queue->end;

	if (queue_is_empty(queue))
		return;

	remove_node(queue, queue->end);

//	if (queue->cleanup)
//		queue->cleanup(temp->str); 
	free(temp->str);
	free(temp);
 
	// decrement the total of full slots by 1
	queue->count--;
}
 
// Remove front of the queue because its a mismatch
void lru_evict(Queue *queue, unsigned int key)
{
	Hash *hash = queue->hash;
	QNode *temp = queue->front;

	if (queue_is_empty(queue))
		return;
 
	hash->array[key] = NULL;
	remove_node(queue, queue->front);

//	if (queue->cleanup)
//		queue->cleanup(temp->str);
	free(temp->str);
	free(temp);

        // decrement the total of full slots by 1
	queue->count--;
	queue->evictions++;
}

// Make a new entry with str to be assigned later
// and setup the hash key
static void enqueue(Queue *queue, unsigned int key)
{
	QNode *temp;
	Hash *hash = queue->hash;

	// If all slots are full, remove the page at the end
	if (are_all_slots_full(queue)) {
		// remove page from hash
		hash->array[key] = NULL;
		dequeue(queue);
	}

	// Create a new node with given page total,
	// And add the new node to the front of queue
	temp = new_QNode();

	insert_beginning(queue, temp); 
	hash->array[key] = temp;
 
	// increment number of full slots
	queue->count++;
}
 
// This function is called needing a str from cache.
//  There are two scenarios:
// 1. Item is not in cache, so add it to the front of the queue
// 2. Item is in cache, we move the str to front of queue
QNode *check_lru_cache(Queue *queue, unsigned int key)
{
	QNode *reqPage;
	Hash *hash = queue->hash;

	// Check for out of bounds key
	if (key >= queue->total) {
		return NULL;
	}

	reqPage = hash->array[key];
 
	// str is not in cache, make new spot for it
	if (reqPage == NULL) {
		enqueue(queue, key);
		queue->misses++;
 
	// str is there but not at front. Move it
	} else if (reqPage != queue->front) {
		remove_node(queue, reqPage);
		reqPage->next = NULL; 
		reqPage->prev = NULL; 
		insert_beginning(queue, reqPage);
 
		// Increment cached object metrics
		queue->front->uses++;
		queue->hits++;
	} else
		queue->hits++;

	return queue->front;
}

Queue *init_lru(unsigned int qsize, void (*cleanup)(void *),
		const char *name)
{
	Queue *q = create_queue(qsize, name);
	if (q == NULL)
		return q;

	q->cleanup = cleanup;
	q->hash = create_hash(qsize);

	return q;
}

void destroy_lru(Queue *queue)
{
	if (queue == NULL)
		return;

	destroy_hash(queue->hash);
	destroy_queue(queue);
}

unsigned int compute_subject_key(const Queue *queue, unsigned int uid)
{
	if (queue)
		return uid % queue->total;
	else
		return 0;
}

