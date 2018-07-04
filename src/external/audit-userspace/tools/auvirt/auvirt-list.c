#include "auvirt-list.h"
#include <stdlib.h>

list_t *list_init(list_t *list, list_free_data_fn *free_data_fn)
{
	if (list == NULL)
		return NULL;
	list->head = list->tail = NULL;
	list->free_data_fn = free_data_fn;
	return list;
}

list_t *list_new(list_free_data_fn *free_data_fn)
{
	return list_init(malloc(sizeof(list_t)), free_data_fn);
}

void list_free_node(list_node_t *node, list_free_data_fn *free_data_fn)
{
	if (node) {
		if (free_data_fn)
			free_data_fn(node->data);
		free(node);
	}
}

void list_free_(list_t *list, list_free_data_fn *free_data_fn)
{
	if (list != NULL) {
		list_node_t *it = list->head;
		while (it && it->next) {
			it = it->next;
			list_free_node(it->prev, free_data_fn);
		}
		list_free_node(it, free_data_fn);
		free(list);
	}
}

void list_free(list_t *list)
{
	if (list)
		list_free_(list, list->free_data_fn);
}

list_node_t *list_insert_after(list_t *list, list_node_t *it,
		void *data)
{
	list_node_t *node = NULL;
	if (list == NULL)
		return NULL;

	/* allocate node */
	node = malloc(sizeof(list_node_t));
	if (node == NULL)
		return NULL;
	node->data = data;

	/* insert the new node after it */
	node->prev = it;
	if (it) {
		node->next = it->next;
		it->next = node;
	}
	else
		node->next = list->head;
	if (node->next)
		node->next->prev = node;

	/* update list's head and tail */
	if (it == list->tail)
		list->tail = node;
	if (it == NULL)
		list->head = node;

	return node;
}

list_node_t *list_append(list_t *list, void *data)
{
	return list_insert_after(list, list->tail, data);
}

int list_remove_(list_t *list, list_node_t *it,
		list_free_data_fn *free_data_fn)
{
	if (list == NULL || it == NULL)
		return 1;
	if (list->head == it)
		list->head = it->next;
	if (list->tail == it)
		list->tail = it->prev;
	if (it->next)
		it->next->prev = it->prev;
	if (it->prev)
		it->prev->next = it->next;
	list_free_node(it, free_data_fn);
	return 0;
}

int list_remove(list_t *list, list_node_t *it)
{
	return list_remove_(list, it, list->free_data_fn);
}

