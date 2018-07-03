
#ifndef AUVIRT_LIST_HEADER
#define AUVIRT_LIST_HEADER

typedef void (list_free_data_fn)(void *data);

typedef struct list_node_t {
	void *data;
	struct list_node_t *prev;
	struct list_node_t *next;
} list_node_t;

typedef struct list_t {
	list_node_t *head;
	list_node_t *tail;
	list_free_data_fn *free_data_fn;
} list_t;

list_t *list_init(list_t *list, list_free_data_fn *free_data_fn);
list_t *list_new(list_free_data_fn *free_data_fn);
void list_free_(list_t *list, list_free_data_fn *free_data_fn);
void list_free(list_t *list);
list_node_t *list_insert_after(list_t *list, list_node_t *it,
		void *data);
list_node_t *list_append(list_t *list, void *data);
int list_remove_(list_t *list, list_node_t *it,
		list_free_data_fn *free_data_fn);
int list_remove(list_t *list, list_node_t *it);

#endif

