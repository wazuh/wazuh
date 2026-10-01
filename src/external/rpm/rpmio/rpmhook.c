#include "system.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <rpm/rpmstring.h>
#include "rpmhook.h"

#include "debug.h"

#define RPMHOOK_TABLE_INITSIZE  256
#define RPMHOOK_BUCKET_INITSIZE 5

typedef struct rpmhookItem_s {
    rpmhookFunc func;
    void *data;
    struct rpmhookItem_s *next;
} * rpmhookItem;

typedef struct rpmhookBucket_s {
    unsigned long hash;
    char *name;
    rpmhookItem item;
} * rpmhookBucket;

typedef struct rpmhookTable_s {
    int size;
    int used;
    struct rpmhookBucket_s bucket[1];
} * rpmhookTable;


rpmhookArgs rpmhookArgsNew(int argc)
{
    rpmhookArgs args = (rpmhookArgs) xcalloc(1,
			sizeof(*args) + sizeof(args->argv) * (argc-1));
    args->argc = argc;
    return args;
}

rpmhookArgs rpmhookArgsFree(rpmhookArgs args)
{
    if (args != NULL)
	free(args);
    return NULL;
}

static rpmhookTable rpmhookTableNew(int size)
{
    rpmhookTable table = (rpmhookTable) xcalloc(1,
		sizeof(*table) + sizeof(table->bucket) * (size-1));
    table->size = size;
    return table;
}

#if 0
static rpmhookTable rpmhookTableFree(rpmhookTable table)
{
    rpmhookItem item, nextItem;
    int i;
    for (i = 0; i != table->size; i++) {
	if (table->bucket[i].name == NULL)
	    continue;
	free(table->bucket[i].name);
	item = table->bucket[i].item;
	while (item) {
	    nextItem = item->next;
	    free(item);
	    item = nextItem;
	}
    }
    free(table);
    return NULL;
}
#endif

static void rpmhookTableRehash(rpmhookTable *table);

static int rpmhookTableFindBucket(rpmhookTable *table, const char *name)
{
    /* Hash based on http://www.isthe.com/chongo/tech/comp/fnv/ */
    unsigned long perturb;
    unsigned long hash = 0;
    unsigned char *bp = (unsigned char *)name;
    unsigned char *be = bp + strlen(name);
    rpmhookBucket bucket;
    int ret;

    if (((*table)->used/2)*3 > (*table)->size)
	rpmhookTableRehash(table);
    while (bp < be) {
	hash ^= (unsigned long)*bp++;
	hash *= (unsigned long)0x01000193;
    }
    perturb = hash;
    ret = hash % (*table)->size;
    bucket = &(*table)->bucket[ret];
    while (bucket->name &&
	    (bucket->hash != hash || !rstreq(bucket->name, name))) {
	/* Collision resolution based on Python's perturb scheme. */
	ret = ((ret << 2) + ret + perturb + 1) % (*table)->size;
	perturb >>= 5;
	bucket = &(*table)->bucket[ret];
    }
    if (!bucket->name)
	bucket->hash = hash;
    return ret;
}

static void rpmhookTableRehash(rpmhookTable *table)
{
    rpmhookTable newtable = rpmhookTableNew((*table)->size*2);
    int n, i = 0;

    for (; i != (*table)->size; i++) {
	if ((*table)->bucket[i].name == NULL)
	    continue;
	n = rpmhookTableFindBucket(&newtable, (*table)->bucket[i].name);
	newtable->bucket[n].name = (*table)->bucket[i].name;
	newtable->bucket[n].item = (*table)->bucket[i].item;
    }
    newtable->used = (*table)->used;
    free(*table);
    *table = newtable;
}

static void rpmhookTableAddItem(rpmhookTable *table, const char *name,
				rpmhookFunc func, void *data)
{
    int n = rpmhookTableFindBucket(table, name);
    rpmhookBucket bucket = &(*table)->bucket[n];
    rpmhookItem *item = &bucket->item;
    if (!bucket->name) {
	bucket->name = xstrdup(name);
	(*table)->used++;
    }
    while (*item) item = &(*item)->next;
    *item = (rpmhookItem)xcalloc(1, sizeof(**item));
    (*item)->func = func;
    (*item)->data = data;
}

static void rpmhookTableDelItem(rpmhookTable *table, const char *name,
		rpmhookFunc func, void *data,
		int matchfunc, int matchdata)
{
    int n = rpmhookTableFindBucket(table, name);
    rpmhookBucket bucket = &(*table)->bucket[n];
    rpmhookItem item = bucket->item;
    rpmhookItem lastItem = NULL;
    rpmhookItem nextItem;
    while (item) {
	nextItem = item->next;
	if ((!matchfunc || item->func == func) &&
	    (!matchdata || item->data == data)) {
	    free(item);
	    if (lastItem)
		lastItem->next = nextItem;
	    else
		bucket->item = nextItem;
	} else {
	    lastItem = item;
	}
	item = nextItem;
    }
    if (!bucket->item) {
	free(bucket->name);
	bucket->name = NULL;
	(*table)->used--;
    }
}

static rpmhookArgs rpmhookArgsParse(const char *argt, va_list ap)
{
    rpmhookArgs args = rpmhookArgsNew(strlen(argt));
    int i;

    args->argt = argt;
    for (i = 0; i != args->argc; i++) {
	switch (argt[i]) {
	    case 's':
		args->argv[i].s = va_arg(ap, char *);
		break;
	    case 'i':
		args->argv[i].i = va_arg(ap, int);
		break;
	    case 'f':
		args->argv[i].f = va_arg(ap, double);
		break;
	    case 'p':
		args->argv[i].p = va_arg(ap, void *);
		break;
	    default:
		fprintf(stderr, "error: unsupported type '%c' as "
				"a hook argument\n", argt[i]);
		break;
	}
    }
    return args;
}

static void rpmhookTableCallArgs(rpmhookTable *table, const char *name,
			rpmhookArgs args)
{
    int n = rpmhookTableFindBucket(table, name);
    rpmhookItem item = (*table)->bucket[n].item;
    rpmhookItem next;
    while (item) {
	next = item->next;
	if (item->func(args, item->data) != 0)
	    break;
	item = next;
    }
}

static rpmhookTable globalTable = NULL;

void rpmhookRegister(const char *name, rpmhookFunc func, void *data)
{
    if (globalTable == NULL)
	globalTable = rpmhookTableNew(RPMHOOK_TABLE_INITSIZE);
    rpmhookTableAddItem(&globalTable, name, func, data);
}

void rpmhookUnregister(const char *name, rpmhookFunc func, void *data)
{
    if (globalTable != NULL)
	rpmhookTableDelItem(&globalTable, name, func, data, 1, 1);
}

void rpmhookUnregisterAny(const char *name, rpmhookFunc func)
{
    if (globalTable != NULL)
	rpmhookTableDelItem(&globalTable, name, func, NULL, 1, 0);
}

void rpmhookUnregisterAll(const char *name)
{
    if (globalTable != NULL)
	rpmhookTableDelItem(&globalTable, name, NULL, NULL, 0, 0);
}

void rpmhookCall(const char *name, const char *argt, ...)
{
    if (globalTable != NULL) {
	rpmhookArgs args;
	va_list ap;
	va_start(ap, argt);
	args = rpmhookArgsParse(argt, ap);
	rpmhookTableCallArgs(&globalTable, name, args);
	(void) rpmhookArgsFree(args);
	va_end(ap);
    }
}

void rpmhookCallArgs(const char *name, rpmhookArgs args)
{
    if (globalTable != NULL)
	rpmhookTableCallArgs(&globalTable, name, args);
}
