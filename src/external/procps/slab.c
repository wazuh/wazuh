/*
 * slab.c - slab related functions for libproc
 *
 * Chris Rivera <cmrivera@ufl.edu>
 * Robert Love <rml@tech9.net>
 *
 * This program is licensed under the GNU Library General Public License, v2
 *
 * Copyright (C) 2003 Chris Rivera
 * Copyright 2004, Albert Cahalan
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>

#include "slab.h"
#include "procps.h"

#define SLABINFO_LINE_LEN	2048
#define SLABINFO_VER_LEN	100
#define SLABINFO_FILE		"/proc/slabinfo"

static struct slab_info *free_index;

/*
 * get_slabnode - allocate slab_info structures using a free list
 *
 * In the fast path, we simply return a node off the free list.  In the slow
 * list, we malloc() a new node.  The free list is never automatically reaped,
 * both for simplicity and because the number of slab caches is fairly
 * constant.
 */
static struct slab_info *get_slabnode(void)
{
	struct slab_info *node;

	if (free_index) {
		node = free_index;
		free_index = free_index->next;
	} else {
		node = malloc(sizeof(struct slab_info));
		if (!node)
			perror("malloc");
	}

	return node;
}

/*
 * slab_badname_detect - return true if current slab was declared with
 *                       whitespaces for instance
 *			 FIXME :Other cases ?
 */

static int slab_badname_detect(const char *restrict buffer)
{
	int numberarea=0;
	while (*buffer){
		if((*buffer)==' ')
			numberarea=1;
		if(isalpha(*buffer)&&numberarea)
			return 1;
		buffer++;
	}
	return 0;
}

/*
 * put_slabinfo - return all allocated nodes to the free list
 */
void put_slabinfo(struct slab_info *head)
{
	free_index = head;
}

/*
 * free_slabinfo - deallocate the memory associated with each node in the
 * slab_info linked list
 */
void free_slabinfo(struct slab_info *list)
{
	while (list) {
		struct slab_info *temp = list->next;
		free(list);
		list = temp;
	}
}

/* parse_slabinfo20 - actual parse routine for slabinfo 2.x (2.6 kernels)
   Note: difference between 2.0 and 2.1 is in the ": globalstat" part where version 2.1
   has extra column <nodeallocs>. We don't use ": globalstat" part in both versions.

   Formats (we don't use "statistics" extensions)

    slabinfo - version: 2.1
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> \
    : tunables <batchcount> <limit> <sharedfactor> \
    : slabdata <active_slabs> <num_slabs> <sharedavail>

    slabinfo - version: 2.1 (statistics)
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> \
    : tunables <batchcount> <limit> <sharedfactor> \
    : slabdata <active_slabs> <num_slabs> <sharedavail> \
    : globalstat <listallocs> <maxobjs> <grown> <reaped> <error> <maxfreeable> <freelimit> <nodeallocs> \
    : cpustat <allochit> <allocmiss> <freehit> <freemiss>

    slabinfo - version: 2.0
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> \
    : tunables <batchcount> <limit> <sharedfactor> \
    : slabdata <active_slabs> <num_slabs> <sharedavail>

    slabinfo - version: 2.0 (statistics)
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> \
    : tunables <batchcount> <limit> <sharedfactor> \
    : slabdata <active_slabs> <num_slabs> <sharedavail> \
    : globalstat <listallocs> <maxobjs> <grown> <reaped> <error> <maxfreeable> <freelimit> \
    : cpustat <allochit> <allocmiss> <freehit> <freemiss>
*/
static int parse_slabinfo20(struct slab_info **list, struct slab_stat *stats,
				FILE *f)
{
	struct slab_info *curr = NULL, *prev = NULL;
	char buffer[SLABINFO_LINE_LEN];
	int entries = 0;
	int page_size = getpagesize();

	stats->min_obj_size = INT_MAX;
	stats->max_obj_size = 0;

	while (fgets(buffer, SLABINFO_LINE_LEN, f)) {
		int assigned;

		if (buffer[0] == '#')
			continue;

		curr = get_slabnode();
		if (!curr)
			break;

		if (entries++ == 0)
			*list = curr;
		else
			prev->next = curr;

		assigned = sscanf(buffer, "%" STRINGIFY(SLAB_INFO_NAME_LEN)
				"s %d %d %d %d %d : tunables %*d %*d %*d : \
				slabdata %d %d %*d", curr->name,
				&curr->nr_active_objs, &curr->nr_objs,
				&curr->obj_size, &curr->objs_per_slab,
				&curr->pages_per_slab, &curr->nr_active_slabs,
				&curr->nr_slabs);

		if (assigned < 8) {
			fprintf(stderr, "unrecognizable data in slabinfo!\n");
			curr = NULL;
			break;
		}

		if (curr->obj_size < stats->min_obj_size)
			stats->min_obj_size = curr->obj_size;
		if (curr->obj_size > stats->max_obj_size)
			stats->max_obj_size = curr->obj_size;

		curr->cache_size = (unsigned long)curr->nr_slabs * curr->pages_per_slab * page_size;

		if (curr->nr_objs) {
			curr->use = 100 * curr->nr_active_objs / curr->nr_objs;
			stats->nr_active_caches++;
		} else
			curr->use = 0;

		stats->nr_objs += curr->nr_objs;
		stats->nr_active_objs += curr->nr_active_objs;
		stats->total_size += (unsigned long)curr->nr_objs * curr->obj_size;
		stats->active_size += (unsigned long)curr->nr_active_objs * curr->obj_size;
		stats->nr_pages += curr->nr_slabs * curr->pages_per_slab;
		stats->nr_slabs += curr->nr_slabs;
		stats->nr_active_slabs += curr->nr_active_slabs;

		prev = curr;
	}

	if (!curr) {
		fprintf(stderr, "\rerror reading slabinfo!\n");
		return 1;
	}

	curr->next = NULL;
	stats->nr_caches = entries;
	if (stats->nr_objs)
		stats->avg_obj_size = stats->total_size / stats->nr_objs;

	return 0;
}

/*
 * parse_slabinfo11 - actual parsing routine for slabinfo 1.1 (2.4 kernels)
 */
static int parse_slabinfo11(struct slab_info **list, struct slab_stat *stats,
				FILE *f)
{
	struct slab_info *curr = NULL, *prev = NULL;
	char buffer[SLABINFO_LINE_LEN];
	int entries = 0;
	int page_size = getpagesize();

	stats->min_obj_size = INT_MAX;
	stats->max_obj_size = 0;

	while (fgets(buffer, SLABINFO_LINE_LEN, f)) {
		int assigned;

		curr = get_slabnode();
		if (!curr)
			break;

		if (entries++ == 0)
			*list = curr;
		else
			prev->next = curr;

		assigned = sscanf(buffer, "%" STRINGIFY(SLAB_INFO_NAME_LEN)
				"s %d %d %d %d %d %d",
				curr->name, &curr->nr_active_objs,
				&curr->nr_objs, &curr->obj_size,
				&curr->nr_active_slabs, &curr->nr_slabs,
				&curr->pages_per_slab);

		if (assigned < 6) {
			fprintf(stderr, "unrecognizable data in  your slabinfo version 1.1\n\r");
			if(slab_badname_detect(buffer))
				fprintf(stderr, "Found an error in cache name at line %s\n", buffer);
			curr = NULL;
			break;
		}

		if (curr->obj_size < stats->min_obj_size)
			stats->min_obj_size = curr->obj_size;
		if (curr->obj_size > stats->max_obj_size)
			stats->max_obj_size = curr->obj_size;

		curr->cache_size = (unsigned long)curr->nr_slabs * curr->pages_per_slab * page_size;

		if (curr->nr_objs) {
			curr->use = 100 * curr->nr_active_objs / curr->nr_objs;
			stats->nr_active_caches++;
		} else
			curr->use = 0;

		if (curr->obj_size)
			curr->objs_per_slab = curr->pages_per_slab *
					page_size / curr->obj_size;

		stats->nr_objs += curr->nr_objs;
		stats->nr_active_objs += curr->nr_active_objs;
		stats->total_size += (unsigned long)curr->nr_objs * curr->obj_size;
		stats->active_size += (unsigned long)curr->nr_active_objs * curr->obj_size;
		stats->nr_pages += curr->nr_slabs * curr->pages_per_slab;
		stats->nr_slabs += curr->nr_slabs;
		stats->nr_active_slabs += curr->nr_active_slabs;

		prev = curr;
	}

	if (!curr) {
		fprintf(stderr, "\rerror reading slabinfo!\n");
		return 1;
	}

	curr->next = NULL;
	stats->nr_caches = entries;
	if (stats->nr_objs)
		stats->avg_obj_size = stats->total_size / stats->nr_objs;

	return 0;
}

/*
 * parse_slabinfo10 - actual parsing routine for slabinfo 1.0 (2.2 kernels)
 *
 * Not yet implemented.  Please feel free.
 */
static int parse_slabinfo10(struct slab_info **list, struct slab_stat *stats,
				FILE *f)
{
	(void) list, (void) stats, (void) f;
	fprintf(stderr, "slabinfo version 1.0 not yet supported\n");
	return 1;
}

/*
 * slabinfo - parse the system's slabinfo and fill out both a linked list of
 * slab_info structures and the slab_stat structure
 *
 * The function returns zero on success, in which case 'list' and 'stats' are
 * valid.  Nonzero is returned on failure and the state of 'list' and 'stats'
 * are undefined.
 */
int get_slabinfo(struct slab_info **list, struct slab_stat *stats)
{
	FILE *slabfile;
	char buffer[SLABINFO_VER_LEN];
	int major, minor, ret = 0;

	slabfile = fopen(SLABINFO_FILE, "r");
	if (!slabfile) {
		perror("fopen " SLABINFO_FILE);
		return 1;
	}

	if (!fgets(buffer, SLABINFO_VER_LEN, slabfile)) {
		fprintf(stderr, "cannot read from slabinfo\n");
		return 1;
	}

	if (sscanf(buffer, "slabinfo - version: %d.%d", &major, &minor) != 2) {
		fprintf(stderr, "not the good old slabinfo we know\n");
		return 1;
	}

	if (major == 2)
		ret = parse_slabinfo20(list, stats, slabfile);
	else if (major == 1 && minor == 1)
		ret = parse_slabinfo11(list, stats, slabfile);
	else if (major == 1 && minor == 0)
		ret = parse_slabinfo10(list, stats, slabfile);
	else {
		fprintf(stderr, "unrecognizable slabinfo version\n");
		return 1;
	}

	fclose(slabfile);

	return ret;
}
