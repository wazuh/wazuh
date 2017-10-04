#ifndef _PROC_SLAB_H
#define _PROC_SLAB_H

#define SLAB_INFO_NAME_LEN      64

struct slab_info {
	char name[SLAB_INFO_NAME_LEN];  /* name of this cache */
	struct slab_info *next;
	unsigned long cache_size;       /* size of entire cache */
	unsigned nr_objs;               /* number of objects in this cache */
	unsigned nr_active_objs;        /* number of active objects */
	unsigned obj_size;              /* size of each object */
	unsigned objs_per_slab;         /* number of objects per slab */
	unsigned pages_per_slab;        /* number of pages per slab */
	unsigned nr_slabs;              /* number of slabs in this cache */
	unsigned nr_active_slabs;       /* number of active slabs */
	unsigned use;                   /* percent full: total / active */
};

struct slab_stat {
	unsigned long total_size;       /* size of all objects */
	unsigned long active_size;      /* size of all active objects */
	unsigned nr_objs;               /* number of objects, among all caches */
	unsigned nr_active_objs;        /* number of active objects, among all caches */
	unsigned nr_pages;              /* number of pages consumed by all objects */
	unsigned nr_slabs;              /* number of slabs, among all caches */
	unsigned nr_active_slabs;       /* number of active slabs, among all caches */
	unsigned nr_caches;             /* number of caches */
	unsigned nr_active_caches;      /* number of active caches */
	unsigned avg_obj_size;          /* average object size */
	unsigned min_obj_size;          /* size of smallest object */
	unsigned max_obj_size;          /* size of largest object */
};

extern void put_slabinfo(struct slab_info *);
extern void free_slabinfo(struct slab_info *);
extern int get_slabinfo(struct slab_info **, struct slab_stat *);

#endif /* _PROC_SLAB_H */
