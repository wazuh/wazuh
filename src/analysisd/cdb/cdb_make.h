/* Public domain */
/* Copyright (C) 2015-2019, Wazuh Inc. */
/* Adapted from DJB's original cdb-0.75 package */

#ifndef CDB_MAKE_H
#define CDB_MAKE_H

#include <stdio.h>
#include "uint32.h"

#define CDB_HPLIST 1000

struct cdb_hp {
    uint32 h;
    uint32 p;
} ;

struct cdb_hplist {
    struct cdb_hp hp[CDB_HPLIST];
    struct cdb_hplist *next;
    int num;
} ;

struct cdb_make {
    /* char bspace[8192]; */
    char final[2048];
    uint32 count[256];
    uint32 start[256];
    struct cdb_hplist *head;
    struct cdb_hp *split; /* includes space for hash */
    struct cdb_hp *hash;
    uint32 numentries;
    /* buffer b; */
    uint32 pos;
    /* int fd; */
    FILE *fp;
} ;

extern int cdb_make_start(struct cdb_make *, FILE *);
extern int cdb_make_addbegin(struct cdb_make *, unsigned int, unsigned int);
extern int cdb_make_addend(struct cdb_make *, unsigned int, unsigned int, uint32);
extern int cdb_make_add(struct cdb_make *, char *, unsigned int, char *, unsigned int);
extern int cdb_make_finish(struct cdb_make *);

#endif
