#include "system.h"
#include <string.h>
#include <stdlib.h>
#include "dbiset.h"
#include "debug.h"

dbiIndexSet dbiIndexSetNew(unsigned int sizehint)
{
    dbiIndexSet set = (dbiIndexSet)xcalloc(1, sizeof(*set));
    if (sizehint > 0)
	dbiIndexSetGrow(set, sizehint);
    return set;
}

/* 
 * Ensure sufficient memory for nrecs of new records in dbiIndexSet.
 * Allocate in power of two sizes to avoid memory fragmentation, so
 * realloc is not always needed.
 */
void dbiIndexSetGrow(dbiIndexSet set, unsigned int nrecs)
{
    size_t need = (set->count + nrecs) * sizeof(*(set->recs));
    size_t alloced = set->alloced ? set->alloced : 1 << 4;

    while (alloced < need)
	alloced <<= 1;

    if (alloced != set->alloced) {
	set->recs = xrealloc(set->recs, alloced);
	set->alloced = alloced;
    }
}

static int hdrNumCmp(const void * one, const void * two)
{
    const struct dbiIndexItem_s *a = (const struct dbiIndexItem_s *)one;
    const struct dbiIndexItem_s *b = (const struct dbiIndexItem_s *)two;
    if (a->hdrNum - b->hdrNum != 0)
	return a->hdrNum - b->hdrNum;
    return a->tagNum - b->tagNum;
}

void dbiIndexSetSort(dbiIndexSet set)
{
    /*
     * mergesort is much (~10x with lots of identical basenames) faster
     * than pure quicksort, but glibc uses msort_with_tmp() on stack.
     */
    if (set && set->recs && set->count > 1) {
#ifdef HAVE_MERGESORT
	mergesort(set->recs, set->count, sizeof(*set->recs), hdrNumCmp);
#else
	qsort(set->recs, set->count, sizeof(*set->recs), hdrNumCmp);
#endif
    }
}

void dbiIndexSetUniq(dbiIndexSet set, int sorted)
{
    unsigned int from;
    unsigned int to = 0;
    unsigned int num = set->count;

    if (set->count < 2)
	return;

    if (!sorted)
	dbiIndexSetSort(set);

    for (from = 0; from < num; from++) {
	if (from > 0 && set->recs[from - 1].hdrNum == set->recs[from].hdrNum) {
	    set->count--;
	    continue;
	}
	if (from != to)
	    set->recs[to] = set->recs[from]; /* structure assignment */
	to++;
    }
}

int dbiIndexSetAppend(dbiIndexSet set, dbiIndexItem recs,
		      unsigned int nrecs, int sortset)
{
    if (set == NULL || recs == NULL)
	return 1;

    if (nrecs) {
	dbiIndexSetGrow(set, nrecs);
	memcpy(set->recs + set->count, recs, nrecs * sizeof(*(set->recs)));
	set->count += nrecs;
    }
    
    if (sortset && set->count > 1)
	qsort(set->recs, set->count, sizeof(*(set->recs)), hdrNumCmp);

    return 0;
}

int dbiIndexSetAppendSet(dbiIndexSet set, dbiIndexSet oset, int sortset)
{
    if (oset == NULL)
	return 1;
    return dbiIndexSetAppend(set, oset->recs, oset->count, sortset);
}

int dbiIndexSetAppendOne(dbiIndexSet set, unsigned int hdrNum,
			 unsigned int tagNum, int sortset)
{
    if (set == NULL)
	return 1;
    dbiIndexSetGrow(set, 1);

    set->recs[set->count].hdrNum = hdrNum;
    set->recs[set->count].tagNum = tagNum;
    set->count += 1;

    if (sortset && set->count > 1)
	qsort(set->recs, set->count, sizeof(*(set->recs)), hdrNumCmp);

    return 0;
}

int dbiIndexSetPrune(dbiIndexSet set, dbiIndexItem recs,
		     unsigned int nrecs, int sorted)
{
    unsigned int from;
    unsigned int to = 0;
    unsigned int num = set->count;
    unsigned int numCopied = 0;
    size_t recsize = sizeof(*recs);

    if (num == 0 || nrecs == 0)
	return 1;

    if (nrecs > 1 && !sorted)
	qsort(recs, nrecs, recsize, hdrNumCmp);

    for (from = 0; from < num; from++) {
	if (bsearch(&set->recs[from], recs, nrecs, recsize, hdrNumCmp)) {
	    set->count--;
	    continue;
	}
	if (from != to)
	    set->recs[to] = set->recs[from]; /* structure assignment */
	to++;
	numCopied++;
    }
    return (numCopied == num);
}

int dbiIndexSetPruneSet(dbiIndexSet set, dbiIndexSet oset, int sortset)
{
    if (oset == NULL)
	return 1;
    return dbiIndexSetPrune(set, oset->recs, oset->count, sortset);
}

int dbiIndexSetFilter(dbiIndexSet set, dbiIndexItem recs,
                        unsigned int nrecs, int sorted)
{
    unsigned int from;
    unsigned int to = 0;
    unsigned int num = set->count;
    unsigned int numCopied = 0;
    size_t recsize = sizeof(*recs);

    if (num == 0 || nrecs == 0) {
	set->count = 0;
	return num ? 0 : 1;
    }
    if (nrecs > 1 && !sorted)
	qsort(recs, nrecs, recsize, hdrNumCmp);
    for (from = 0; from < num; from++) {
	if (!bsearch(&set->recs[from], recs, nrecs, recsize, hdrNumCmp)) {
	    set->count--;
	    continue;
	}
	if (from != to)
	    set->recs[to] = set->recs[from]; /* structure assignment */
	to++;
	numCopied++;
    }
    return (numCopied == num);
}

int dbiIndexSetFilterSet(dbiIndexSet set, dbiIndexSet oset, int sorted)
{
    return dbiIndexSetFilter(set, oset->recs, oset->count, sorted);
}

unsigned int dbiIndexSetCount(dbiIndexSet set)
{
    return (set != NULL) ? set->count : 0;
}

unsigned int dbiIndexRecordOffset(dbiIndexSet set, unsigned int recno)
{
    return set->recs[recno].hdrNum;
}

unsigned int dbiIndexRecordFileNumber(dbiIndexSet set, unsigned int recno)
{
    return set->recs[recno].tagNum;
}

dbiIndexSet dbiIndexSetFree(dbiIndexSet set)
{
    if (set) {
	free(set->recs);
	memset(set, 0, sizeof(*set)); /* trash and burn */
	free(set);
    }
    return NULL;
}

