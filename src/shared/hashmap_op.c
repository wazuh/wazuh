
#include "hashmap_op.h"
#include "shared.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HM_LOAD_NUM 3  // numerator of load factor (3/4)
#define HM_LOAD_DEN 4  // denominator of load factor (3/4)
#define HM_MIN_CAP  16 // minimum table capacity

// ---------------------- Hash and helpers ----------------------

static uint64_t fnv1a64(const char* s)
{
    // FNV-1a 64-bit hash, fast and simple non-cryptographic
    uint64_t h = 1469598103934665603ULL; // offset basis
    for (; *s; ++s)
    {
        h ^= (unsigned char)(*s);
        h *= 1099511628211ULL; // FNV prime
    }
    return h;
}

static size_t next_pow2(size_t x)
{
    // Round up to next power-of-two, with HM_MIN_CAP floor
    size_t p = HM_MIN_CAP;
    while (p < x) p <<= 1;
    return p;
}

// Slot state checks
static inline int is_empty(const hm_entry_t* e)
{
    return e->key == NULL;
}
static inline int is_tomb(const hm_entry_t* e)
{
    return e->key == (char*)-1;
}
static inline int is_occupied(const hm_entry_t* e)
{
    return e->key && e->key != (char*)-1;
}

// ---------------------- Core operations ----------------------

static int hm_rehash(hashmap_t* hm, size_t new_cap)
{
    // Rebuilds the table with a new capacity, compacting out tombstones
    hm_entry_t* old = hm->entries;
    size_t old_cap = hm->capacity;

    hm_entry_t* neu;
    os_calloc(new_cap, sizeof(hm_entry_t), neu);
    if (!neu)
        return -1;

    hm->entries = neu;
    hm->capacity = new_cap;
    hm->size = 0;
    hm->tombstones = 0;

    // Reinsert occupied entries (keys are already owned, not duplicated again)
    if (old)
    {
        for (size_t i = 0; i < old_cap; ++i)
        {
            if (is_occupied(&old[i]))
            {
                uint64_t h = fnv1a64(old[i].key);
                size_t m = new_cap - 1;
                size_t idx = (size_t)(h & m);

                // Linear probe until an empty slot is found
                while (!is_empty(&neu[idx]))
                {
                    idx = (idx + 1) & m;
                }
                neu[idx].key = old[i].key;
                neu[idx].value = old[i].value;
                hm->size++;
            }
        }
        os_free(old);
    }
    return 0;
}

int hm_init(hashmap_t* hm, size_t initial_capacity)
{
    // Initialize map with capacity rounded up to power-of-two
    if (!hm)
        return -1;
    size_t cap = next_pow2(initial_capacity ? initial_capacity : HM_MIN_CAP);
    os_calloc(cap, sizeof(hm_entry_t), hm->entries);
    if (!hm->entries)
        return -1;
    hm->capacity = cap;
    hm->size = 0;
    hm->tombstones = 0;
    return 0;
}

void hm_destroy(hashmap_t* hm)
{
    // Free all keys and the table; values are not freed (caller owns them)
    if (!hm)
        return;
    if (hm->entries)
    {
        for (size_t i = 0; i < hm->capacity; ++i)
        {
            if (is_occupied(&hm->entries[i]))
            {
                os_free(hm->entries[i].key);
            }
        }
        os_free(hm->entries);
    }
    hm->entries = NULL;
    hm->capacity = hm->size = hm->tombstones = 0;
}

static int hm_maybe_grow(hashmap_t* hm)
{
    // Grow if (size + tombstones)/capacity >= 0.75
    if (((hm->size + hm->tombstones) * HM_LOAD_DEN) >= (hm->capacity * HM_LOAD_NUM))
    {
        return hm_rehash(hm, hm->capacity << 1);
    }
    return 0;
}

int hm_get(hashmap_t* hm, const char* key, void** out_value)
{
    // Lookup by key, return 1 if found, 0 otherwise
    if (!hm || !key)
        return 0;
    if (hm->capacity == 0)
        return 0;

    uint64_t h = fnv1a64(key);
    size_t m = hm->capacity - 1;
    size_t idx = (size_t)(h & m);

    for (;;)
    {
        hm_entry_t* e = &hm->entries[idx];
        if (is_empty(e))
        {
            return 0; // not present
        }
        if (is_occupied(e) && strcmp(e->key, key) == 0)
        {
            if (out_value)
                *out_value = e->value;
            return 1;
        }
        idx = (idx + 1) & m; // continue probing
    }
}

int hm_put(hashmap_t* hm, const char* key, void* value)
{
    // Insert new key or update existing
    if (!hm || !key)
        return -1;
    if (hm_maybe_grow(hm) != 0)
        return -1;

    uint64_t h = fnv1a64(key);
    size_t m = hm->capacity - 1;
    size_t idx = (size_t)(h & m);

    hm_entry_t* first_tomb = NULL;

    for (;;)
    {
        hm_entry_t* e = &hm->entries[idx];
        if (is_empty(e))
        {
            // insert into empty slot (reuse tombstone if found earlier)
            hm_entry_t* target = first_tomb ? first_tomb : e;
            if (first_tomb)
                hm->tombstones--;
            os_strdup(key, target->key);
            if (!target->key)
                return -1;
            target->value = value;
            hm->size++;
            return 0; // inserted
        }
        else if (is_tomb(e))
        {
            // remember first tombstone seen
            if (!first_tomb)
                first_tomb = e;
        }
        else if (strcmp(e->key, key) == 0)
        {
            // update existing
            e->value = value;
            return 1;
        }
        idx = (idx + 1) & m; // keep probing
    }
}

int hm_del(hashmap_t* hm, const char* key)
{
    // Delete key: free its string, mark as tombstone
    if (!hm || !key || hm->size == 0)
        return 0;

    uint64_t h = fnv1a64(key);
    size_t m = hm->capacity - 1;
    size_t idx = (size_t)(h & m);

    for (;;)
    {
        hm_entry_t* e = &hm->entries[idx];
        if (is_empty(e))
            return 0; // not found
        if (is_occupied(e) && strcmp(e->key, key) == 0)
        {
            os_free(e->key);
            e->key = (char*)-1; // tombstone marker
            e->value = NULL;
            hm->size--;
            hm->tombstones++;
            return 1;
        }
        idx = (idx + 1) & m;
    }
}

int hm_iter_next(hm_iter_t* it, const char** out_key, void** out_value)
{
    // Iterate until next occupied slot is found
    if (!it || !it->hm || it->idx > it->hm->capacity)
        return 0;

    while (it->idx < it->hm->capacity)
    {
        hm_entry_t* e = &it->hm->entries[it->idx++];
        if (e->key && e->key != (char*)-1)
        {
            if (out_key)
                *out_key = e->key;
            if (out_value)
                *out_value = e->value;
            return 1;
        }
    }
    return 0;
}
