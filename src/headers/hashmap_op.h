#ifndef HASHMAP_OP_H
#define HASHMAP_OP_H

#include <stddef.h>

/**
 * @file hashmap_op.h
 * @brief Open-addressing hash map with tombstones (C API).
 *
 * This header exposes a minimal hash map interface using an array of buckets
 * (entries) with open addressing and tombstones for deletions.
 *
 * ### Design notes
 * - **Buckets:** Each bucket holds a (key, value) pair. Empty buckets have
 *   `key == NULL`. Deleted buckets (tombstones) have `key == (char*)-1`.
 * - **Capacity invariant:** `capacity` is always a power of two and at least 16.
 * - **Sizes:** `size` counts live keys only (excludes tombstones).
 *   `tombstones` counts deleted buckets that may be reused by future inserts.
 * - **Iteration:** The simple iterator skips empty buckets and tombstones.
 * - **Thread-safety:** No internal synchronization is provided; use external
 *   synchronization if accessed concurrently.
 */

/**
 * @brief Single hash map bucket.
 *
 * Empty bucket: `key == NULL`
 * Tombstone (deleted): `key == (char*)-1`
 */
typedef struct hm_entry
{
    char* key;   ///< NULL = empty; (char*)-1 = tombstone (deleted)
    void* value; ///< Associated value pointer
} hm_entry_t;

/**
 * @brief Hash map container.
 *
 * @invariant capacity is a power of two and >= 16.
 * @note `entries` is an array with length `capacity`.
 */
typedef struct hashmap
{
    hm_entry_t* entries; ///< Bucket array of length `capacity`
    size_t capacity;     ///< Power of two (>= 16)
    size_t size;         ///< Number of live keys (excludes tombstones)
    size_t tombstones;   ///< Number of deleted buckets (tombstones)
} hashmap_t;

/**
 * @brief Forward-only iterator over occupied entries (skips empty/tombstones).
 */
typedef struct hm_iter
{
    const hashmap_t* hm; ///< Hash map being iterated
    size_t idx;          ///< Current bucket index (0..capacity)
} hm_iter_t;

/**
 * @brief Initialize a hash map.
 *
 * @param hm Pointer to an uninitialized hashmap_t.
 * @param initial_capacity Desired initial capacity (the actual capacity will
 *        satisfy the invariant: power of two and >= 16).
 * @retval 0 on success
 * @retval -1 on allocation or parameter error
 */
int hm_init(hashmap_t* hm, size_t initial_capacity);

/**
 * @brief Destroy a hash map and release its internal storage.
 *
 * @param hm Pointer to a previously initialized hash map.
 * @note Does NOT free user-provided keys/values unless the implementation
 *       explicitly documents ownership transfer. Caller is responsible for
 *       disposing pointed data if needed.
 */
void hm_destroy(hashmap_t* hm);

/**
 * @brief Look up a key.
 *
 * @param hm         Target hash map.
 * @param key        NUL-terminated key string.
 * @param out_value  Output: set to the stored value pointer when found.
 * @retval 1 if found (and *out_value set)
 * @retval 0 if not found
 */
int hm_get(hashmap_t* hm, const char* key, void** out_value);

/**
 * @brief Insert or replace a (key, value) pair.
 *
 * @param hm    Target hash map.
 * @param key   NUL-terminated key string.
 * @param value Value pointer to associate.
 * @retval 0 if a new key was inserted
 * @retval 1 if an existing key was replaced
 * @retval -1 on error (e.g., allocation failure)
 *
 * @note Key and value ownership/lifetime are caller-defined unless specified
 *       otherwise by the implementation. Keys must remain valid for the
 *       lifetime of the entry if the map stores pointers directly.
 */
int hm_put(hashmap_t* hm, const char* key, void* value);

/**
 * @brief Delete a key if present.
 *
 * @param hm  Target hash map.
 * @param key NUL-terminated key string.
 * @retval 1 if a key was found and deleted
 * @retval 0 if the key did not exist
 */
int hm_del(hashmap_t* hm, const char* key);

/**
 * @brief Initialize an iterator to traverse live (occupied) entries.
 *
 * The iterator skips empty buckets and tombstones.
 *
 * @param hm Hash map to iterate.
 * @param it Iterator to initialize.
 */
static inline void hm_iter_init(const hashmap_t* hm, hm_iter_t* it)
{
    it->hm = hm;
    it->idx = 0;
}

/**
 * @brief Advance the iterator and yield the next (key, value) pair.
 *
 * @param it         Iterator state.
 * @param out_key    Output: pointer to the entry key.
 * @param out_value  Output: pointer to the entry value.
 * @retval 1 if an element was produced
 * @retval 0 when the iteration is finished
 *
 * @warning The returned `key` pointer is owned by the hash map. Do NOT free it.
 */
int hm_iter_next(hm_iter_t* it, const char** out_key, void** out_value);

/**
 * @brief Get the number of live keys (excludes tombstones).
 *
 * @param hm Hash map.
 * @return Count of live keys; 0 if `hm` is NULL.
 */
static inline size_t hm_size(const hashmap_t* hm)
{
    return hm ? hm->size : 0;
}

#endif // HASHMAP_OP_H
