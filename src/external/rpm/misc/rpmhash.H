/**
 * \file lib/rpmhash.h
 * Hash table implemenation.
 */

#include <string.h>
// Hackery to make sure that macros get expanded
#define __JOIN(a,b) a##b
#define JOIN(a,b) __JOIN(a,b)
#define HASHPREFIX(name) JOIN(HASHTYPE,name)
#define HASHSTRUCT JOIN(HASHTYPE,_s)

typedef struct HASHSTRUCT * HASHTYPE;

/* function pointer types to deal with the datatypes the hash works with */

#define hashFunctionType JOIN(HASHTYPE,HashFunctionType)
#define hashEqualityType JOIN(HASHTYPE,HashEqualityType)
#define hashFreeKey JOIN(HASHTYPE,FreeKey)

typedef unsigned int (*hashFunctionType) (HTKEYTYPE string);
typedef int (*hashEqualityType) (HTKEYTYPE key1, HTKEYTYPE key2);
typedef HTKEYTYPE (*hashFreeKey) (HTKEYTYPE);

#ifdef HTDATATYPE
#define hashFreeData JOIN(HASHTYPE,FreeData)
typedef HTDATATYPE (*hashFreeData) (HTDATATYPE);
#endif

/**
 * Create hash table.
 * If keySize > 0, the key is duplicated within the table (which costs
 * memory, but may be useful anyway.
 * @param numBuckets    number of hash buckets
 * @param fn            function to generate hash value for key
 * @param eq            function to compare hash keys for equality
 * @param freeKey       function to free the keys or NULL
 * @param freeData      function to free the data or NULL
 * @return		pointer to initialized hash table
 */
RPM_GNUC_INTERNAL
HASHTYPE  HASHPREFIX(Create)(int numBuckets,
			     hashFunctionType fn, hashEqualityType eq,
			     hashFreeKey freeKey
#ifdef HTDATATYPE
, hashFreeData freeData
#endif
);

/**
 * Destroy hash table.
 * @param ht            pointer to hash table
 * @return		NULL always
 */
RPM_GNUC_INTERNAL
HASHTYPE  HASHPREFIX(Free)( HASHTYPE ht);

/**
 * Remove all entries from the hash table.
 * @param ht            pointer to hash table
 */
RPM_GNUC_INTERNAL
void HASHPREFIX(Empty)(HASHTYPE ht);

/**
 * Calculate hash for key.
 * @param @ht		pointer to hash table
 * @param @key		key
 */
RPM_GNUC_INTERNAL
unsigned int HASHPREFIX(KeyHash)(HASHTYPE ht, HTKEYTYPE key);

/**
 * Add item to hash table.
 * @param ht            pointer to hash table
 * @param key           key
 * @param data          data value
 */
RPM_GNUC_INTERNAL
void  HASHPREFIX(AddEntry)(HASHTYPE ht, HTKEYTYPE key
#ifdef HTDATATYPE
, HTDATATYPE data
#endif
);

/* Add item to hash table with precalculated key hash. */
RPM_GNUC_INTERNAL
void  HASHPREFIX(AddHEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash
#ifdef HTDATATYPE
, HTDATATYPE data
#endif
);

/**
 * Retrieve item from hash table.
 * @param ht            pointer to hash table
 * @param key           key value
 * @retval data         address to store data value from bucket
 * @retval dataCount    address to store data value size from bucket
 * @retval tableKey     address to store key value from bucket (may be NULL)
 * @return		1 on success, 0 if the item is not found.
 */
RPM_GNUC_INTERNAL
int  HASHPREFIX(GetEntry)(HASHTYPE ht, HTKEYTYPE key,
#ifdef HTDATATYPE
		HTDATATYPE** data,
		int * dataCount,
#endif
		HTKEYTYPE* tableKey);

/* Retrieve item from hash table with precalculated key hash. */
RPM_GNUC_INTERNAL
int  HASHPREFIX(GetHEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash,
#ifdef HTDATATYPE
		HTDATATYPE** data,
		int * dataCount,
#endif
		HTKEYTYPE* tableKey);

/**
 * Check for key in hash table.
 * @param ht            pointer to hash table
 * @param key           key value
 * @return		1 if the key is present, 0 otherwise
 */
RPM_GNUC_INTERNAL
int  HASHPREFIX(HasEntry)(HASHTYPE ht, HTKEYTYPE key);

/* Check for key in hash table with precalculated key hash. */
RPM_GNUC_INTERNAL
int  HASHPREFIX(HasHEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash);

/**
 * How many buckets are currently allocated (result is implementation 
 * dependent)
 * @param ht            pointer to hash table
 * @result		number of buckets allocated
 */
RPM_GNUC_INTERNAL
unsigned int HASHPREFIX(NumBuckets)(HASHTYPE ht);

/**
 * How many buckets are used (result is implementation dependent)
 * @param ht            pointer to hash table
 * @result		number of buckets used
 */
RPM_GNUC_INTERNAL
unsigned int HASHPREFIX(UsedBuckets)(HASHTYPE ht);

/**
 * How many (unique) keys have been added to the hash table
 * @param ht            pointer to hash table
 * @result		number of unique keys
 */
RPM_GNUC_INTERNAL
unsigned int HASHPREFIX(NumKeys)(HASHTYPE ht);

#ifdef HTDATATYPE
/**
 * How many data entries have been added to the hash table
 * @param ht            pointer to hash table
 * @result		number of data entries
 */
RPM_GNUC_INTERNAL
unsigned int HASHPREFIX(NumData)(HASHTYPE ht);
#endif

/**
 * Print statistics about the hash to stderr
 * This is for debugging only
 * @param ht            pointer to hash table
 */
RPM_GNUC_INTERNAL
void HASHPREFIX(PrintStats)(HASHTYPE ht);
