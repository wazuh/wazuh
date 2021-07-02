/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "mem_op.h"
#include "shared.h"

/* Add pointer to array */
void **os_AddPtArray(void *pt, void **array)
{
    size_t i = 0;
    void **ret = NULL;

    if (array) {
        while (array[i]) {
            i++;
        }
    }

    os_realloc(array, (i + 2)*sizeof(void *), ret);
    ret[i] = pt;
    ret[i + 1] = NULL;

    return (ret);
}

/* Add a string to an array */
char **os_AddStrArray(const char *str, char **array)
{
    size_t i = 0;
    char **ret = NULL;
    if (array) {
        while (array[i]) {
            i++;
        }
    }

    os_realloc(array, (i + 2)*sizeof(char *), ret);
    os_strdup(str, ret[i]);
    ret[i + 1] = NULL;

    return (ret);
}

/* Check if String is on array (Must be NULL terminated) */
int os_IsStrOnArray(const char *str, char **array)
{
    if (!str || !array) {
        return (0);
    }

    while (*array) {
        if (strcmp(*array, str) == 0) {
            return (1);
        }
        array++;
    }
    return (0);
}

/* Clear the memory of one char and one char** */
void os_FreeArray(char *ch1, char **ch2)
{
    /* Clean char * */
    if (ch1) {
        free(ch1);
        ch1 = NULL;
    }

    /* Clean chat ** */
    if (ch2) {
        char **nch2 = ch2;
        w_FreeArray(ch2);
        free(nch2);
        nch2 = NULL;
    }

    return;
}

/* Allocate memory at "*at" and copy *str to it
 * If *at already exist, realloc the memory and strcat str on it
 * It will return the new string on success or NULL on memory error
 */
char *os_LoadString(char *at, const char *str)
{
    if (at == NULL) {
        at = strdup(str);
        if (!at) {
            merror(MEM_ERROR, errno, strerror(errno));
        }
        return (at);
    } else { /* at is not null. Need to reallocate its memory and copy str to it */
        char *newat;
        size_t strsize = strlen(str);
        size_t finalsize = strsize + strlen(at) + 1;

        newat = (char *) realloc(at, finalsize * sizeof(char));
        if (newat == NULL) {
            free(at);
            merror(MEM_ERROR, errno, strerror(errno));
            return (NULL);
        }
        at = newat;

        strncat(at, str, strsize);
        at[finalsize - 1] = '\0';

        return (at);
    }

    return (NULL);
}

/* Clear memory regardless of compiler optimizations
 * v = memory to clear
 * c = character to set
 * n = memory size to clear
 */
void *memset_secure(void *v, int c, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) {
        *p++ = (unsigned char) c;
    }

    return v;
}

static long n_alloc = 0;
static long n_frees = 0;
static long n_realloc = 0;

extern void * __real_malloc(size_t size);
extern void __real_free(void *ptr);
extern void * __real_calloc(size_t nmemb, size_t size);
extern void  *__real_realloc(void *ptr, size_t size);
extern char * __real_strdup(const char *s);
extern char * __real_cJSON_Print(void *);
extern char * __real_cJSON_PrintUnformatted(void *);

void * __wrap_malloc(size_t size) {
    void * ptr = __real_malloc(size);
    n_alloc += (ptr != NULL);
    return ptr;
}

void __wrap_free(void *ptr) {
    n_frees += (ptr != NULL);
    __real_free(ptr);
}
void * __wrap_calloc(size_t nmemb, size_t size) {
    void * ptr = __real_calloc(nmemb, size);
    n_alloc += (ptr != NULL);
    return ptr;
}

void * __wrap_realloc(void *ptr, size_t size) {
    void * ptr2 = __real_realloc(ptr, size);

    if (ptr2 != NULL) {
        if (ptr == NULL) {
            n_alloc++;
        } else {
            n_realloc++;
        }
    }

    return ptr2;
}

extern char * __wrap_strdup(const char *s) {
    char * s2 = __real_strdup(s);
    n_alloc += (s2 != NULL);
    return s2;
}

char * __wrap_cJSON_Print(void * p) {
    n_alloc+=1000000;
    return __real_cJSON_Print(p);
}

char * __wrap_cJSON_PrintUnformatted(void * p) {
    n_alloc+=1000000;
    return __real_cJSON_PrintUnformatted(p);
}

void print_alloc() {
    minfo("n_alloc = %ld, n_frees = %ld, n_realloc = %ld, n_chunks = %ld", n_alloc, n_frees, n_realloc, n_alloc - n_frees);
}
