/*
 * defects_c.c — CodeChecker detection validation samples (C).
 *
 * Each function contains exactly ONE deliberate defect to validate that the
 * configured checker fires on that defect class.  This file is only present
 * on the test/codechecker-defect-samples branch — it is never compiled into
 * a production build.
 *
 * Defect map
 * ----------
 *   defect_null_deref                -> clang.core.NullDereference
 *   defect_memory_leak               -> clang.unix.Malloc / cppcheck-memleak
 *   defect_realloc_leak              -> cppcheck-memleakOnRealloc
 *                                       bugprone-suspicious-realloc-usage
 *   defect_use_after_free            -> clang.unix.Malloc / cppcheck-deallocuse
 *   defect_double_free               -> clang.unix.Malloc
 *   defect_uninit_var                -> clang.core.UndefinedBinaryOperatorResult
 *                                       cppcheck-uninitvar
 *   defect_unchecked_fopen           -> clang.core.NullDereference
 *                                       (unchecked fopen return → NULL deref)
 *   defect_block_in_critical_section -> unix.BlockInCriticalSection
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/* clang.core.NullDereference ------------------------------------------------*/
int defect_null_deref(int x)
{
    int *p = NULL;
    if (x > 0) {
        return *p;   /* dereference of null pointer on this path */
    }
    return 0;
}

/* clang.unix.Malloc / cppcheck-memleak --------------------------------------
 * 'tmp' is allocated but not freed on the early-return path when
 * 'result' allocation fails.
 */
char *defect_memory_leak(size_t n)
{
    char *tmp = malloc(n);
    if (!tmp) {
        return NULL;
    }
    char *result = malloc(n * 2);
    if (!result) {
        return NULL;   /* tmp leaked here */
    }
    memcpy(result, tmp, n);
    free(tmp);
    return result;
}

/* cppcheck-memleakOnRealloc / bugprone-suspicious-realloc-usage -------------
 * If realloc() returns NULL the original pointer is overwritten and lost.
 */
int defect_realloc_leak(void)
{
    char *buf = malloc(64);
    if (!buf) {
        return -1;
    }
    buf = realloc(buf, 128);   /* original buf is lost if realloc returns NULL */
    if (!buf) {
        return -1;
    }
    free(buf);
    return 0;
}

/* clang.unix.Malloc / cppcheck-deallocuse -----------------------------------*/
void defect_use_after_free(void)
{
    char *p = malloc(32);
    if (!p) {
        return;
    }
    free(p);
    p[0] = 'X';   /* write to freed memory */
}

/* clang.unix.Malloc: double free on flag==true path ------------------------*/
void defect_double_free(int flag)
{
    char *p = malloc(32);
    if (!p) {
        return;
    }
    if (flag) {
        free(p);
    }
    free(p);   /* second free when flag is non-zero */
}

/* clang.core.UndefinedBinaryOperatorResult / cppcheck-uninitvar -------------*/
int defect_uninit_var(void)
{
    int x;           /* declared but never assigned */
    return x + 1;    /* read of uninitialized value */
}

/* clang.core.NullDereference: fopen return value not checked ----------------*/
void defect_unchecked_fopen(const char *path)
{
    FILE *f = fopen(path, "r");   /* return value not checked */
    char buf[256];
    fread(buf, 1, sizeof(buf), f);   /* f may be NULL → null dereference */
    fclose(f);
}

/* unix.BlockInCriticalSection -----------------------------------------------
 * sleep() is a blocking system call; calling it while holding a mutex can
 * cause other threads to stall indefinitely.
 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void defect_block_in_critical_section(void)
{
    pthread_mutex_lock(&g_lock);
    sleep(1);   /* blocking call inside critical section */
    pthread_mutex_unlock(&g_lock);
}
