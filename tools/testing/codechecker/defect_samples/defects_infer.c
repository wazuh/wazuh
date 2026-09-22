/*
 * defects_infer.c — Infer/RacerD validation samples (C).
 *
 * Defect map
 * ----------
 *   defect_fd_leak        -> Infer: RESOURCE_LEAK
 *                            File descriptor opened but not closed on the
 *                            early-return path when read() fails.
 *
 *   defect_lock_imbalance -> Infer: THREAD_SAFETY_VIOLATION
 *                            Mutex acquired but not released on the error
 *                            path (early return without unlock).
 *
 * These defects are chosen because Infer's bi-abduction engine tracks heap /
 * lock state across paths more precisely than clangsa in these patterns.
 */
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

/* Infer: RESOURCE_LEAK -------------------------------------------------------
 * 'fd' is opened but not closed when read() returns an error.
 */
int defect_fd_leak(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0)
        return -1;   /* fd leaked on this path */

    close(fd);
    return (int)n;
}

/* Infer: THREAD_SAFETY_VIOLATION --------------------------------------------
 * Mutex is locked but not unlocked on the early-return path when err != 0.
 */
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

int defect_lock_imbalance(int err)
{
    pthread_mutex_lock(&g_mtx);
    if (err)
        return -1;   /* mutex not released — lock imbalance */
    pthread_mutex_unlock(&g_mtx);
    return 0;
}
