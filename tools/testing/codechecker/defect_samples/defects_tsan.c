/*
 * defects_tsan.c — ThreadSanitizer validation sample.
 *
 * Defect map
 * ----------
 *   defect_data_race  -> TSan: DATA RACE
 *                        Two threads increment g_counter without a mutex.
 *                        TSan instruments the binary at compile time
 *                        (-fsanitize=thread) and reports the race at runtime.
 *
 * Build: $(CC) -g -O0 -fsanitize=thread -pthread defects_tsan.c -o defects_tsan
 * Run:   ./defects_tsan
 *        TSan output should contain "DATA RACE" on g_counter.
 *
 * Note: this file produces a standalone executable (not an object file) so
 *       it is excluded from the static-analysis compile_commands merge.
 *       It is built and run separately by run_tsan_tests.sh when RUN_TSAN=1.
 */
#include <pthread.h>
#include <stdio.h>

static int g_counter = 0;   /* shared, deliberately unprotected */

static void *increment_thread(void *arg)
{
    (void)arg;
    for (int i = 0; i < 100000; i++)
        g_counter++;   /* data race: no synchronisation */
    return NULL;
}

void defect_data_race(void)
{
    pthread_t t1, t2;
    pthread_create(&t1, NULL, increment_thread, NULL);
    pthread_create(&t2, NULL, increment_thread, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}

int main(void)
{
    defect_data_race();
    printf("counter = %d (expected ~200000, TSan DATA RACE reported above)\n",
           g_counter);
    return 0;
}
