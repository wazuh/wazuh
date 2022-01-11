#include "my_assert.h"

#include <execinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void print_backtrace() {
    void *array[10];
    char **strings;
    int size, i;

    size = backtrace(array, 10);
    strings = backtrace_symbols(array, size);
    if (strings != 0) {
        for (i = 2; i < size; i++) { printf("%s\n", strings[i]); }
    }
    free(strings);
}

void my_assert(const char *expr, const char *file, const char *func, int line) {
    fprintf(stderr, "----------------------------------------\n");
    fprintf(stderr, "# ASSERT FAILED (%s): %s::%s::%d\n", expr, file, func, line);
    fprintf(stderr, "----------------------------------------\n\n");
    print_backtrace();
    // CRASH
    *((volatile int *)0) = 0xDEADBEEF;
}

void my_assert_msg(const char *expr,
                   const char *file,
                   const char *func,
                   int line,
                   char *fmt,
                   ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "----------------------------------------\n");
    fprintf(stderr,
            "# ASSERT FAILED (%s): %s::%s::%d\n# ",
            expr,
            file,
            func,
            line);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n----------------------------------------\n\n");
    print_backtrace();
    // CRASH
    *((volatile int *)0) = 0xDEADBEEF;
}
