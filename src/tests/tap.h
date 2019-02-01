/* TAP format macros. */
#ifndef _LIB_TAP_H
#define _LIB_TAP_H

static int tap_count;
static int tap_todo;
static int tap_fail;

#define CRED    "\033[1;31m"
#define CYELLOW    "\033[1;33m"
#define CCYAN    "\033[1;36m"
#define CGREEN    "\033[1;32m"
#define CEXTERN    "\033[1;35m"
#define CEND    "\033[0m"

#define ENDLINE                  \
    {                            \
        if (tap_todo)            \
        {                        \
            printf(" # TODO\n"); \
        }                        \
        else                     \
        {                        \
            printf("\n");        \
        }                        \
    }

#define TAP_TEST_MSG(x, msg, args...)                   \
{                                                       \
    tap_count++;                                        \
    if (!(x)) {                                         \
        if (!tap_todo) {                                \
            tap_fail++;                                 \
        }                                               \
        printf(CRED "not ok %*d - ", 2 , tap_count);    \
    }                                                   \
    else if (tap_todo == 1) {                           \
        printf(CGREEN "    ok %*d - ", 2 , tap_count);  \
        tap_fail++;                                     \
    }                                                   \
    else {                                              \
        printf(CGREEN "    ok %*d - ", 2 , tap_count);  \
    }                                                   \
    printf(msg, ##args);                                \
    ENDLINE;                                            \
}

#define TODO tap_todo = 1
#define END_TODO tap_todo = 0

#define TAP_PLAN { printf(CCYAN "1..%d\n", tap_count); }

#define TAP_SUMMARY                                                    \
{                                                                      \
    if (tap_fail>0) {                                                  \
        printf(CRED   "\n       [ %d TEST FAILED ]\n" CEND, tap_fail); \
    }                                                                  \
    else {                                                             \
        printf(CGREEN "\n      [ ALL TESTS PASSED ]\n" CEND);          \
    }                                                                  \
}

#endif