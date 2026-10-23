/*
 * defects_ctu_callee.c — CTU validation sample: callee translation unit.
 *
 * Defect map
 * ----------
 *   ctu_maybe_null  -> clang.core.NullDereference (via defects_ctu_caller.c)
 *
 * Per-TU analysis of the CALLER cannot see this function's body, so the NULL
 * return on condition==1 is invisible without CTU.  With ENABLE_CTU=1,
 * CodeChecker maps the callee definition and the checker fires in the caller.
 */
#include <stddef.h>

int *ctu_maybe_null(int condition)
{
    if (condition)
        return NULL;        /* always NULL when condition is non-zero */
    static int val = 42;
    return &val;
}
