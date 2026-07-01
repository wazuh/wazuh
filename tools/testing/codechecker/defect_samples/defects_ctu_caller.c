/*
 * defects_ctu_caller.c — CTU validation sample: caller translation unit.
 *
 * Defect map
 * ----------
 *   defect_ctu_null_deref  -> clang.core.NullDereference  (ENABLE_CTU=1 only)
 *
 * ctu_maybe_null(1) always returns NULL (defined in defects_ctu_callee.c).
 * A per-TU scan of this file alone sees only an opaque extern — the checker
 * cannot conclude the pointer is NULL.  With CTU enabled, the callee body is
 * inlined into the analysis and core.NullDereference fires at the dereference.
 */

extern int *ctu_maybe_null(int condition);

int defect_ctu_null_deref(void)
{
    int *p = ctu_maybe_null(1);  /* always returns NULL — visible only via CTU */
    return *p;                   /* NULL deref: core.NullDereference */
}
