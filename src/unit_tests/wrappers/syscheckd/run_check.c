#include "run_check.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

WINBOOL wrap_SetThreadPriority (HANDLE hThread, int nPriority) {
    check_expected(hThread);
    check_expected(nPriority);
    return mock();
}
