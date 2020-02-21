#ifndef UNIT_TEST_WRAPPERS_RUN_CHECK
#define UNIT_TEST_WRAPPERS_RUN_CHECK

#include <windows.h>

WINBOOL wrap_SetThreadPriority (HANDLE hThread, int nPriority);

#endif
