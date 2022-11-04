#include "shared.h"
#include "hooking.h"

#ifdef WIN32
#include "cryptography.h"
#include "distormx.h"
#include <winternl.h>
#include <windows.h>
#include <psapi.h>

static void loadedModulesVerification()
{
    HMODULE hMods[OS_SIZE_1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    hProcess = GetCurrentProcess();

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                                    sizeof(szModName) / sizeof(TCHAR))) {
                // convert to wide char
                wchar_t wtext[1024];
                mbstowcs(wtext, szModName, strlen(szModName) + 1);

#ifdef DEBUG
                // White list of dlls to load.
                if (strncmp(szModName, "C:\\Program Files (x86)\\ossec-agent\\", 35) != 0) {
#endif
                    // Check if the images loaded are signed.
                    if (verify_pe_signature(wtext) != ERROR_SUCCESS &&
                        verify_catalog(wtext) != ERROR_SUCCESS) {
                        merror_exit("Dll not signed: %s", szModName);
                    }
#ifdef DEBUG
                }
#endif
            }
        }
    }
}

typedef void (WINAPI * LdrLoadDll_) (PWSTR SearchPath OPTIONAL,
                                     PULONG DllCharacteristics OPTIONAL,
                                     PUNICODE_STRING DllName,
                                     PVOID *BaseAddress);

static LdrLoadDll_ LdrLoadDll_base = NULL;

__declspec(noinline) __stdcall void LdrLoadDll_hook(PWSTR SearchPath OPTIONAL,
                                          PULONG DllCharacteristics OPTIONAL,
                                          PUNICODE_STRING DllName,
                                          PVOID *BaseAddress)
{
    // Identify if this function is called recursively.
    // Recursive mutex, critical section.
    // If the mutex is already locked, the function is called recursively.
    // If the mutex is not locked, the function is not called recursively.

    static CRITICAL_SECTION cs;
    static BOOL csInitialized = FALSE;
    static int csLockCount = 0;

    if (!csInitialized) {
        InitializeCriticalSection(&cs);
        csInitialized = TRUE;
    }

    EnterCriticalSection(&cs);
    ++csLockCount;
#ifdef DEBUG
    if (wcsncmp(DllName->Buffer, L"C:\\Program Files (x86)\\ossec-agent\\", 35) != 0) {
#endif
        if (csLockCount > 1) {
            LdrLoadDll_base(SearchPath, DllCharacteristics, DllName, BaseAddress);
        } else {
            if ((verify_catalog(DllName->Buffer) == ERROR_SUCCESS) ||
                (verify_pe_signature(DllName->Buffer) == ERROR_SUCCESS))
            {
                LdrLoadDll_base(SearchPath, DllCharacteristics, DllName, BaseAddress);
            }
        }

#ifdef DEBUG
    } else {
        LdrLoadDll_base(SearchPath, DllCharacteristics, DllName, BaseAddress);
    }
#endif
    --csLockCount;
    LeaveCriticalSection(&cs);
}

void hook_LdrLoadDll()
{
    loadedModulesVerification();

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (hNtdll) {
        FARPROC wlLdrLoadDll_base = GetProcAddress(hNtdll, "LdrLoadDll");
        if (wlLdrLoadDll_base) {
            LdrLoadDll_base = (LdrLoadDll_)wlLdrLoadDll_base;
            if (!distormx_hook((void **)&LdrLoadDll_base, LdrLoadDll_hook))
            {
                merror("Side loading of DLLs is not prevented.");
            }
        }
    }
}

#endif // WIN32

