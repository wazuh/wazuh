#include "shared.h"
#include "dll_load_notify.h"

#ifdef WIN32

_LdrRegisterDllNotification LdrRegisterDllNotification = NULL;
_LdrUnregisterDllNotification LdrUnregisterDllNotifcation = NULL;
PVOID cookie_dll_notification = NULL;

/**
 *@brief Verify all the DLLs that are already loaded
 */
static void loaded_modules_verification()
{
#ifdef IMAGE_TRUST_CHECKS
    HMODULE handle_module[OS_SIZE_1024];
    HANDLE handle_process = GetCurrentProcess();
    DWORD handle_bytes_needed;

    if (EnumProcessModules(handle_process,
                           handle_module,
                           sizeof(handle_module), &handle_bytes_needed)) {

        for (size_t i = 0; i < (handle_bytes_needed / sizeof(HMODULE)); i++) {
            wchar_t module_name[MAX_PATH];

            // Get the full path to the module's file.
            if (GetModuleFileNameExW(handle_process,
                                     handle_module[i],
                                     module_name,
                                     sizeof(module_name) / sizeof(wchar_t))) {
                // Check if the images loaded are signed.
                if (verify_pe_signature(module_name) != ERROR_SUCCESS &&
                    verify_hash_catalog(module_name) != ERROR_SUCCESS) {
                    merror_exit("The file '%S' is not signed or its signature is invalid.", module_name);
                }

                mdebug1("The file '%S' is signed and its signature is valid.", module_name);
            }
        }
    } else {
        merror_exit("Unable to enumerate the process modules. Error: %lu", GetLastError());
    }
#endif
}

/**
 * @brief Callback function for DLL load notifications
 * @param reason Reason for the notification.
 * @param notification_data Data for the notification.
 * @param context Context for the notification.
 */
void CALLBACK dll_notification(ULONG reason,
                               PLDR_DLL_NOTIFICATION_DATA notification_data,
                               __attribute__((unused)) PVOID context)
{
    //Check for the reason
    switch(reason)
    {
    case LDR_DLL_NOTIFICATION_REASON_LOADED:
        if (verify_pe_signature(notification_data->loaded.full_dll_name->Buffer) != ERROR_SUCCESS
            && verify_hash_catalog(notification_data->loaded.full_dll_name->Buffer) != ERROR_SUCCESS) {
            merror_exit("The file '%S' is not signed or its signature is invalid.", notification_data->loaded.full_dll_name->Buffer);
        }
        break;
    case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
        mdebug1("Unloaded: %S", notification_data->unloaded.full_dll_name->Buffer);
        break;
    }
}

/**
 * @brief Register for DLL load notifications and verify all the DLLs that are already loaded
 */
void enable_dll_verification()
{
    loaded_modules_verification();

#ifdef IMAGE_TRUST_CHECKS
    HMODULE handle_ntdll = GetModuleHandle("ntdll.dll");
    if (handle_ntdll) {
        LdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(handle_ntdll, "LdrRegisterDllNotification");

        if (LdrRegisterDllNotification)
        {
            LdrRegisterDllNotification(0, &dll_notification, NULL, &cookie_dll_notification);
        } else {
            merror("Unable to get the address of LdrRegisterDllNotification. Error: %lu", GetLastError());
        }
    } else {
        merror("Unable to get the handle of ntdll.dll. Error: %lu", GetLastError());
    }
#endif
}

#endif // WIN32

