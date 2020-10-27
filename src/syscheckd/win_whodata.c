/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 13, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "shared.h"
#include "hash_op.h"
#include "syscheck.h"
#include "syscheck_op.h"

#ifdef WIN_WHODATA

#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winevt.h>

#define WLIST_ALERT_THRESHOLD 80 // 80%
#define WLIST_REMOVE_MAX 10 // 10%
#define WCLIST_MAX_SIZE OS_SIZE_1024
#define WPOL_BACKUP_COMMAND "auditpol /backup /file:\"%s\""
#define WPOL_RESTORE_COMMAND "auditpol /restore /file:\"%s\""
#define WPOL_BACKUP_FILE "tmp\\backup-policies"
#define WPOL_NEW_FILE "tmp\\new-policies"
#define modify_criteria (FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES)
#define criteria (DELETE | modify_criteria)
#define WHODATA_DIR_REMOVE_INTERVAL 2
#define FILETIME_SECOND 10000000

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "unit_tests/wrappers/windows/aclapi_wrappers.h"
#include "unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#include "unit_tests/wrappers/windows/fileapi_wrappers.h"
#include "unit_tests/wrappers/windows/handleapi_wrappers.h"
#include "unit_tests/wrappers/windows/heapapi_wrappers.h"
#include "unit_tests/wrappers/windows/processthreadsapi_wrappers.h"
#include "unit_tests/wrappers/windows/sddl_wrappers.h"
#include "unit_tests/wrappers/windows/securitybaseapi_wrappers.h"
#include "unit_tests/wrappers/windows/stringapiset_wrappers.h"
#include "unit_tests/wrappers/windows/synchapi_wrappers.h"
#include "unit_tests/wrappers/windows/sysinfoapi_wrappers.h"
#include "unit_tests/wrappers/windows/timezoneapi_wrappers.h"
#include "unit_tests/wrappers/windows/winbase_wrappers.h"
#include "unit_tests/wrappers/windows/winevt_wrappers.h"
#include "unit_tests/wrappers/windows/winreg_wrappers.h"
#include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

// Variables whodata
STATIC char sys_64 = 1;
STATIC PSID everyone_sid = NULL;
STATIC size_t ev_sid_size = 0;
static unsigned short inherit_flag = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE; //SUB_CONTAINERS_AND_OBJECTS_INHERIT
STATIC EVT_HANDLE context;
STATIC const wchar_t* event_fields[] = {
    L"Event/System/EventID",
    L"Event/EventData/Data[@Name='SubjectUserName']",
    L"Event/EventData/Data[@Name='ObjectName']",
    L"Event/EventData/Data[@Name='ProcessName']",
    L"Event/EventData/Data[@Name='ProcessId']",
    L"Event/EventData/Data[@Name='HandleId']",
    L"Event/EventData/Data[@Name='AccessMask']",
    L"Event/EventData/Data[@Name='SubjectUserSid']",
    L"Event/System/TimeCreated/@SystemTime"
};
enum rendered_fields {
    RENDERED_EVENT_ID = 0,
    RENDERED_USER_NAME,
    RENDERED_PATH,
    RENDERED_PROCESS_NAME,
    RENDERED_PROCESS_ID,
    RENDERED_HANDLE_ID,
    RENDERED_ACCESS_MASK,
    RENDERED_USER_SID,
    RENDERED_TIMESTAMP
};

static unsigned int fields_number = sizeof(event_fields) / sizeof(LPWSTR);
static const unsigned __int64 AUDIT_SUCCESS = 0x20000000000000;
static LPCTSTR priv = "SeSecurityPrivilege";
STATIC int restore_policies = 0;

// Whodata function headers
void restore_sacls();
int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable);
int is_valid_sacl(PACL sacl, int is_file);
unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, __attribute__((unused)) void *_void, EVT_HANDLE event);
int set_policies();
void set_subscription_query(wchar_t *query);
extern int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);
int restore_audit_policies();
int check_object_sacl(char *obj, int is_file);
int whodata_hash_add(OSHash *table, char *id, void *data, char *tag);
void notify_SACL_change(char *dir);
int whodata_path_filter(char **path);
void whodata_adapt_path(char **path);
int whodata_check_arch();

// Whodata list operations
char *get_whodata_path(const short unsigned int *win_path);

// Get volumes and paths of Windows system
int get_volume_names();
int get_drive_names(wchar_t *volume_name, char *device);
void replace_device_path(char **path);

int set_winsacl(const char *dir, int position) {
    DWORD result = 0;
    PACL old_sacl = NULL, new_sacl = NULL;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    SYSTEM_AUDIT_ACE *ace = NULL;
    PVOID entry_access_it = NULL;
    HANDLE hdle;
    unsigned int i;
    ACL_SIZE_INFORMATION old_sacl_info;
    unsigned long new_sacl_size;
    int retval = 1;
    int privilege_enabled = 0;

    mdebug2(FIM_SACL_CONFIGURE, dir);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hdle)) {
        merror(FIM_ERROR_SACL_OPENPROCESSTOKEN, GetLastError());
        return 1;
    }

    if (set_privilege(hdle, priv, TRUE)) {
        merror(FIM_ERROR_SACL_ELEVATE_PRIVILEGE, GetLastError());
        goto end;
    }

    privilege_enabled = 1;

    if (result = GetNamedSecurityInfo(dir, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &old_sacl, &security_descriptor), result != ERROR_SUCCESS) {
        merror(FIM_ERROR_SACL_GETSECURITYINFO, result);
        goto end;
    }

    ZeroMemory(&old_sacl_info, sizeof(ACL_SIZE_INFORMATION));

    // Check if the sacl has what the whodata scanner needs
    switch(is_valid_sacl(old_sacl, (syscheck.wdata.dirs_status[position].object_type == WD_STATUS_FILE_TYPE) ? 1 : 0)) {
        case 0:
            mdebug1(FIM_SACL_CHECK_CONFIGURE, dir);
            syscheck.wdata.dirs_status[position].status |= WD_IGNORE_REST;

            // Get SACL size
            if (!GetAclInformation(old_sacl, (LPVOID)&old_sacl_info, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
                merror(FIM_ERROR_SACL_GETSIZE, dir);
                goto end;
            }
        break;
        case 1:
            // It is not necessary to configure the SACL of the directory
            retval = 0;
            goto end;
        case 2:
            // Empty SACL
            syscheck.wdata.dirs_status[position].status |= WD_IGNORE_REST;
            old_sacl_info.AclBytesInUse = sizeof(ACL);
            break;
    }
    if (!ev_sid_size) {
        ev_sid_size = GetLengthSid(everyone_sid);
    }

    // Set the new ACL size
    new_sacl_size = old_sacl_info.AclBytesInUse + sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(unsigned long);

    if (new_sacl = (PACL)win_alloc(new_sacl_size), !new_sacl) {
        merror(FIM_ERROR_SACL_NOMEMORY, dir);
        goto end;
    }

    if (!InitializeAcl(new_sacl, new_sacl_size, ACL_REVISION)) {
        merror(FIM_ERROR_SACL_CREATE, dir);
        goto end;
    }

    // If SACL is present, copy it to a new SACL
    if (old_sacl) {
        if (old_sacl_info.AceCount) {
            for (i = 0; i < old_sacl_info.AceCount; i++) {
               if (!GetAce(old_sacl, i, &entry_access_it)) {
                   merror(FIM_ERROR_SACL_ACE_GET, i, dir);
                   goto end;
               }

               if (!AddAce(new_sacl, ACL_REVISION, MAXDWORD, entry_access_it, ((PACE_HEADER)entry_access_it)->AceSize)) {
                   merror(FIM_ERROR_SACL_ACE_CPY, i, dir);
                   goto end;
               }
           }
        }
    }
    // Build the new ACE
    if (ace = (SYSTEM_AUDIT_ACE *)win_alloc(sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(DWORD)), !ace) {
        merror(FIM_ERROR_SACL_ACE_NOMEMORY, dir);
        goto end;
    }

    ace->Header.AceType  = SYSTEM_AUDIT_ACE_TYPE;
    ace->Header.AceFlags = inherit_flag | SUCCESSFUL_ACCESS_ACE_FLAG;
    ace->Header.AceSize  = LOWORD(sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(DWORD));
    ace->Mask            = criteria;
    if (!CopySid(ev_sid_size, &ace->SidStart, everyone_sid)) {
        goto end;
    }

    // Add the new ACE
    if (!AddAce(new_sacl, ACL_REVISION, 0, (LPVOID)ace, ace->Header.AceSize)) {
        merror(FIM_ERROR_SACL_ACE_ADD, dir);
        goto end;
    }

    // Set a new ACL for the security descriptor
    if (result = SetNamedSecurityInfo((char *) dir, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, new_sacl), result != ERROR_SUCCESS) {
        merror(FIM_ERROR_SACL_SETSECURITYINFO, result);
        goto end;
    }

    retval = 0;
end:
    if (privilege_enabled) {
        // Disable the privilege
        if (set_privilege(hdle, priv, FALSE)) {
            merror(FIM_ERROR_SACL_SET_PRIVILEGE, GetLastError());
        }
    }

    if (hdle) {
        CloseHandle(hdle);
    }

    if (security_descriptor) {
        LocalFree((HLOCAL)security_descriptor);
    }

    if (old_sacl) {
        LocalFree((HLOCAL)old_sacl);
    }

    if (new_sacl) {
        LocalFree((HLOCAL)new_sacl);
    }
    if (ace) {
        LocalFree((HLOCAL)ace);
    }
    return retval;
}

int is_valid_sacl(PACL sacl, int is_file) {
    int i;
    ACCESS_ALLOWED_ACE *ace;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    if (!everyone_sid) {
        if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid)) {
            merror(FIM_ERROR_WHODATA_GET_SID, GetLastError());
            return 0;
        }
    }

    if (!sacl) {
        mdebug2(FIM_SACL_NOT_FOUND);
        return 2;
    }

    for (i = 0; i < sacl->AceCount; i++) {
        if (!GetAce(sacl, i, (LPVOID*)&ace)) {
            merror(FIM_ERROR_WHODATA_GET_ACE, GetLastError());
            return 0;
        }

        if ((is_file || (ace->Header.AceFlags & inherit_flag)) && // Check folder and subfolders
            (ace->Header.AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) && // Check successful attemp
            ((ace->Mask & (criteria)) == criteria) && // Check write, delete, change_permissions and change_attributes permission
            (EqualSid((PSID)&ace->SidStart, everyone_sid))) { // Check everyone user
            return 1;
        }
    }
    return 0;
}

int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable) {
    TOKEN_PRIVILEGES tp;
    LUID pr_uid;

    // Get the privilege UID
    if (!LookupPrivilegeValue(NULL, privilege, &pr_uid)) {
        merror(FIM_ERROR_SACL_FIND_PRIVILEGE, privilege, GetLastError());
        return 1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = pr_uid;

    if (enable) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tp.Privileges[0].Attributes = 0;
    }

    // Set the privilege to the process
    if (!AdjustTokenPrivileges(hdle, 0, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        merror(FIM_ERROR_WHODATA_TOKENPRIVILEGES, GetLastError());
        return 1;
    }

    if (enable) {
        mdebug2(FIM_ELEVATE_PRIVILEGE, privilege);
    } else {
        mdebug2(FIM_REDUCE_PRIVILEGE, privilege);
    }

    return 0;
}

int run_whodata_scan() {
    wchar_t query[OS_MAXSTR];
    int result;

    if (whodata_check_arch()) {
        return 1;
    }

    // Set the signal handler to restore the policies
    atexit(audit_restore);

    // Set the system audit policies
    if (result = set_policies(), result) {
        merror(FIM_WARN_WHODATA_LOCALPOLICIES);
        return 1;
    }

    // Select the interesting fields
    if (context = EvtCreateRenderContext(fields_number, event_fields, EvtRenderContextValues), !context) {
        merror(FIM_ERROR_WHODATA_CONTEXT, GetLastError());
        return 1;
    }

    set_subscription_query(query);

    // Set the whodata callback
    if (!EvtSubscribe(NULL, NULL, L"Security", query,
            NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)whodata_callback, EvtSubscribeToFutureEvents)) {
        merror(FIM_ERROR_WHODATA_EVENTCHANNEL);
        return 1;
    }

    minfo(FIM_WHODATA_STARTED);

    return 0;
}

void audit_restore() {
    restore_sacls();
    if (restore_policies) {
        restore_audit_policies();
    }
}

/* Removes added security audit policies */
void restore_sacls() {
    int i;
    PACL sacl_it;
    HANDLE hdle = NULL;
    HANDLE c_process = NULL;
    LPCTSTR priv = "SeSecurityPrivilege";
    DWORD result = 0;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    int privilege_enabled = 0;

    c_process = GetCurrentProcess();
    if (!OpenProcessToken(c_process, TOKEN_ADJUST_PRIVILEGES, &hdle)) {
        merror(FIM_ERROR_SACL_OPENPROCESSTOKEN, GetLastError());
        goto end;
    }

    if (set_privilege(hdle, priv, TRUE)) {
        merror(FIM_ERROR_SACL_ELEVATE_PRIVILEGE, GetLastError());
        goto end;
    }

    privilege_enabled = 1;

    for (i = 0; syscheck.dir[i] != NULL; i++) {
        if (syscheck.wdata.dirs_status[i].status & WD_IGNORE_REST) {
            sacl_it = NULL;
            if (result = GetNamedSecurityInfo(syscheck.dir[i], SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &sacl_it, &security_descriptor), result != ERROR_SUCCESS) {
                merror(FIM_ERROR_SACL_GETSECURITYINFO, result);
                break;
            }

            // The ACE we added is in position 0
            if (!DeleteAce(sacl_it, 0)) {
                merror(FIM_ERROR_SACL_ACE_DELETE, GetLastError());
                break;
            }

            // Set the SACL
            if (result = SetNamedSecurityInfo((char *) syscheck.dir[i], SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, sacl_it), result != ERROR_SUCCESS) {
                merror(FIM_ERROR_SACL_SETSECURITYINFO, result);
                break;
            }

            if (sacl_it) {
                LocalFree((HLOCAL)sacl_it);
            }

            if (security_descriptor) {
                LocalFree((HLOCAL)security_descriptor);
            }
            mdebug1(FIM_SACL_RESTORED, syscheck.dir[i]);
        }
    }

end:
    if (privilege_enabled) {
        // Disable the privilege
        if (set_privilege(hdle, priv, FALSE)) {
            merror(FIM_ERROR_SACL_SET_PRIVILEGE, GetLastError());
        }
    }

    if (hdle) {
        CloseHandle(hdle);
    }
    if (c_process) {
        CloseHandle(c_process);
    }
}

int restore_audit_policies() {
    char command[OS_SIZE_1024];
    int result_code;
    snprintf(command, OS_SIZE_1024, WPOL_RESTORE_COMMAND, WPOL_BACKUP_FILE);

    if (IsFile(WPOL_BACKUP_FILE)) {
        merror(FIM_ERROR_WHODATA_RESTORE_POLICIES);
        return 1;
    }
    // Get the current policies
    char *cmd_output = NULL;
    const int wm_exec_ret_code = wm_exec(command, &cmd_output, &result_code, 5, NULL);

    if (wm_exec_ret_code < 0) {
        merror(FIM_ERROR_WHODATA_AUDITPOL, "failed to execute command");
        return 1;
    }

    if (wm_exec_ret_code == 1) {
        merror(FIM_ERROR_WHODATA_AUDITPOL, "time overtaken while running the command");
        os_free(cmd_output);
        return 1;
    }

    if (!wm_exec_ret_code && result_code) {
        char error_msg[OS_MAXSTR];
        snprintf(error_msg, OS_MAXSTR, FIM_ERROR_WHODATA_AUDITPOL, "command returned failure'. Output: '%s");
        merror(error_msg, cmd_output);
        os_free(cmd_output);
        return 1;
    }

    return 0;
}

PEVT_VARIANT whodata_event_render(EVT_HANDLE event) {
    PEVT_VARIANT buffer = NULL;
    unsigned long used_size;
    unsigned long property_count;

    // Extract the necessary memory size
    EvtRender(context, event, EvtRenderEventValues, 0, NULL, &used_size, &property_count);

    os_malloc(used_size, buffer);
    memset(buffer, 0, used_size);

    if (!EvtRender(context, event, EvtRenderEventValues, used_size, buffer, &used_size, &property_count)) {
        mwarn(FIM_WHODATA_RENDER_EVENT, GetLastError());
        os_free(buffer);
        return buffer;
    }

    if (property_count != fields_number) {
        mwarn(FIM_WHODATA_RENDER_PARAM);
        os_free(buffer);
    }

    return buffer;
}

int whodata_get_event_id(const PEVT_VARIANT raw_data, short *event_id) {
    if (!raw_data || !event_id) {
        return -1;
    }

    // EventID
    if (raw_data[RENDERED_EVENT_ID].Type != EvtVarTypeUInt16) {
        mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_EVENT_ID].Type, "event_id");
        return -1;
    }
    *event_id = raw_data[RENDERED_EVENT_ID].Int16Val;

    return 0;
}

int whodata_get_handle_id(const PEVT_VARIANT raw_data, unsigned __int64 *handle_id) {
    if (!raw_data || !handle_id) {
        return -1;
    }

    // HandleId
    // In 32-bit Windows we find EvtVarTypeSizeT or EvtVarTypeHexInt32
    if (raw_data[RENDERED_HANDLE_ID].Type != EvtVarTypeHexInt64) {
        if (raw_data[RENDERED_HANDLE_ID].Type == EvtVarTypeSizeT) {
            *handle_id = (unsigned __int64) raw_data[RENDERED_HANDLE_ID].SizeTVal;
        } else if (raw_data[RENDERED_HANDLE_ID].Type == EvtVarTypeHexInt32) {
            *handle_id = (unsigned __int64) raw_data[RENDERED_HANDLE_ID].UInt32Val;
        } else {
            mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_HANDLE_ID].Type, "handle_id");
            return -1;
        }
    } else {
        *handle_id = raw_data[RENDERED_HANDLE_ID].UInt64Val;
    }
    return 0;
}

int whodata_get_access_mask(const PEVT_VARIANT raw_data, unsigned long *mask) {
    if (!raw_data || !mask) {
        return -1;
    }

    // AccessMask
    if (raw_data[RENDERED_ACCESS_MASK].Type != EvtVarTypeHexInt32) {
        mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_ACCESS_MASK].Type, "mask");
        return -1;
    }
    *mask = raw_data[RENDERED_ACCESS_MASK].UInt32Val;

    return 0;
}

int whodata_event_parse(const PEVT_VARIANT raw_data, whodata_evt *event_data) {
    if (!raw_data || !event_data) {
        return -1;
    }

    // ObjectName
    if (raw_data[RENDERED_PATH].Type != EvtVarTypeString) {
        mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_PATH].Type, "path");
        return -1;
    }  else {
        if (event_data->path = get_whodata_path(raw_data[RENDERED_PATH].XmlVal), !event_data->path) {
            return -1;
        }

        // Replace in string path \device\harddiskvolumeX\ by drive letter
        replace_device_path(&event_data->path);

        str_lowercase(event_data->path);
        if (whodata_path_filter(&event_data->path)) {
            return -1;
        }
    }

    // SubjectUserName
    if (raw_data[RENDERED_USER_NAME].Type != EvtVarTypeString) {
        mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_USER_NAME].Type, "user_name");
        event_data->user_name = NULL;
    } else {
        event_data->user_name = convert_windows_string(raw_data[RENDERED_USER_NAME].XmlVal);
    }

    // ProcessName
    if (raw_data[RENDERED_PROCESS_NAME].Type != EvtVarTypeString) {
        mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_PROCESS_NAME].Type, "process_name");
        event_data->process_name = NULL;
    } else {
        event_data->process_name = convert_windows_string(raw_data[RENDERED_PROCESS_NAME].XmlVal);
    }

    // ProcessId
    // In 32-bit Windows we find EvtVarTypeSizeT
    if (raw_data[RENDERED_PROCESS_ID].Type != EvtVarTypeHexInt64) {
        if (raw_data[RENDERED_PROCESS_ID].Type == EvtVarTypeSizeT) {
            event_data->process_id = (unsigned __int64) raw_data[RENDERED_PROCESS_ID].SizeTVal;
        } else if (raw_data[RENDERED_PROCESS_ID].Type == EvtVarTypeHexInt32) {
            event_data->process_id = (unsigned __int64) raw_data[RENDERED_PROCESS_ID].UInt32Val;
        } else {
            mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_PROCESS_ID].Type, "process_id");
            event_data->process_id = 0;
        }
    } else {
        event_data->process_id = raw_data[RENDERED_PROCESS_ID].UInt64Val;
    }

    // SubjectUserSid
    if (raw_data[RENDERED_USER_SID].Type != EvtVarTypeSid) {
        mwarn(FIM_WHODATA_PARAMETER, raw_data[RENDERED_USER_SID].Type, "user_id");
        event_data->user_id = NULL;
    } else if (!ConvertSidToStringSid(raw_data[RENDERED_USER_SID].SidVal, &event_data->user_id)) {
        if (event_data->user_name) {
            mdebug1(FIM_WHODATA_INVALID_UID, event_data->user_name);
        } else {
            mdebug1(FIM_WHODATA_INVALID_UNKNOWN_UID);
        }
        return -1;
    }

    return 0;
}

unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, __attribute__((unused)) void *_void, EVT_HANDLE event) {
    unsigned int retval = 1;
    int result;
    PEVT_VARIANT buffer = NULL;
    whodata_evt *w_evt;
    short event_id;
    unsigned __int64 handle_id;
    char is_directory;
    whodata_directory *w_dir;
    unsigned long mask = 0;

    if (action == EvtSubscribeActionDeliver) {
        fim_element *item;
        char hash_id[21];

        if (buffer = whodata_event_render(event), !buffer) {
            goto clean;
        }

        if (whodata_get_event_id(buffer, &event_id)) {
            goto clean;
        }

        if (whodata_get_handle_id(buffer, &handle_id)) {
            goto clean;
        }
        snprintf(hash_id, 21, "%llu", handle_id);

        switch(event_id) {

            // Open fd
            case 4656:
                is_directory = 0;

                os_calloc(1, sizeof(whodata_evt), w_evt);
                if (whodata_event_parse(buffer, w_evt) != 0) {
                    free_whodata_event(w_evt);
                    goto clean;
                }

                if (whodata_get_access_mask(buffer, &mask)) {
                    free_whodata_event(w_evt);
                    goto clean;
                }
                if (w_evt->config_node = fim_configuration_directory(w_evt->path, "file"), w_evt->config_node < 0 &&
                    !(mask & (FILE_APPEND_DATA | FILE_WRITE_DATA))) {
                    // Discard the file or directory if its monitoring has not been activated
                    mdebug2(FIM_WHODATA_NOT_ACTIVE, w_evt->path);
                    free_whodata_event(w_evt);
                    goto clean;
                }

                if (w_evt->config_node >= 0) {
                    // Ignore the file if belongs to a non-whodata directory
                    if (!(syscheck.wdata.dirs_status[w_evt->config_node].status & WD_CHECK_WHODATA) &&
                        !(mask & (FILE_APPEND_DATA | FILE_WRITE_DATA))) {
                        mdebug2(FIM_WHODATA_CANCELED, w_evt->path);
                        free_whodata_event(w_evt);
                        goto clean;
                    }

                    // Ignore any and all events that are beyond the configured recursion level.
                    int depth = fim_check_depth(w_evt->path, w_evt->config_node);
                    if (depth > syscheck.recursion_level[w_evt->config_node]) {
                        mdebug2(FIM_MAX_RECURSION_LEVEL, depth, syscheck.recursion_level[w_evt->config_node], w_evt->path);
                        free_whodata_event(w_evt);
                        goto clean;
                    }
                }

                int device_type;

                // If it is an existing directory, check_path_type returns 2
                if (device_type = check_path_type(w_evt->path), device_type == 2) {
                    is_directory = 1;
                } else if (device_type == 0) {
                    // If the device could not be found, it was monitored by Syscheck, has not recently been removed,
                    // and had never been entered in the hash table before, we can deduce that it is a removed directory
                    if (mask & DELETE || mask & FILE_APPEND_DATA) {
                        mdebug2(FIM_WHODATA_REMOVE_FOLDEREVENT, w_evt->path);
                        is_directory = 1;
                    }
                }

                // In deferred delete events the access mask comes with delete access only,
                // we need it to scan the directory this file belongs to
                if (mask == DELETE) {
                    w_evt->mask = DELETE;
                } else {
                    w_evt->mask = 0;
                }
                w_evt->scan_directory = is_directory;

                if (result = whodata_hash_add(syscheck.wdata.fd, hash_id, w_evt, "whodata"), result == 0) {
                    free_whodata_event(w_evt);
                    goto clean;
                }

                // Duplicate event handle, attempt to replace it
                if (result == 1) {
                    whodata_evt *w_evtdup;

                    mdebug1(FIM_WHODATA_HANDLE_UPDATE, hash_id);
                    if (w_evtdup = OSHash_Delete_ex(syscheck.wdata.fd, hash_id), !w_evtdup) {
                        merror(FIM_ERROR_WHODATA_HANDLER_REMOVE, hash_id);
                        free_whodata_event(w_evt);
                        goto clean;
                    }
                    free_whodata_event(w_evtdup);

                    if (result = whodata_hash_add(syscheck.wdata.fd, hash_id, w_evt, "whodata"), result != 2) {
                        if(result == 1){
                            merror(FIM_ERROR_WHODATA_EVENTADD, "whodata", hash_id); // LCOV_EXCL_LINE
                        }
                        free_whodata_event(w_evt);
                        goto clean;
                    }
                }
            break;

            // Write fd
            case 4663:
                if (w_evt = OSHash_Get(syscheck.wdata.fd, hash_id), !w_evt) {
                    goto clean;
                }

                // Check if the mask is relevant
                if (whodata_get_access_mask(buffer, &mask)) {
                    goto clean;
                }

                if (!mask) {
                    goto clean;
                }

                w_evt->mask |= mask;

                // Get the event time
                if (buffer[RENDERED_TIMESTAMP].Type != EvtVarTypeFileTime) {
                    mwarn(FIM_WHODATA_PARAMETER, buffer[RENDERED_TIMESTAMP].Type, "event_time");
                    w_evt->scan_directory = 2;
                    goto clean;
                }

                // Check if it is a rename or copy event
                if (w_evt->scan_directory == 0 || (w_evt->mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0) {
                    goto clean;
                }

                // Check if is a valid directory
                if (w_evt->config_node < 0) {
                    mdebug2(FIM_WHODATA_DIRECTORY_DISCARDED, w_evt->path);
                    w_evt->scan_directory = 2;
                    break;
                }

                w_rwlock_wrlock(&syscheck.wdata.directories->mutex);

                if (w_dir = OSHash_Get(syscheck.wdata.directories, w_evt->path), w_dir) {
                    FILETIME ft;

                    if ((buffer[RENDERED_TIMESTAMP].FileTimeVal - w_dir->QuadPart) < FILETIME_SECOND) {
                        w_rwlock_unlock(&syscheck.wdata.directories->mutex);
                        mdebug2(FIM_WHODATA_DIRECTORY_SCANNED, w_evt->path);
                        w_evt->scan_directory = 3;
                        break;
                    }
                    GetSystemTimeAsFileTime(&ft);
                    w_dir->LowPart = ft.dwLowDateTime;
                    w_dir->HighPart = ft.dwHighDateTime;

                    w_rwlock_unlock(&syscheck.wdata.directories->mutex);

                    mdebug2(FIM_WHODATA_CHECK_NEW_FILES, w_evt->path);
                } else {
                    w_rwlock_unlock(&syscheck.wdata.directories->mutex);
                    os_calloc(1, sizeof(whodata_directory), w_dir);

                    if (result = whodata_hash_add(syscheck.wdata.directories, w_evt->path, w_dir, "directories"), result != 2) {
                        w_evt->scan_directory = 2;
                        free(w_dir);
                        break;
                    } else {
                        mdebug2(FIM_WHODATA_CHECK_NEW_FILES, w_evt->path);
                    }
                }
            break;

            // Close fd
            case 4658:
                os_calloc(1, sizeof(fim_element), item);
                item->mode = FIM_WHODATA;

                if (w_evt = OSHash_Delete_ex(syscheck.wdata.fd, hash_id), w_evt && w_evt->path) {

                    if (!w_evt->scan_directory) {

                        fim_whodata_event(w_evt);

                    } else if (w_evt->scan_directory == 1) {
                        // Directory scan has been aborted if scan_directory is 2
                        if (w_evt->mask & DELETE) {
                            fim_whodata_event(w_evt);

                        } else if(w_evt->mask & FILE_APPEND_DATA || w_evt->mask & FILE_WRITE_DATA) {
                            // Find new files
                            fim_whodata_event(w_evt);

                        } else {
                            mdebug2(FIM_WHODATA_NO_NEW_FILES, w_evt->path, w_evt->mask);
                        }

                    } else if (w_evt->scan_directory == 2) {
                        mdebug1(FIM_WHODATA_SCAN_ABORTED, w_evt->path);
                    }
                }

                free_whodata_event(w_evt);
                os_free(item);
            break;

            default:
                merror(FIM_ERROR_WHODATA_EVENTID);
                goto clean;
        }
    }
    retval = 0;
clean:
    os_free(buffer);
    return retval;
}

int whodata_audit_start() {
    // Set the hash table of directories
    if (syscheck.wdata.directories = OSHash_Create(), !syscheck.wdata.directories) {
        return 1;
    }
    // Set the hash table of file descriptors
    // We assume that its default value is 1024
    if (syscheck.wdata.fd = OSHash_Create(), !syscheck.wdata.fd) {
        return 1;
    }

    OSHash_SetFreeDataPointer(syscheck.wdata.fd, (void (*)(void *))free_whodata_event);

    minfo(FIM_WHODATA_VOLUMES);
    get_volume_names();

    return 0;
}

long unsigned int WINAPI state_checker(__attribute__((unused)) void *_void) {
    int i;
    int exists;
    whodata_dir_status *d_status;
    int interval;
    OSHashNode *w_dir_node;
    OSHashNode *w_dir_node_next;
    whodata_directory *w_dir;
    unsigned int w_dir_it;
    FILETIME current_time;
    ULARGE_INTEGER stale_time;

    if (!syscheck.wdata.interval_scan) {
        interval = WDATA_DEFAULT_INTERVAL_SCAN;
    } else {
        interval = syscheck.wdata.interval_scan;
    }

    mdebug1(FIM_WHODATA_CHECKTHREAD, interval);

    while (FOREVER()) {
        for (i = 0; syscheck.dir[i]; i++) {
            exists = 0;
            d_status = &syscheck.wdata.dirs_status[i];

            if (!(d_status->status & WD_CHECK_WHODATA)) {
                // It is not whodata
                continue;
            }

            switch (check_path_type(syscheck.dir[i])) {
                case 0:
                    // Unknown device type or does not exist
                    exists = 0;
                break;
                case 1:
                    exists = 1;
                    d_status->object_type = WD_STATUS_FILE_TYPE;
                break;
                case 2:
                    exists = 1;
                    d_status->object_type = WD_STATUS_DIR_TYPE;
                break;

            }

            if (exists) {
                if (!(d_status->status & WD_STATUS_EXISTS)) {
                    minfo(FIM_WHODATA_READDED, syscheck.dir[i]);
                    if (set_winsacl(syscheck.dir[i], i)) {
                        merror(FIM_ERROR_WHODATA_ADD_DIRECTORY, syscheck.dir[i]);
                        d_status->status &= ~WD_CHECK_WHODATA;
                        syscheck.opts[i] &= ~WHODATA_ACTIVE;
                        d_status->status |= WD_CHECK_REALTIME;
                        syscheck.realtime_change = 1;
                        continue;
                    }
                    d_status->status |= WD_STATUS_EXISTS;
                } else {
                    // Check if the SACL is invalid
                    if (check_object_sacl(syscheck.dir[i], (d_status->object_type == WD_STATUS_FILE_TYPE) ? 1 : 0)) {
                        minfo(FIM_WHODATA_SACL_CHANGED, syscheck.dir[i]);
                        // Mark the directory to prevent its children from
                        // sending partial whodata alerts
                        d_status->status &= ~WD_CHECK_WHODATA;
                        // Removes CHECK_WHODATA from directory properties to prevent from
                        // being found in the whodata callback for Windows
                        syscheck.opts[i] &= ~WHODATA_ACTIVE;
                        // Mark it to prevent the restoration of its SACL
                        d_status->status &= ~WD_IGNORE_REST;
                        // Mark it to be monitored by Realtime
                        d_status->status |= WD_CHECK_REALTIME;
                        syscheck.realtime_change = 1;
                        notify_SACL_change(syscheck.dir[i]);
                        continue;
                    }
                }
            } else {
                mdebug1(FIM_WHODATA_DELETE, syscheck.dir[i]);
                d_status->status &= ~WD_STATUS_EXISTS;
                d_status->object_type = WD_STATUS_UNK_TYPE;
            }
            // Set the timestamp
            GetSystemTime(&d_status->last_check);
        }

        // Go through syscheck.wdata.directories and remove stale entries
        GetSystemTimeAsFileTime(&current_time);

        stale_time.LowPart = current_time.dwLowDateTime;
        stale_time.HighPart = current_time.dwHighDateTime;

        // 5 seconds ago
        stale_time.QuadPart -= 5 * FILETIME_SECOND;

        w_dir_it = 0;
        w_rwlock_wrlock(&syscheck.wdata.directories->mutex);

        while (w_dir_it <= syscheck.wdata.directories->rows) {
            w_dir_node = syscheck.wdata.directories->table[w_dir_it];
            w_dir_node_next = w_dir_node;

            while(w_dir_node_next) {
                w_dir_node_next = w_dir_node_next->next;

                w_dir = w_dir_node->data;
                if (w_dir->QuadPart < stale_time.QuadPart) {
                    if (w_dir = OSHash_Delete(syscheck.wdata.directories, w_dir_node->key), w_dir) {
                        free(w_dir);
                    }
                }
                w_dir_node = w_dir_node_next;
            }
            w_dir_it++;
        }

        w_rwlock_unlock(&syscheck.wdata.directories->mutex);

        sleep(interval);
    }

    return 0;
}

int set_policies() {
    int result_code = 0;
    FILE *f_backup = NULL;
    FILE *f_new = NULL;
    char buffer[OS_MAXSTR];
    char command[OS_SIZE_1024];
    int retval = 1;
    static const char *WPOL_FILE_SYSTEM_SUC = ",System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,1\n";
    static const char *WPOL_HANDLE_SUC = ",System,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,1\n";

    if (!IsFile(WPOL_BACKUP_FILE) && remove(WPOL_BACKUP_FILE)) {
        merror(FIM_ERROR_WPOL_BACKUP_FILE_REMOVE, WPOL_BACKUP_FILE, strerror(errno), errno);
        goto end;
    }

    snprintf(command, OS_SIZE_1024, WPOL_BACKUP_COMMAND, WPOL_BACKUP_FILE);

    // Get the current policies
    int wm_exec_ret_code = wm_exec(command, NULL, &result_code, 5, NULL);
    if (wm_exec_ret_code || result_code) {
        retval = 2;
        merror(FIM_WARN_WHODATA_AUTOCONF);
        goto end;
    }

    if (f_backup = fopen (WPOL_BACKUP_FILE, "r"), !f_backup) {
        merror(FIM_ERROR_WPOL_BACKUP_FILE_OPEN, WPOL_BACKUP_FILE, strerror(errno), errno);
        goto end;
    }
    if (f_new = fopen (WPOL_NEW_FILE, "w"), !f_new) {
        merror(FIM_ERROR_WPOL_BACKUP_FILE_OPEN, WPOL_NEW_FILE, strerror(errno), errno);
        goto end;
    }

    // Copy the policies
    while (fgets(buffer, OS_MAXSTR - 60, f_backup)) {
        fprintf(f_new, buffer);
    }

    // Add the new policies
    fprintf(f_new, WPOL_FILE_SYSTEM_SUC);
    fprintf(f_new, WPOL_HANDLE_SUC);

    fclose(f_new);

    snprintf(command, OS_SIZE_1024, WPOL_RESTORE_COMMAND, WPOL_NEW_FILE);

    // Set the new policies
    wm_exec_ret_code = wm_exec(command, NULL, &result_code, 5, NULL);
    if (wm_exec_ret_code || result_code) {
        retval = 2;
        merror(FIM_WARN_WHODATA_AUTOCONF);
        goto end;
    }

    retval = 0;
    restore_policies = 1;
end:
    if (f_backup) {
        fclose(f_backup);
    }
    return retval;
}

void set_subscription_query(wchar_t *query) {
    snwprintf(query, OS_MAXSTR, L"Event[ System[band(Keywords, %llu)] " \
                                    "and " \
                                        "( " \
                                            "( " \
                                                "( " \
                                                    "EventData/Data[@Name='ObjectType'] = 'File' " \
                                                ") " \
                                            "and " \
                                                "( " \
                                                    "(  " \
                                                        "System/EventID = 4656 " \
                                                    "or " \
                                                        "System/EventID = 4663 " \
                                                    ") " \
                                                "and " \
                                                    "( " \
                                                        "EventData[band(Data[@Name='AccessMask'], %lu)] " \
                                                    ") " \
                                                ") " \
                                            ") " \
                                        "or " \
                                            "System/EventID = 4658 " \
                                        ") " \
                                    "]",
            AUDIT_SUCCESS, // Only successful events
            criteria); // For 4663 and 4656 events need write, delete, change_attributes or change_permissions accesss
}

int check_object_sacl(char *obj, int is_file) {
    HANDLE hdle = NULL;
    PACL sacl = NULL;
    int retval = 1;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    long int result;
    int privilege_enabled = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hdle)) {
        merror(FIM_ERROR_SACL_OPENPROCESSTOKEN, GetLastError());
        return 1;
    }

    if (set_privilege(hdle, priv, TRUE)) {
        merror(FIM_ERROR_SACL_ELEVATE_PRIVILEGE, GetLastError());
        goto end;
    }

    privilege_enabled = 1;
    if (result = GetNamedSecurityInfo(obj, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &sacl, &security_descriptor), result != ERROR_SUCCESS) {
        merror(FIM_ERROR_SACL_GETSECURITYINFO, result);
        goto end;
    }

    if (is_valid_sacl(sacl, is_file) == 1) {
        // Is a valid SACL
        retval = 0;
    }

end:
    if (privilege_enabled) {
        // Disable the privilege
        if (set_privilege(hdle, priv, FALSE)) {
            merror(FIM_ERROR_SACL_SET_PRIVILEGE, GetLastError());
        }
    }
    if (hdle) {
        CloseHandle(hdle);
    }
    if (security_descriptor) {
        LocalFree((HLOCAL)security_descriptor);
    }
    if (sacl) {
        LocalFree((HLOCAL)sacl);
    }
    return retval;
}

int whodata_hash_add(OSHash *table, char *id, void *data, char *tag) {
    int result;

    if (result = OSHash_Add_ex(table, id, data), result != 2) {
        if (!result) {
            merror(FIM_ERROR_WHODATA_EVENTADD, tag, id);
        } else if (result == 1) {
            mdebug2(FIM_ERROR_WHODATA_EVENTADD_DUP, tag, id);
        }
    }

    return result;
}

void notify_SACL_change(char *dir) {
    char msg_alert[OS_SIZE_1024 + 1];
    snprintf(msg_alert, OS_SIZE_1024, "ossec: Audit: The SACL of '%s' has been modified and can no longer be scanned in whodata mode.", dir);
    SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
}

int get_volume_names() {
    char *convert_device;
    char *convert_volume;
    wchar_t device_name[MAX_PATH] = L"";
    wchar_t volume_name[MAX_PATH] = L"";
    HANDLE fh = INVALID_HANDLE_VALUE;
    unsigned long char_count = 0;
    size_t index = 0;
    size_t success = -1;
    size_t win_error = ERROR_SUCCESS;

    // Enumerate all volumes in the system.
    fh = FindFirstVolumeW(volume_name, ARRAYSIZE(volume_name));

    if (fh == INVALID_HANDLE_VALUE) {
        win_error = GetLastError();
        mwarn("FindFirstVolumeW failed (%u)'%s'", win_error, strerror(win_error));
        FindVolumeClose(fh);
        return success;
    }

    os_calloc(MAX_PATH, sizeof(char), convert_volume);
    os_calloc(MAX_PATH, sizeof(char), convert_device);

    // The loop ends when there are no more volumes
    while (1) {
        //  Skip the \\?\ prefix and remove the trailing backslash.
        index = wcslen(volume_name) - 1;

        // Convert volume_name
        wcstombs(convert_volume, volume_name, ARRAYSIZE(volume_name));

        if (volume_name[0]     != L'\\' ||
            volume_name[1]     != L'\\' ||
            volume_name[2]     != L'?'  ||
            volume_name[3]     != L'\\' ||
            volume_name[index] != L'\\')
        {
            mwarn("Find Volume returned a bad path: %s", convert_volume);
            break;
        }

        // QueryDosDeviceW does not allow a trailing backslash,
        // so temporarily remove it.
        volume_name[index] = '\0';
        char_count = QueryDosDeviceW(&volume_name[4], device_name, ARRAYSIZE(device_name));
        volume_name[index] = '\\';

        if (char_count == 0) {
            win_error = GetLastError();
            mwarn("QueryDosDeviceW failed (%u)'%s'", win_error, strerror(win_error));
            break;
        }

        // Convert device name
        wcstombs(convert_device, device_name, ARRAYSIZE(device_name));
        // Get all drive letters
        get_drive_names(volume_name, convert_device);

        // Move on to the next volume.
        if (!FindNextVolumeW(fh, volume_name, ARRAYSIZE(volume_name))) {
            win_error = GetLastError();

            if (win_error != ERROR_NO_MORE_FILES) {
                mwarn("FindNextVolumeW failed (%u)'%s'", win_error, strerror(win_error));
                break;
            }

            // Finished iterating, through all the volumes.
            success = 0;
            break;
        }

    }

    FindVolumeClose(fh);

    os_free(convert_device);
    os_free(convert_volume);

    return success;
}

int get_drive_names(wchar_t *volume_name, char *device) {

    wchar_t *names = NULL;
    wchar_t *nameit = NULL;
    unsigned long char_count = MAX_PATH + 1;
    unsigned int device_it;
    size_t success = -1;
    size_t retval = -1;

    while (1) {
        // Allocate a buffer to hold the paths.
        os_calloc(char_count, sizeof(wchar_t), names);

        // Obtain all of the paths for this volume.
        success = GetVolumePathNamesForVolumeNameW(
            volume_name, names, char_count, &char_count
            );

        if (success) {
            break;
        }

        if (retval = GetLastError(), retval != ERROR_MORE_DATA) {
            mwarn("GetVolumePathNamesForVolumeNameW (%u)'%s'", retval, strerror(retval));
            break;
        }

        //  Try again with the new suggested size.
        os_free(names);
        names = NULL;
    }

    if (success) {
        // Save information in FIM whodata structure
        char convert_name[MAX_PATH] = "";

        for (nameit = names; nameit[0] != L'\0'; nameit += wcslen(nameit) + 1) {
            wcstombs(convert_name, nameit, wcslen(nameit));
            mdebug1(FIM_WHODATA_DEVICE_LETTER, device, convert_name);

            if(syscheck.wdata.device) {
                device_it = 0;

                while(syscheck.wdata.device[device_it]) {
                    device_it++;
                }

                os_realloc(syscheck.wdata.device,
                        (device_it + 2) * sizeof(char*),
                        syscheck.wdata.device);
                os_strdup(device, syscheck.wdata.device[device_it]);
                syscheck.wdata.device[device_it + 1] = NULL;

                os_realloc(syscheck.wdata.drive,
                        (device_it + 2) * sizeof(char*),
                        syscheck.wdata.drive);
                os_strdup(convert_name, syscheck.wdata.drive[device_it]);
                syscheck.wdata.drive[device_it + 1] = NULL;

            } else {
                os_calloc(2, sizeof(char*), syscheck.wdata.device);
                os_strdup(device, syscheck.wdata.device[0]);
                syscheck.wdata.device[1] = NULL;

                os_calloc(2, sizeof(char*), syscheck.wdata.drive);
                os_strdup(convert_name, syscheck.wdata.drive[0]);
                syscheck.wdata.drive[1] = NULL;
            }
        }
    }
    os_free(names);

    return 0;
}

void replace_device_path(char **path) {
    char *new_path;
    unsigned int iterator = 0;

    if (**path != '\\') {
        return;
    }

    while (syscheck.wdata.device[iterator]) {
        size_t dev_size = strlen(syscheck.wdata.device[iterator]);

        mdebug2(FIM_WHODATA_DEVICE_PATH, syscheck.wdata.device[iterator], *path);

        if (!strncmp(*path, syscheck.wdata.device[iterator], dev_size)) {
            size_t new_path_size = strlen(syscheck.wdata.drive[iterator]) + (size_t) (*path - dev_size);

            os_calloc(new_path_size + 1, sizeof(char), new_path);
            snprintf(new_path, new_path_size, "%s%s", syscheck.wdata.drive[iterator], *path + dev_size);
            mdebug2(FIM_WHODATA_DEVICE_REPLACE, *path, new_path);

            os_free(*path);
            *path = new_path;
            break;
        }

        iterator++;
    }

}

char *get_whodata_path(const short unsigned int *win_path) {
    int count;
    char *path = NULL;
    int error = -1;

    if (count = WideCharToMultiByte(CP_ACP, 0, win_path, -1, NULL, 0, NULL, NULL), count > 0) {
        os_calloc(count + 1, sizeof(char), path);
        if (count = WideCharToMultiByte(CP_ACP, 0, win_path, -1, path, count, NULL, NULL), count > 0) {
            path[count] = '\0';
        } else {
            error = GetLastError();
        }
    } else {
        error = GetLastError();
    }

    if (count <= 0) {
        mdebug1(FIM_WHODATA_PATH_NOPROCCESED, error);
        os_free(path);
    }

    return path;
}

int whodata_path_filter(char **path) {
    if (check_removed_file(*path)) {
        mdebug2(FIM_DISCARD_RECYCLEBIN, *path);
        return 1;
    }

    if (sys_64) {
        whodata_adapt_path(path);
    }

    return 0;
}

void whodata_adapt_path(char **path) {
    const char *system_32 = ":\\windows\\system32";
    const char *system_wow64 = ":\\windows\\syswow64";
    const char *system_native = ":\\windows\\sysnative";
    char *new_path = NULL;

    if (strstr(*path, system_32)) {
        new_path = wstr_replace(*path, system_32, system_native);

    } else if (strstr(*path, system_wow64)) {
        new_path = wstr_replace(*path, system_wow64, system_32);
    }

    if (new_path) {
        mdebug2(FIM_WHODATA_CONVERT_PATH, *path, new_path);
        free(*path);
        *path = new_path;
    }
}

int whodata_check_arch() {
    HKEY RegistryKey;
    int retval = OS_INVALID;
    char arch[64 + 1] = "";
    long unsigned int data_size = 64;
    unsigned int result;
    const char *environment_key = "System\\CurrentControlSet\\Control\\Session Manager\\Environment";
    const char *processor_arch = "PROCESSOR_ARCHITECTURE";

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, environment_key, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
        merror(SK_REG_OPEN, environment_key);
        return OS_INVALID;
    } else {
        if (result = RegQueryValueEx(RegistryKey, TEXT(processor_arch), NULL, NULL, (LPBYTE)&arch, &data_size), result != ERROR_SUCCESS) {
            merror(FIM_ERROR_WHODATA_WIN_ARCH, (unsigned int)result);
        } else {

            if (!strncmp(arch, "AMD64", 5) || !strncmp(arch, "IA64", 4) || !strncmp(arch, "ARM64", 5)) {
                sys_64 = 1;
                retval = 0;
            } else if (!strncmp(arch, "x86", 3)) {
                sys_64 = 0;
                retval = 0;
            }
        }
        RegCloseKey(RegistryKey);
    }

    return retval;
}

int w_update_sacl(const char *obj_path) {
    SYSTEM_AUDIT_ACE *ace = NULL;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    HANDLE hdle = NULL;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    PACL old_sacl = NULL;
    PACL new_sacl = NULL;
    long unsigned result;
    unsigned long new_sacl_size;
    int retval = OS_INVALID;
    int privilege_enabled = 0;
    ACL_SIZE_INFORMATION old_sacl_info;
    PVOID entry_access_it = NULL;
    unsigned int i;

    if (!everyone_sid) {
        if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid)) {
            merror(FIM_ERROR_WHODATA_WIN_SIDERROR, GetLastError());
            goto end;
        }
    }

    if (!ev_sid_size) {
        ev_sid_size = GetLengthSid(everyone_sid);
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hdle)) {
        merror(FIM_ERROR_WHODATA_OPEN_TOKEN, GetLastError());
        goto end;
    }

    if (set_privilege(hdle, priv, TRUE)) {
        merror(FIM_ERROR_WHODATA_ACTIVATE_PRIV, GetLastError());
        goto end;
    }

    privilege_enabled = 1;

    if (result = GetNamedSecurityInfo(obj_path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &old_sacl, &security_descriptor), result != ERROR_SUCCESS) {
        merror(FIM_ERROR_WHODATA_GETNAMEDSECURITY, result);
        goto end;
    }

    ZeroMemory(&old_sacl_info, sizeof(ACL_SIZE_INFORMATION));
    // Get SACL size
    if (old_sacl && !GetAclInformation(old_sacl, (LPVOID)&old_sacl_info, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
        merror(FIM_ERROR_WHODATA_SACL_SIZE, obj_path);
        goto end;
    }

    // Set the new ACL size
    new_sacl_size = (old_sacl ? old_sacl_info.AclBytesInUse : sizeof(ACL)) + sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size;

    if (new_sacl = (PACL)win_alloc(new_sacl_size), !new_sacl) {
        merror(FIM_ERROR_WHODATA_SACL_MEMORY, obj_path);
        goto end;
    }

    if (!InitializeAcl(new_sacl, new_sacl_size, ACL_REVISION)) {
        merror(FIM_ERROR_WHODATA_SACL_NOCREATE, obj_path, GetLastError());
        goto end;
    }

    if (ace = (SYSTEM_AUDIT_ACE *)win_alloc(sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(DWORD)), !ace) {
        merror(FIM_ERROR_WHODATA_ACE_MEMORY, obj_path, GetLastError());
        goto end;
    }

    ace->Header.AceType  = SYSTEM_AUDIT_ACE_TYPE;
    ace->Header.AceFlags = FAILED_ACCESS_ACE_FLAG;
    ace->Header.AceSize  = LOWORD(sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(DWORD));
    ace->Mask            = 0;

    if (!CopySid(ev_sid_size, &ace->SidStart, everyone_sid)) {
        merror(FIM_ERROR_WHODATA_COPY_SID, obj_path, ev_sid_size, GetLastError());
        goto end;
    }

    if (old_sacl) {
        if (old_sacl_info.AceCount) {
            for (i = 0; i < old_sacl_info.AceCount; i++) {
               if (!GetAce(old_sacl, i, &entry_access_it)) {
                   merror(FIM_ERROR_WHODATA_ACE_NOOBTAIN, i, obj_path);
                   goto end;
               }

               if (!AddAce(new_sacl, ACL_REVISION, MAXDWORD, entry_access_it, ((PACE_HEADER)entry_access_it)->AceSize)) {
                   merror(FIM_ERROR_WHODATA_ACE_NUMBER, i, obj_path);
                   goto end;
               }
           }
        }
    }

    // Add the new ACE
    if (!AddAce(new_sacl, ACL_REVISION, 0, (LPVOID)ace, ace->Header.AceSize)) {
        merror(FIM_ERROR_WHODATA_ACE_NOADDED, obj_path, GetLastError());
        goto end;
    }

    if (result = SetNamedSecurityInfo((char *) obj_path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, new_sacl), result != ERROR_SUCCESS) {
        merror(FIM_ERROR_WHODATA_SETNAMEDSECURITY, result);
        goto end;
    }

    retval = 0;
end:
    if (privilege_enabled && set_privilege(hdle, priv, FALSE)) {
        merror(FIM_ERROR_WHODATA_ACTIVATE_PRIV, GetLastError());
        goto end;
    }

    if (security_descriptor) {
        LocalFree((HLOCAL)security_descriptor);
    }

    if (old_sacl) {
        LocalFree((HLOCAL)old_sacl);
    }

    if (new_sacl) {
        LocalFree((HLOCAL)new_sacl);
    }

    if (hdle) {
        CloseHandle(hdle);
    }

    if (ace) {
        LocalFree((HLOCAL)ace);
    }

    return retval;
}

#endif
