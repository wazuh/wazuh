#ifdef WIN32

#define _WIN32_WINNT 0x600  // Windows Vista or later (must be included in the dll)
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winevt.h>
#include "shared.h"
#include "hash_op.h"
#include "syscheck.h"

#define WLIST_ALERT_THRESHOLD 80 // 80%
#define WLIST_REMOVE_MAX 10 // 10%
#define WLIST_MAX_SIZE OS_SIZE_1024

static PSID everyone_sid = NULL;
static size_t ev_sid_size = 0;
static unsigned short inherit_flag = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE; //SUB_CONTAINERS_AND_OBJECTS_INHERIT

void restore_sacls();
int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable);
int is_valid_sacl(PACL sacl);
unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, void *_void, EVT_HANDLE event);
char *guid_to_string(GUID *guid);

// Whodata list operations
whodata_event_node *whodata_list_add(char *id);
void whodata_list_remove(whodata_event_node *node);
void whodata_list_set_values();
void whodata_list_remove_multiple(size_t quantity);

char *guid_to_string(GUID *guid) {
    char *string_guid;
    os_calloc(40, sizeof(char *), string_guid);

    snprintf(string_guid, 40, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
    guid->Data1,
    guid->Data2,
    guid->Data3,
    guid->Data4[0], guid->Data4[1],
    guid->Data4[2], guid->Data4[3],guid->Data4[4], guid->Data4[5],guid->Data4[6], guid->Data4[7]);

    return string_guid;
}

int set_winsacl(const char *dir, int position) {
    static LPCTSTR priv = "SeSecurityPrivilege";
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

    mdebug2("The SACL of '%s' will be configured.", dir);

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES /*| ACCESS_SYSTEM_SECURITY*/, &hdle)) {
		merror("OpenProcessToken() failed. Error '%lu'.", GetLastError());
		return 1;
	}

	if (set_privilege(hdle, priv, TRUE)) {
		merror("The privilege could not be activated. Error: '%ld'.", GetLastError());
		return 1;
	}

	if (result = GetNamedSecurityInfo(dir, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &old_sacl, &security_descriptor), result != ERROR_SUCCESS) {
		merror("GetNamedSecurityInfo() failed. Error '%ld'", result);
        goto end;
	}

    ZeroMemory(&old_sacl_info, sizeof(ACL_SIZE_INFORMATION));

    // Check if the sacl has what the whodata scanner needs
    switch(is_valid_sacl(old_sacl)) {
        case 0:
            mdebug1("It is necessary to configure the SACL of '%s'.", dir);
            syscheck.wdata.ignore_rest[position] = 1;

            // Get SACL size
            if (!GetAclInformation(old_sacl, (LPVOID)&old_sacl_info, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
                merror("The size of the '%s' SACL could not be obtained.", dir);
                goto end;
            }
        break;
        case 1:
            mdebug1("It is not necessary to configure the SACL of '%s'.", dir);
            retval = 0;
            goto end;
        case 2:
            // Empty SACL
            syscheck.wdata.ignore_rest[position] = 1;
            old_sacl_info.AclBytesInUse = sizeof(ACL);
            break;
    }
    if (!ev_sid_size) {
        ev_sid_size = GetLengthSid(everyone_sid);
    }

    // Set the new ACL size
    new_sacl_size = old_sacl_info.AclBytesInUse + sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(unsigned long);

    if (new_sacl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, new_sacl_size), !new_sacl) {
        merror("No memory could be reserved for the new SACL of '%s'.", dir);
        goto end;
    }

    if (!InitializeAcl(new_sacl, new_sacl_size, ACL_REVISION)) {
        merror("The new SACL for '%s' could not be created.", dir);
        goto end;
    }

    // If SACL is present, copy it to a new SACL
    if (old_sacl) {
        if (old_sacl_info.AceCount) {
            for (i = 0; i < old_sacl_info.AceCount; i++) {
               if (!GetAce(old_sacl, i, &entry_access_it)) {
                   merror("The ACE number %i for '%s' could not be obtained.", i, dir);
                   goto end;
               }

               if (!AddAce(new_sacl, ACL_REVISION, MAXDWORD, entry_access_it, ((PACE_HEADER)entry_access_it)->AceSize)) {
                   merror("The ACE number %i of '%s' could not be copied to the new ACL.", i, dir);
                   goto end;
               }
           }
        }
    }
    // Build the new ACE
    if (ace = (SYSTEM_AUDIT_ACE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(DWORD)), !ace) {
        merror("No memory could be reserved for the new ACE of '%s'.", dir);
        goto end;
    }

    ace->Header.AceType  = SYSTEM_AUDIT_ACE_TYPE;
    ace->Header.AceFlags = inherit_flag | SUCCESSFUL_ACCESS_ACE_FLAG;
    ace->Header.AceSize  = LOWORD(sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(DWORD));
    ace->Mask            = FILE_WRITE_DATA | DELETE;
    if (!CopySid(ev_sid_size, &ace->SidStart, everyone_sid)) {
        goto end;
    }

    // Add the new ACE
    if (!AddAce(new_sacl, ACL_REVISION, 0, (LPVOID)ace, ace->Header.AceSize)) {
		wprintf(L"The new ACE could not be added to '%s'.", dir);
		goto end;
	}

    // Set a new ACL for the security descriptor
    if (result = SetNamedSecurityInfo((char *) dir, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, new_sacl), result != ERROR_SUCCESS) {
        merror("SetNamedSecurityInfo() failed. Error: '%lu'", result);
        goto end;
    }

	// Disable the privilege
	if (set_privilege(hdle, priv, 0)) {
		merror("Failed to disable the privilege. Error '%lu'.", GetLastError());
        goto end;
	}

	CloseHandle(hdle);
	retval = 0;
end:
    if (security_descriptor) {
        LocalFree((HLOCAL)security_descriptor);
    }

    if (old_sacl) {
        LocalFree((HLOCAL)old_sacl);
    }

    if (new_sacl) {
        LocalFree((HLOCAL)new_sacl);
    }
    return retval;
}

int is_valid_sacl(PACL sacl) {
    int i;
    ACCESS_ALLOWED_ACE *ace;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    if (!everyone_sid) {
        if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid)) {
            merror("Could not obtain the sid of Everyone. Error '%lu'.", GetLastError());
            return 0;
        }
    }

    if (!sacl) {
        mdebug2("No SACL found on target. A new one will be created.");
        return 2;
    }

    for (i = 0; i < sacl->AceCount; i++) {
        if (!GetAce(sacl, i, (LPVOID*)&ace)) {
            merror("Could not extract the ACE information. Error: '%lu'.", GetLastError());
            return 0;
        }
        if ((ace->Header.AceFlags & inherit_flag) && // Check folder and subfolders
            (ace->Header.AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) && // Check successful attemp
            (ace->Mask & (FILE_WRITE_DATA | DELETE)) && // Check write and delete permission
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
		merror("Could not find the '%s' privilege. Error: %lu", privilege, GetLastError());
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
		merror("AdjustTokenPrivileges() failed. Error: '%lu'", GetLastError());
		return 1;
	}

    if (enable) {
        mdebug2("The '%s' privilege has been added.", privilege);
    } else {
        mdebug2("The '%s' privilege has been removed.", privilege);
    }

	return 0;
}

int run_whodata_scan() {
    // Set the signal handler to restore the policies
    atexit(restore_sacls);
    // Set the whodata callback
    if (!EvtSubscribe(NULL, NULL, L"Security", L"Event[(((System/EventID = 4656 or System/EventID = 4663) and (EventData/Data[@Name='ObjectType'] = 'File')) or System/EventID = 4658 or System/EventID = 4660)]", NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)whodata_callback, EvtSubscribeToFutureEvents)) {
        merror("Event Channel subscription could not be made. Whodata scan is disabled.");
        return 1;
    }
    return 0;
}

/* Removes added security audit policies */
void restore_sacls() {
    int i;
    PACL sacl_it;
    HANDLE hdle = NULL;
    LPCTSTR priv = "SeSecurityPrivilege";
    DWORD result = 0;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hdle)) {
        merror("OpenProcessToken() failed restoring the SACLs. Error '%lu'.", GetLastError());
        return;
    }

    if (set_privilege(hdle, priv, TRUE)) {
        merror("The privilege could not be activated restoring the SACLs. Error: '%ld'.", GetLastError());
        return;
    }

    for (i = 0; syscheck.dir[i] != NULL; i++) {
        if (syscheck.wdata.ignore_rest[i]) {
            sacl_it = NULL;
            if (result = GetNamedSecurityInfo(syscheck.dir[i], SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &sacl_it, &security_descriptor), result != ERROR_SUCCESS) {
                merror("GetNamedSecurityInfo() failed restoring the SACLs. Error '%ld'.", result);
                break;
            }

            // The ACE we added is in position 0
            if (!DeleteAce(sacl_it, 0)) {
                merror("DeleteAce() failed restoring the SACLs. Error '%ld'", GetLastError());
                break;
            }

            // Set the SACL
            if (result = SetNamedSecurityInfo((char *) syscheck.dir[i], SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, sacl_it), result != ERROR_SUCCESS) {
                merror("SetNamedSecurityInfo() failed restoring the SACL. Error: '%lu'.", result);
                break;
            }

            if (sacl_it) {
                LocalFree((HLOCAL)sacl_it);
            }

            if (security_descriptor) {
                LocalFree((HLOCAL)security_descriptor);
            }
            mdebug1("The SACL of '%s' has been restored correctly.", syscheck.dir[i]);
        }
    }

    // Disable the privilege
    if (set_privilege(hdle, priv, 0)) {
        merror("Failed to disable the privilege while restoring the SACLs. Error '%lu'.", GetLastError());
    }
    CloseHandle(hdle);
}

unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, void *_void, EVT_HANDLE event) {
    unsigned int retval = 1;
    int result;
    unsigned long p_count = 0;
    unsigned long used_size;
    EVT_HANDLE context;
    PEVT_VARIANT buffer = NULL;
    whodata_evt *w_evt;
    short event_id;
    char *user_name = NULL;
    char *path = NULL;
    char *process_name = NULL;
    unsigned __int64 process_id;
    unsigned __int64 handle_id;
    unsigned __int64 keywords;
    char *user_id;
    static const unsigned __int64 AUDIT_SUCCESS = 0x20000000000000;

    unsigned int mask;
    int position;
    static const wchar_t* event_fields[] = {
        L"Event/System/EventID",
        L"Event/EventData/Data[@Name='SubjectUserName']",
        L"Event/EventData/Data[@Name='ObjectName']",
        L"Event/EventData/Data[@Name='ProcessName']",
        L"Event/EventData/Data[@Name='ProcessId']",
        L"Event/EventData/Data[@Name='HandleId']",
        L"Event/EventData/Data[@Name='AccessMask']",
        L"Event/System/Keywords",
        L"Event/EventData/Data[@Name='SubjectUserSid']"
    };
    static unsigned int fields_number = sizeof(event_fields) / sizeof(LPWSTR);
    UNREFERENCED_PARAMETER(_void);
    if (action == EvtSubscribeActionDeliver) {
        char hash_id[21];

        // Select the interesting fields
        if (context = EvtCreateRenderContext(fields_number, event_fields, EvtRenderContextValues), !context) {
            wprintf(L"\nError creating the context. Error %lu.", GetLastError());
            return 1;
        }

        // Extract the necessary memory size
        EvtRender(context, event, EvtRenderEventValues, 0, NULL, &used_size, &p_count);
        // We may be taking more memory than we need to
		buffer = (PEVT_VARIANT)malloc(used_size);

        if (!EvtRender(context, event, EvtRenderEventValues, used_size, buffer, &used_size, &p_count)) {
			merror("Error rendering the event. Error %lu.", GetLastError());
            goto clean;
		}

        if (fields_number != p_count) {
			merror("Invalid number of rendered parameters.");
            goto clean;
        }

        // Check types
        if (buffer[0].Type != EvtVarTypeUInt16) {
            merror("Invalid parameter type (%ld) for 'event_id'.", buffer[0].Type);
            goto clean;
        }
        event_id = buffer[0].Int16Val;

        if (buffer[1].Type != EvtVarTypeString) {
            merror("Invalid parameter type (%ld) for 'user_name'.", buffer[1].Type);
            goto clean;
        }
        user_name = convert_windows_string(buffer[1].XmlVal);

        if (buffer[2].Type != EvtVarTypeString) {
            if (event_id == 4658 || event_id == 4660) {
                path = NULL;
            } else {
                merror("Invalid parameter type (%ld) for 'path'.", buffer[2].Type);
                goto clean;
            }
        }  else {
            path = convert_windows_string(buffer[2].XmlVal);
        }

        if (buffer[3].Type != EvtVarTypeString) {
            merror("Invalid parameter type (%ld) for 'process_name'.", buffer[3].Type);
            goto clean;
        }
        process_name = convert_windows_string(buffer[3].XmlVal);

        // In 32-bit Windows we find EvtVarTypeSizeT
        if (buffer[4].Type != EvtVarTypeHexInt64 && buffer[4].Type !=  EvtVarTypeSizeT) {
            merror("Invalid parameter type (%ld) for 'process_id'.", buffer[4].Type);
            goto clean;
        }
        process_id = buffer[4].UInt64Val;

        // In 32-bit Windows we find EvtVarTypeSizeT
        if (buffer[5].Type != EvtVarTypeHexInt64 && buffer[5].Type !=  EvtVarTypeSizeT) {
            merror("Invalid parameter type (%ld) for 'handle_id'.", buffer[5].Type);
            goto clean;
        }
        handle_id = buffer[5].UInt64Val;

        if (buffer[6].Type != EvtVarTypeHexInt32) {
            if (event_id == 4658 || event_id == 4660) {
                mask = 0;
            } else {
                merror("Invalid parameter type (%ld) for 'mask'.", buffer[6].Type);
                goto clean;
            }
        } else {
            mask = buffer[6].UInt32Val;
        }

        if (buffer[7].Type != EvtVarTypeHexInt64) {
            merror("Invalid parameter type (%ld) for 'keywords'.", buffer[7].Type);
            goto clean;
        }
        keywords = buffer[7].UInt64Val;

        if (buffer[8].Type != EvtVarTypeSid) {
            merror("Invalid parameter type (%ld) for 'user_id'.", buffer[8].Type);
            goto clean;
        } else if (!ConvertSidToStringSid(buffer[8].SidVal, &user_id)) {
            mdebug1("Invalid identifier for user '%s'", user_name);
            goto clean;
        }

        // Discards unsuccessful attempts
        if (!(keywords & AUDIT_SUCCESS)) {
            goto clean;
        }
        snprintf(hash_id, 21, "%llu", handle_id);
        switch(event_id) {
            // Open fd
            case 4656:
                // Check if it is a known file
                if (!OSHash_Get_ex(syscheck.fp, path)) {
                    if (position = find_dir_pos(path, 1), position < 0) {
                        // Discard the file if its monitoring has not been activated
                        mdebug2("'%s' is discarded because its monitoring is not activated.", path);
                        break;
                    }
                } else {
                    position = -1;
                }
                os_calloc(1, sizeof(whodata_evt), w_evt);
                w_evt->user_name = user_name;
                w_evt->user_id = user_id;
                w_evt->path = path;
                w_evt->dir_position = position;
                w_evt->process_name = process_name;
                w_evt->process_id = process_id;
                w_evt->mask = 0;
                w_evt->deleted = 0;
                w_evt->ppid = -1;
                w_evt->wnode = whodata_list_add(strdup(hash_id));

                user_name = NULL;
                user_id = NULL;
                path = NULL;
                process_name = NULL;

                if (result = OSHash_Add_ex(syscheck.wdata.fd, hash_id, w_evt), result != 2) {
                    if (!result) {
                        merror("The event could not be added to the whodata hash table.");
                    } else if (result == 1) {
                        merror("The event could not be added to the whodata hash table because is duplicated.");
                    }
                    retval = 1;
                    goto clean;
                }
            break;
            // Write fd
            case 4663:
                // Check if the mask is relevant
                if (mask) {
                    if (w_evt = OSHash_Get(syscheck.wdata.fd, hash_id), w_evt) {
                        w_evt->mask |= mask;
                    } else {
                        // The file was opened before Wazuh started Syscheck.
                    }
                }
            break;
            // Deleted file
            case 4660:
                if (w_evt = OSHash_Get(syscheck.wdata.fd, hash_id), w_evt) {
                    w_evt->deleted = 1;
                } else {
                    // The file was opened before Wazuh started Syscheck.
                }
            break;
            // Close fd
            case 4658:
                if (w_evt = OSHash_Delete_ex(syscheck.wdata.fd, hash_id), w_evt) {
                    if (w_evt->mask) {
                        unsigned int mask = w_evt->mask;

                        // Check if the file has been written or deleted
                        if (w_evt->deleted) {
                            char del_msg[PATH_MAX + OS_SIZE_6144 + 6];
                            char wd_sum[OS_SIZE_6144 + 1];

                            // Remove the file from the syscheck hash table
                            OSHash_Delete_ex(syscheck.fp, w_evt->path);

                            if (extract_whodata_sum(w_evt, wd_sum, OS_SIZE_6144)) {
                                merror("The whodata sum for '%s' file could not be included in the alert as it is too large.", w_evt->path);
                                *wd_sum = '\0';
                            }

                            snprintf(del_msg, PATH_MAX + OS_SIZE_6144 + 6, "-1!%s %s", wd_sum, w_evt->path);
                            send_syscheck_msg(del_msg);
                        } else if (mask & FILE_WRITE_DATA) {
                            realtime_checksumfile(w_evt->path, w_evt);
                        }
                    }
                    whodata_list_remove(w_evt->wnode);
                    free_whodata_event(w_evt);
                } else {
                    // The file was opened before Wazuh started Syscheck.
                }
            break;
            default:
                merror("Invalid EventID. The whodata cannot be extracted.");
                retval = 1;
                goto clean;
        }
    }
    retval = 0;
clean:
    free(user_name);
    free(path);
    free(process_name);
    if (user_id) {
        LocalFree(user_id);
    }
    if (buffer) {
        free(buffer);
    }
    return retval;
}

int whodata_audit_start() {
    if (syscheck.wdata.fd = OSHash_Create(), !syscheck.wdata.fd) {
        return 1;
    }
    OSHash_setSize_ex(syscheck.wdata.fd, WLIST_MAX_SIZE);
    memset(&syscheck.wlist, 0, sizeof(whodata_event_list));
    whodata_list_set_values();
    return 0;
}

whodata_event_node *whodata_list_add(char *id) {
    whodata_event_node *node = NULL;
    if (syscheck.wlist.current_size < syscheck.wlist.max_size) {
        if (!syscheck.wlist.alerted && syscheck.wlist.alert_threshold < syscheck.wlist.current_size) {
            syscheck.wlist.alerted = 1;
            mwarn("Whodata events queue for Windows has more than %d elements.", syscheck.wlist.alert_threshold);
        }
    } else {
        mdebug1("Whodata events queue for Windows is full. Removing the first %d...", syscheck.wlist.max_remove);
        whodata_list_remove_multiple(syscheck.wlist.max_remove);
    }
    os_calloc(sizeof(whodata_event_node), 1, node);
    if (syscheck.wlist.last) {
        node->next = NULL;
        node->previous = syscheck.wlist.last;
        syscheck.wlist.last = node->next;
    } else {
        node->next = node->previous = NULL;
        syscheck.wlist.last = syscheck.wlist.first = node;
    }
    node->handle_id = id;
    syscheck.wlist.current_size++;

    return node;
}

void whodata_list_remove_multiple(size_t quantity) {
    size_t i;
    whodata_evt *w_evt;
    for (i = 0; i < quantity && syscheck.wlist.first; i++) {
        if (w_evt = OSHash_Delete_ex(syscheck.wdata.fd, syscheck.wlist.first->handle_id), w_evt) {
            free_whodata_event(w_evt);
        }
        whodata_list_remove(syscheck.wlist.first);
    }
    mdebug2("%d events have been deleted from the whodata list.", quantity);
}

void whodata_list_remove(whodata_event_node *node) {
    if (node->next) {
        if (node->previous) {
            node->next->previous = node->previous;
        } else {
            node->next->previous = NULL;
            syscheck.wlist.first = node->next;
        }
    }

    if (node->previous) {
        if (node->next) {
            node->previous->next = node->next;
        } else {
            node->previous->next = NULL;
            syscheck.wlist.last = node->previous;
        }
    }
    free(node->handle_id);
    free(node);
    syscheck.wlist.current_size--;

    if (syscheck.wlist.alerted && syscheck.wlist.alert_threshold > syscheck.wlist.current_size) {
        syscheck.wlist.alerted = 0;
    }
}

void whodata_list_set_values() {
    syscheck.wlist.max_size = WLIST_MAX_SIZE;
    syscheck.wlist.max_remove = syscheck.wlist.max_size * WLIST_REMOVE_MAX * 0.01;
    syscheck.wlist.alert_threshold = syscheck.wlist.max_size * WLIST_ALERT_THRESHOLD * 0.01;
    mdebug1("Whodata event queue values for Windows -> max_size:'%d' | max_remove:'%d' | alert_threshold:'%d'.",
    syscheck.wlist.max_size, syscheck.wlist.max_remove, syscheck.wlist.alert_threshold);
}

#endif
