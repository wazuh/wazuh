/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

#ifdef WIN32

#define BUFFER_SIZE 2048*256

/* Event logging local structure */
typedef struct _os_el {
    int time_of_last;
    char *name;

    EVENTLOGRECORD *er;
    HANDLE h;

    DWORD record;
} os_el;

/** Global variables **/

/* Maximum of 9 event log sources */
os_el el[9];
int el_last = 0;
void *vista_sec_id_hash = NULL;
void *dll_hash = NULL;

/* Start the event logging for each el */
int startEL(char *app, os_el *el)
{
    DWORD NumberOfRecords = 0;

    /* Open the event log */
    el->h = OpenEventLog(NULL, app);
    if (!el->h) {
        merror(EVTLOG_OPEN, app);
        return (-1);
    }

    el->name = app;
    if (GetOldestEventLogRecord(el->h, &el->record) == 0) {
        /* Unable to read oldest event log record */
        merror(EVTLOG_GETLAST, app);
        CloseEventLog(el->h);
        el->h = NULL;
        return (-1);
    }

    if (GetNumberOfEventLogRecords(el->h, &NumberOfRecords) == 0) {
        merror(EVTLOG_GETLAST, app);
        CloseEventLog(el->h);
        el->h = NULL;
        return (-1);
    }

    if (NumberOfRecords <= 0) {
        return (0);
    }

    return ((int)NumberOfRecords);
}

/* Returns a string that is a human readable datetime from an epoch int */
char *epoch_to_human(time_t epoch)
{
    struct tm   *ts;
    static char buf[80];

    ts = localtime(&epoch);
    strftime(buf, sizeof(buf), "%Y %b %d %H:%M:%S", ts);
    return (buf);
}

/* Returns a string related to the category id of the log */
char *el_getCategory(int category_id)
{
    char *cat;
    switch (category_id) {
        case EVENTLOG_ERROR_TYPE:
            cat = "ERROR";
            break;
        case EVENTLOG_WARNING_TYPE:
            cat = "WARNING";
            break;
        case EVENTLOG_INFORMATION_TYPE:
            cat = "INFORMATION";
            break;
        case EVENTLOG_AUDIT_SUCCESS:
            cat = "AUDIT_SUCCESS";
            break;
        case EVENTLOG_AUDIT_FAILURE:
            cat = "AUDIT_FAILURE";
            break;
        default:
            cat = "Unknown";
            break;
    }
    return (cat);
}

/* Returns the event */
wchar_t *el_getEventDLL(char *evt_name, wchar_t *source, wchar_t *event)
{
    wchar_t *ret_str;
    HKEY key;
    DWORD ret;

    wchar_t keyname[512] = {L'\0'};

    char *keyname_utf8 = NULL;
    char *skey = NULL;
    wchar_t *sval = NULL;

    swprintf(keyname, 510,
             L"System\\CurrentControlSet\\Services\\EventLog\\%s\\%ls",
             evt_name,
             source);

    /* Generate UTF-8 string to use with OSHash functions */
    keyname_utf8 = convert_windows_string(keyname);
    if (!keyname_utf8) {
        return (NULL);
    }

    /* Check if we have it in memory */
    ret_str = OSHash_Get(dll_hash, keyname_utf8 + 42);
    if (ret_str) {
        free(keyname_utf8);
        return (ret_str);
    }

    /* Open Registry */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyname, 0,
                     KEY_ALL_ACCESS, &key) != ERROR_SUCCESS) {
        free(keyname_utf8);
        return (NULL);
    }

    /* Retrieve registry value */
    ret = MAX_PATH - 1;
    if (RegQueryValueExW(key, L"EventMessageFile", NULL,
                        NULL, (LPBYTE)event, &ret) != ERROR_SUCCESS) {
        event[0] = L'\0';
        RegCloseKey(key);
        free(keyname_utf8);
        return (NULL);
    } else {
        /* Adding to memory */
        skey = strdup(keyname_utf8 + 42);
        sval = wcsdup(event);
        
        if (skey != NULL && sval != NULL) {
            if (OSHash_Add(dll_hash, skey, sval) != 2) free(sval);
            free(skey);
        } else {
            merror(MEM_ERROR, errno, strerror(errno));
            if (skey != NULL) free(skey);
            if (sval != NULL) free(sval);
        }
        
        skey = NULL;
        sval = NULL;
    }

    RegCloseKey(key);
    return (event);
}

/* Returns a descriptive message of the event - Vista only */
wchar_t *el_vista_getMessage(int evt_id_int, char **el_sstring)
{
    DWORD fm_flags = 0;
    wchar_t *message = NULL;
    wchar_t *desc_string = NULL;
    char evt_id[16] = {'\0'};

    /* Flags for format event */
    fm_flags |= FORMAT_MESSAGE_FROM_STRING;
    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
    fm_flags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;

    /* Get descriptive message */
    snprintf(evt_id, 15, "%d", evt_id_int);

    desc_string = OSHash_Get(vista_sec_id_hash, evt_id);
    if (!desc_string) {
        return (NULL);
    }

    if (!FormatMessageW(fm_flags, desc_string, 0, 0,
                       message, 0, el_sstring)) {
        return (NULL);
    }

    return (message);
}

/* Returns a descriptive message of the event */
wchar_t *el_getMessage(EVENTLOGRECORD *er, char *name,
                    wchar_t *source, char **el_sstring)
{
    DWORD fm_flags = 0;
    wchar_t tmp_str[257] = {L'\0'};
    wchar_t event[MAX_PATH + 1] = {L'\0'};
    wchar_t *curr_str = NULL;
    wchar_t *next_str = NULL;
    wchar_t *message = NULL;

    HMODULE hevt;

    /* Flags for format event */
    fm_flags |= FORMAT_MESSAGE_FROM_HMODULE;
    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
    fm_flags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;

    /* Get the file name from the registry (stored on event) */
    if (!(curr_str = el_getEventDLL(name, source, event))) {
        return (NULL);
    }

    /* If our event has multiple libraries, try each one of them */
    while ((next_str = wcschr(curr_str, L';'))) {
        *next_str = L'\0';

        ExpandEnvironmentStringsW(curr_str, tmp_str, 255);

        /* Revert back old value */
        *next_str = L';';

        /* Load library */
        hevt = LoadLibraryExW(tmp_str, NULL,
                             DONT_RESOLVE_DLL_REFERENCES |
                             LOAD_LIBRARY_AS_DATAFILE);
        if (hevt) {
            if (!FormatMessageW(fm_flags, hevt, er->EventID, 0,
                               message, 0, el_sstring)) {
                message = NULL;
            }
            FreeLibrary(hevt);

            /* If we have a message, we can return it */
            if (message) {
                return (message);
            }
        }

        curr_str = next_str + 1;
    }

    /* Get last value */
    ExpandEnvironmentStringsW(curr_str, tmp_str, 255);
    hevt = LoadLibraryExW(tmp_str, NULL,
                         DONT_RESOLVE_DLL_REFERENCES |
                         LOAD_LIBRARY_AS_DATAFILE);
    if (hevt) {
        if (!FormatMessageW(fm_flags, hevt, er->EventID,
                                 0,
                                 message, 0, el_sstring)) {
            message = NULL;
        }
        FreeLibrary(hevt);

        /* If we have a message, we can return it */
        if (message) {
            return (message);
        }
    }

    return (NULL);
}

/* Reads the event log */
void readel(os_el *el, int printit)
{
    DWORD _evtid = 65535;
    DWORD nstr;
    DWORD user_size;
    DWORD domain_size;
    DWORD read, needed;
    int size_left;
    int str_size;
    int id;

    wchar_t mbuffer[BUFFER_SIZE + 1] = {L'\0'};
    wchar_t *sstr = NULL;

    wchar_t *tmp_str = NULL;
    char *category = NULL;
    wchar_t *source = NULL;
    wchar_t *computer_name = NULL;
    wchar_t *descriptive_msg = NULL;

    wchar_t el_user[OS_FLSIZE + 1] = {L'\0'};
    wchar_t el_domain[OS_FLSIZE + 1] = {L'\0'};
    wchar_t el_string[OS_MAXSTR + 1] = {L'\0'};
    wchar_t final_msg[OS_MAXSTR + 1] = {L'\0'};
    char *el_sstring[OS_FLSIZE + 1];

    char *sstr_utf8 = NULL;
    wchar_t *tmp_utf16 = NULL;
    char *final_msg_utf8 = NULL;

    /* er must point to the mbuffer */
    el->er = (EVENTLOGRECORD *) &mbuffer;

    /* Event log is not open */
    if (!el->h) {
        return;
    }

    /* Read the event log */
    while (ReadEventLogW(el->h,
                        EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                        0,
                        el->er, BUFFER_SIZE - 1, &read, &needed)) {
        if (!printit) {
            /* Set er to the beginning of the buffer */
            el->er = (EVENTLOGRECORD *)&mbuffer;
            continue;
        }


        while (read > 0) {
            /* We need to initialize every variable before the loop */
            category = el_getCategory(el->er->EventType);
            source = (wchar_t*)((LPBYTE)el->er + sizeof(EVENTLOGRECORD));
            computer_name = source + wcslen(source) + 1;
            descriptive_msg = NULL;
            memset(el_sstring, 0, (OS_FLSIZE + 1) * sizeof(char*));

            /* Get event id */
            id = (int)el->er->EventID & _evtid;

            /* Initialize domain/user size */
            user_size = 255;
            domain_size = 255;
            el_domain[0] = L'\0';
            el_user[0] = L'\0';

            /* We must have some description */
            if (el->er->NumStrings) {
                size_left = OS_MAXSTR - OS_SIZE_1024;

                sstr = (wchar_t*)((LPBYTE)el->er + el->er->StringOffset);
                el_string[0] = L'\0';

                for (nstr = 0; nstr < el->er->NumStrings; nstr++) {
                    str_size = wcslen(sstr);
                    if (size_left > 1) {
                        wcsncat(el_string, sstr, size_left);
                    }

                    tmp_str = wcschr(el_string, L'\0');
                    if (tmp_str) {
                        *tmp_str = L' ';
                        tmp_str++;
                        *tmp_str = L'\0';
                    } else {
                        merror("Invalid application string (size+)");
                    }
                    size_left -= str_size + 2;

                    if (nstr <= 92) {
                        /* FormatMessageW() requires char** for the argument list */
                        sstr_utf8 = convert_windows_string(sstr);
                        if (sstr_utf8) {
                            el_sstring[nstr] = sstr_utf8;
                            el_sstring[nstr + 1] = NULL;
                        }
                        sstr_utf8 = NULL;
                    }

                    sstr = wcschr(sstr, '\0');
                    if (sstr) {
                        sstr++;
                    } else {
                        break;
                    }
                }

                /* Get a more descriptive message (if available) */
                if (isVista && strcmp(el->name, "Security") == 0) {
                    descriptive_msg = el_vista_getMessage(id, el_sstring);
                }

                else {
                    descriptive_msg = el_getMessage(el->er,
                                                    el->name,
                                                    source,
                                                    el_sstring);
                }

                if (descriptive_msg != NULL) {
                    /* format message */
                    win_format_event_string_wide(descriptive_msg);
                }
            } else {
                swprintf(el_string, 128, L"(no message)");
            }

            /* Get username */
            if (el->er->UserSidLength) {
                SID_NAME_USE account_type;
                if (!LookupAccountSidW(NULL,
                                      (SID *)((LPBYTE)el->er +
                                              el->er->UserSidOffset),
                                      el_user,
                                      &user_size,
                                      el_domain,
                                      &domain_size,
                                      &account_type)) {
                    swprintf(el_user, 255, L"(no user)");
                    swprintf(el_domain, 255, L"no domain");
                }
            }

            else if (isVista && strcmp(el->name, "Security") == 0) {
                int uid_array_id = -1;

                switch (id) {
                    case 4624:
                        uid_array_id = 5;
                        break;
                    case 4634:
                        uid_array_id = 1;
                        break;
                    case 4647:
                        uid_array_id = 1;
                        break;
                    case 4769:
                        uid_array_id = 0;
                        break;
                }

                if ((uid_array_id >= 0) &&
                        el_sstring[uid_array_id] &&
                        el_sstring[uid_array_id + 1]) {
                    /* Get user in UTF-16LE */
                    tmp_utf16 = convert_unix_string(el_sstring[uid_array_id]);
                    if (tmp_utf16) {
                        swprintf(el_user, OS_FLSIZE, tmp_utf16);
                        free(tmp_utf16);
                        tmp_utf16 = NULL;
                    }

                    /* Get domain in UTF-16LE */
                    tmp_utf16 = convert_unix_string(el_sstring[uid_array_id + 1]);
                    if (tmp_utf16) {
                        swprintf(el_domain, OS_FLSIZE, tmp_utf16);
                        free(tmp_utf16);
                        tmp_utf16 = NULL;
                    }
                } else {
                    swprintf(el_user, 255, L"(no user)");
                    swprintf(el_domain, 255, L"no domain");
                }
            }

            else {
                swprintf(el_user, 255, L"(no user)");
                swprintf(el_domain, 255, L"no domain");
            }

            if (printit) {
                DWORD _evtid = 65535;
                int id = (int)el->er->EventID & _evtid;

                swprintf(final_msg, OS_MAXSTR - OS_LOG_HEADER - 1,
                         L"%s WinEvtLog: %s: %s(%d): %ls: %ls: %ls: %ls: %ls",
                         epoch_to_human((int)el->er->TimeGenerated),
                         el->name,
                         category,
                         id,
                         source,
                         el_user,
                         el_domain,
                         computer_name,
                         descriptive_msg != NULL ? descriptive_msg : el_string);

                /* Generate UTF-8 string */
                final_msg_utf8 = convert_windows_string(final_msg);
                if (final_msg_utf8) {
                    if (SendMSG(logr_queue, final_msg_utf8, "WinEvtLog", LOCALFILE_MQ) < 0) {
                        merror(QUEUE_SEND);
                    }
                    free(final_msg_utf8);
                }
            }

            if (descriptive_msg != NULL) {
                LocalFree(descriptive_msg);
            }

            /* Cleanup el_sstring */
            char **el_str_tmp = el_sstring;
            while(*el_str_tmp != NULL) {
                free(*el_str_tmp);
                el_str_tmp++;
            }

            /* Change the point to the er */
            read -= el->er->Length;
            el->er = (EVENTLOGRECORD *)((LPBYTE) el->er + el->er->Length);
        }

        /* Set er to the beginning of the buffer */
        el->er = (EVENTLOGRECORD *)&mbuffer;
    }

    id = GetLastError();
    if (id == ERROR_HANDLE_EOF) {
        return;
    }

    /* Event log was cleared */
    else if (id == ERROR_EVENTLOG_FILE_CHANGED) {
        char msg_alert[512 + 1] = {'\0'};
        mwarn("Event log cleared: '%s'", el->name);

        /* Send message about cleared */
        snprintf(msg_alert, 512, "ossec: Event log cleared: '%s'", el->name);
        SendMSG(logr_queue, msg_alert, "WinEvtLog", LOCALFILE_MQ);

        /* Close the event log and reopen */
        CloseEventLog(el->h);
        el->h = NULL;

        /* Reopen */
        if (startEL(el->name, el) < 0) {
            merror("Unable to reopen event log '%s'", el->name);
        }
    }

    else {
        mdebug1("Error reading event log: %d", id);
    }
}

/* Read Windows Vista security description */
void win_read_vista_sec()
{
    char *p = NULL;
    char *key = NULL;
    char *desc = NULL;
    char buf[OS_MAXSTR + 1] = {'\0'};
    FILE *fp;

    wchar_t *desc_utf16 = NULL;

    /* Vista security */
    fp = fopen("vista_sec.txt", "r");
    if (!fp) merror_exit("Unable to read vista security descriptions.");

    /* Creating the hash */
    vista_sec_id_hash = OSHash_Create();
    if (!vista_sec_id_hash) {
        fclose(fp);
        merror_exit("Unable to read vista security descriptions.");
    }

    /* Read the whole file and add it to memory */
    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        /* Get the last occurrence of \n */
        if ((p = strrchr(buf, '\n')) != NULL) {
            *p = '\0';
        }

        p = strchr(buf, ',');
        if (!p) {
            merror("Invalid entry on the Vista security "
                   "description.");
            continue;
        }

        *p = '\0';
        p++;
        
        /* Remove whitespace */
        while (*p == ' ') {
            p++;
        }

        /* Allocate memory */
        key = strdup(buf);
        desc = strdup(p);
        
        if (!key || !desc) {
            merror("Invalid entry on the Vista security description.");
            if (key) free(key);
            if (desc) free(desc);
        } else {
            /* Convert description to UTF16-LE */
            desc_utf16 = convert_unix_string(desc);

            /* Free ANSI description */
            free(desc);

            if (desc_utf16) {
                /* Insert on hash */
                if (OSHash_Add(vista_sec_id_hash, key, desc_utf16) != 2) free(desc_utf16);
                
                /* OSHash_Add() duplicates the key, but not the data */
                free(key);
            }
        }
        
        /* Reset pointer addresses before using strdup() again */
        /* The hash will keep the needed memory references */
        key = NULL;
        desc = NULL;
        desc_utf16 = NULL;
    }

    fclose(fp);
}

/* Start the event logging for windows */
void win_startel(char *evt_log)
{
    int entries_count = 0;

    /* Maximum size */
    if (el_last == 9) {
        merror(EVTLOG_DUP, evt_log);
        return;
    }

    /* Create the DLL hash */
    if (!dll_hash) {
        dll_hash = OSHash_Create();
        if (!dll_hash) {
            merror("Unable to create DLL hash.");
        }
    }

    /* Start event log -- going to last available record */
    if ((entries_count = startEL(evt_log, &el[el_last])) < 0) {
        merror(INV_EVTLOG, evt_log);
        return;
    } else {
        readel(&el[el_last], 0);
    }
    el_last++;
}

/* Read the event logging for windows */
void win_readel()
{
    int i = 0;

    /* Sleep plus 2 seconds before reading again */
    Sleep(2000);

    for (; i < el_last; i++) {
        readel(&el[i], 1);
    }
}

#endif
