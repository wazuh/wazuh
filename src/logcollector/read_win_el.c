/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"
#include "state.h"

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
    static char buf[80];
    struct tm tm_result = { .tm_sec = 0 };

    localtime_r(&epoch, &tm_result);
    strftime(buf, sizeof(buf), "%Y %b %d %H:%M:%S", &tm_result);
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
char *el_getEventDLL(char *evt_name, char *source, char *event)
{
    char *ret_str;
    HKEY key;
    DWORD ret;
    char keyname[512] = {'\0'};
    char *skey = NULL, *sval = NULL;

    snprintf(keyname, 510,
             "System\\CurrentControlSet\\Services\\EventLog\\%s\\%s",
             evt_name,
             source);

    /* Check if we have it in memory */
    ret_str = OSHash_Get(dll_hash, keyname + 42);
    if (ret_str) {
        return (ret_str);
    }

    /* Open Registry */
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0,
                     KEY_ALL_ACCESS, &key) != ERROR_SUCCESS) {
        return (NULL);
    }

    ret = MAX_PATH - 1;
    if (RegQueryValueEx(key, "EventMessageFile", NULL,
                        NULL, (LPBYTE)event, &ret) != ERROR_SUCCESS) {
        event[0] = '\0';
        RegCloseKey(key);
        return (NULL);
    } else {
        /* Adding to memory */
        skey = strdup(keyname + 42);
        sval = strdup(event);

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
char *el_vista_getMessage(int evt_id_int, LPTSTR *el_sstring)
{
    DWORD fm_flags = 0;
    LPSTR message = NULL;
    char *desc_string;
    char evt_id[16];

    /* Flags for format event */
    fm_flags |= FORMAT_MESSAGE_FROM_STRING;
    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
    fm_flags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;

    /* Get descriptive message */
    evt_id[15] = '\0';
    snprintf(evt_id, 15, "%d", evt_id_int);

    desc_string = OSHash_Get(vista_sec_id_hash, evt_id);
    if (!desc_string) {
        return (NULL);
    }

    if (!FormatMessage(fm_flags, desc_string, 0, 0,
                       (LPTSTR) &message, 0, el_sstring)) {
        return (NULL);
    }

    return (message);
}

/* Returns a descriptive message of the event */
char *el_getMessage(EVENTLOGRECORD *er,  char *name,
                    char *source, LPTSTR *el_sstring)
{
    DWORD fm_flags = 0;
    char tmp_str[257];
    char event[MAX_PATH + 1];
    char *curr_str;
    char *next_str;
    LPSTR message = NULL;

    HMODULE hevt;

    /* Initialize variables */
    event[MAX_PATH] = '\0';
    tmp_str[256] = '\0';

    /* Flags for format event */
    fm_flags |= FORMAT_MESSAGE_FROM_HMODULE;
    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
    fm_flags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;

    /* Get the file name from the registry (stored on event) */
    if (!(curr_str = el_getEventDLL(name, source, event))) {
        return (NULL);
    }

    /* If our event has multiple libraries, try each one of them */
    while ((next_str = strchr(curr_str, ';'))) {
        *next_str = '\0';

        ExpandEnvironmentStrings(curr_str, tmp_str, 255);

        /* Revert back old value */
        *next_str = ';';

        /* Load library */
        hevt = LoadLibraryEx(tmp_str, NULL,
                             DONT_RESOLVE_DLL_REFERENCES |
                             LOAD_LIBRARY_AS_DATAFILE);
        if (hevt) {
            if (!FormatMessage(fm_flags, hevt, er->EventID, 0,
                               (LPTSTR) &message, 0, el_sstring)) {
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
    ExpandEnvironmentStrings(curr_str, tmp_str, 255);
    hevt = LoadLibraryEx(tmp_str, NULL,
                         DONT_RESOLVE_DLL_REFERENCES |
                         LOAD_LIBRARY_AS_DATAFILE);
    if (hevt) {
        int hr;
        if (hr = FormatMessage(fm_flags, hevt, er->EventID,
                               0,
                               (LPTSTR) &message, 0, el_sstring), !hr) {
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
    static int counter = 0;

    char mbuffer[BUFFER_SIZE + 1];
    LPSTR sstr = NULL;

    char *tmp_str = NULL;
    char *category;
    char *source;
    char *computer_name;
    char *descriptive_msg;

    char el_user[OS_FLSIZE + 1];
    char el_domain[OS_FLSIZE + 1];
    char el_string[OS_MAXSTR + 1];
    char final_msg[OS_MAXSTR + 1];
    LPSTR el_sstring[OS_FLSIZE + 1] = {0};

    /* er must point to the mbuffer */
    el->er = (EVENTLOGRECORD *) &mbuffer;

    /* Zero the values */
    el_string[OS_MAXSTR] = '\0';
    el_user[OS_FLSIZE] = '\0';
    el_domain[OS_FLSIZE] = '\0';
    final_msg[OS_MAXSTR] = '\0';

    /* Event log is not open */
    if (!el->h) {
        el->er = NULL;
        return;
    }

    /* Read the event log */
    while (ReadEventLog(el->h,
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
            source = (LPSTR) ((LPBYTE) el->er + sizeof(EVENTLOGRECORD));
            computer_name = source + strlen(source) + 1;
            descriptive_msg = NULL;

            /* Get event id */
            id = (int)el->er->EventID & _evtid;

            /* Initialize domain/user size */
            user_size = 255;
            domain_size = 255;
            el_domain[0] = '\0';
            el_user[0] = '\0';

            /* We must have some description */
            if (el->er->NumStrings) {
                size_left = OS_MAXSTR - OS_SIZE_1024;

                sstr = (LPSTR)((LPBYTE)el->er + el->er->StringOffset);
                el_string[0] = '\0';

                for (nstr = 0; nstr < el->er->NumStrings && sstr; nstr++) {
                    str_size = strlen(sstr);
                    if (size_left > 1) {
                        strncat(el_string, sstr, size_left);
                    }

                    tmp_str = strchr(el_string, '\0');
                    if (tmp_str) {
                        *tmp_str = ' ';
                        tmp_str++;
                        *tmp_str = '\0';
                    } else {
                        merror("Invalid application string (size+)");
                    }
                    size_left -= str_size + 2;

                    if (nstr <= 92) {
                        el_sstring[nstr] = (LPSTR)sstr;
                        el_sstring[nstr + 1] = NULL;
                    }

                    sstr = strchr( (LPSTR)sstr, '\0');
                    if (sstr) {
                        sstr++;
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
                    win_format_event_string(descriptive_msg);
                }
            } else {
                strncpy(el_string, "(no message)", 128);
            }

            /* Get username */
            if (el->er->UserSidLength) {
                SID_NAME_USE account_type;
                if (!LookupAccountSid(NULL,
                                      (SID *)((LPSTR)el->er +
                                              el->er->UserSidOffset),
                                      el_user,
                                      &user_size,
                                      el_domain,
                                      &domain_size,
                                      &account_type)) {
                    strncpy(el_user, "(no user)", 255);
                    strncpy(el_domain, "no domain", 255);
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
                    strncpy(el_user, el_sstring[uid_array_id], OS_FLSIZE);
                    strncpy(el_domain, el_sstring[uid_array_id + 1], OS_FLSIZE);
                } else {
                    strncpy(el_user, "(no user)", 255);
                    strncpy(el_domain, "no domain", 255);
                }
            }

            else {
                strncpy(el_user, "(no user)", 255);
                strncpy(el_domain, "no domain", 255);
            }

            if (printit) {
                DWORD _evtid = 65535;
                int id = (int)el->er->EventID & _evtid;

                final_msg[OS_MAXSTR - OS_LOG_HEADER] = '\0';
                final_msg[OS_MAXSTR - OS_LOG_HEADER - 1] = '\0';

                snprintf(final_msg, OS_MAXSTR - OS_LOG_HEADER - 1,
                         "%s WinEvtLog: %s: %s(%d): %s: %s: %s: %s: %s",
                         epoch_to_human((int)el->er->TimeGenerated),
                         el->name,
                         category,
                         id,
                         source,
                         el_user,
                         el_domain,
                         computer_name,
                         descriptive_msg != NULL ? descriptive_msg : el_string);

                w_logcollector_state_update_file(el->name, strlen(final_msg));

                if (SendMSG(logr_queue, final_msg, "WinEvtLog", LOCALFILE_MQ) < 0) {
                    merror(QUEUE_SEND);
                    w_logcollector_state_update_target(el->name, "agent", true);
                } else {
                    w_logcollector_state_update_target(el->name, "agent", false);
                }
            }

            if (descriptive_msg != NULL) {
                LocalFree(descriptive_msg);
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
        el->er = NULL;
        return;
    }

    /* Event log was cleared */
    else if (id == ERROR_EVENTLOG_FILE_CHANGED) {
        char msg_alert[512 + 1];
        msg_alert[512] = '\0';
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


    /* Event log was closed and re-opened */
    else if (id == ERROR_INVALID_HANDLE) {
        mdebug1("The EventLog service has been restarted. Reconnecting to '%s' channel.", el->name);

        CloseEventLog(el->h);
        el->h = NULL;

        /* Reopen */
        if (startEL(el->name, el) < 0) {
            merror(
            "Could not subscribe for (%s) which returned (%d)",
            el->name,
            id);
        } else {
            counter = 0;
            minfo("'%s' channel has been reconnected succesfully.", el->name);
        }
    }

    else if (id == RPC_S_SERVER_UNAVAILABLE || id == RPC_S_UNKNOWN_IF) {
        /* Prevent message flooding when EventLog is stopped */
        el->er = NULL;
        if (counter == 0) {
            mwarn("The EventLog service is down. Unable to collect logs from its channels.");
            counter = 1;
        }
    }

    else {
        mdebug1("Error reading event log: %d", id);
    }
}

/* Read Windows Vista security description */
void win_read_vista_sec()
{
    char *p = NULL, *key = NULL, *desc = NULL;
    char buf[OS_MAXSTR + 1] = {'\0'};
    FILE *fp;

    /* Vista security */
    fp = wfopen("vista_sec.txt", "r");
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
            merror("Invalid entry on the Vista security description.");
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
            /* Insert on hash */
            if (OSHash_Add(vista_sec_id_hash, key, desc) != 2) free(desc);

            /* OSHash_Add() duplicates the key, but not the data */
            free(key);
        }

        /* Reset pointer addresses before using strdup() again */
        /* The hash will keep the needed memory references */
        key = NULL;
        desc = NULL;
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

    w_logcollector_state_add_file(evt_log);
    w_logcollector_state_add_target(evt_log, "agent");

    /* Start event log -- going to last available record */
    if (entries_count = startEL(evt_log, &el[el_last]), entries_count < 0) {
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
