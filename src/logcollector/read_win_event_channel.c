/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef WIN32
#ifdef EVENTCHANNEL_SUPPORT

/* Saying we are on Vista in order to have the API */
#define _WIN32_WINNT 0x0600

/* Using Secure APIs */
#define MINGW_HAS_SECURE_API 1

/* Bookmarks directory */
#define BOOKMARKS_DIR "bookmarks"

/* Logging levels */
#define WINEVENT_AUDIT		0
#define WINEVENT_CRITICAL	1
#define WINEVENT_ERROR		2
#define WINEVENT_WARNING	3
#define WINEVENT_INFORMATION	4
#define WINEVENT_VERBOSE	5

/* Audit types */
#define WINEVENT_AUDIT_FAILURE 0x10000000000000LL
#define WINEVENT_AUDIT_SUCCESS 0x20000000000000LL

#include "shared.h"
#include "logcollector.h"

#include <stdint.h>
#include <winevt.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>
#include <sddl.h>

typedef struct _os_event {
    char *name;
    unsigned int id;
    char *source;
    SID *uid;
    char *user;
    char *domain;
    char *computer;
    char *message;
    ULONGLONG time_created;
    char *timestamp;
    int64_t keywords;
    int64_t level;
    char *category;
} os_event;

typedef struct _os_channel {
    char *evt_log;
    char *bookmark_name;
    char bookmark_enabled;
    char bookmark_filename[OS_MAXSTR];
} os_channel;

static char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags);
static EVT_HANDLE read_bookmark(os_channel *channel);

void free_event(os_event *event)
{
    free(event->name);
    free(event->source);
    free(event->user);
    free(event->domain);
    free(event->computer);
    free(event->message);
    free(event->timestamp);
}

wchar_t *convert_unix_string(char *string)
{
    wchar_t *dest = NULL;
    size_t size = 0;
    int result = 0;

    if (string == NULL) {
        return (NULL);
    }

    /* Determine size required */
    size = MultiByteToWideChar(CP_UTF8,
                               MB_ERR_INVALID_CHARS,
                               string,
                               -1,
                               NULL,
                               0);

    if (size == 0) {
        mferror(
            "Could not MultiByteToWideChar() when determining size which returned (%lu)",
            GetLastError());
        return (NULL);
    }

    if ((dest = calloc(size, sizeof(wchar_t))) == NULL) {
        mferror(
            "Could not calloc() memory for MultiByteToWideChar() which returned [(%d)-(%s)]",
            errno,
            strerror(errno));
        return (NULL);
    }

    result = MultiByteToWideChar(CP_UTF8,
                                 MB_ERR_INVALID_CHARS,
                                 string,
                                 -1,
                                 dest,
                                 size);

    if (result == 0) {
        mferror(
            "Could not MultiByteToWideChar() which returned (%lu)",
            GetLastError());
        free(dest);
        return (NULL);
    }

    return (dest);
}

char *get_property_value(PEVT_VARIANT value)
{
    if (value->Type == EvtVarTypeNull) {
        return (NULL);
    }

    return (convert_windows_string(value->StringVal));
}

int get_username_and_domain(os_event *event)
{
    int result = 0;
    int status = 0;
    DWORD user_length = 0;
    DWORD domain_length = 0;
    SID_NAME_USE account_type;
    LPTSTR StringSid = NULL;

    /* Try to convert SID to a string. This isn't necessary to make
     * things work but it is nice to have for error and debug logging.
     */

    if (!ConvertSidToStringSid(event->uid, &StringSid)) {
        mdebug1(
            "Could not convert SID to string which returned (%lu)",
            GetLastError());
    }

    mdebug1("Performing a LookupAccountSid() on (%s)",
           StringSid ? StringSid : "unknown");

    /* Make initial call to get buffer size */
    result = LookupAccountSid(NULL,
                              event->uid,
                              NULL,
                              &user_length,
                              NULL,
                              &domain_length,
                              &account_type);

    if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        /* Not having a user can be normal */
        goto cleanup;
    }

    if ((event->user = calloc(user_length, sizeof(char))) == NULL) {
        mferror(
            "Could not lookup SID (%s) due to calloc() failure on user which returned [(%d)-(%s)]",
            StringSid ? StringSid : "unknown",
            errno,
            strerror(errno));
        goto cleanup;
    }

    if ((event->domain = calloc(domain_length, sizeof(char))) == NULL) {
        mferror(
            "Could not lookup SID (%s) due to calloc() failure on domain which returned [(%d)-(%s)]",
            StringSid ? StringSid : "unknown",
            errno,
            strerror(errno));
        goto cleanup;
    }

    result = LookupAccountSid(NULL,
                              event->uid,
                              event->user,
                              &user_length,
                              event->domain,
                              &domain_length,
                              &account_type);
    if (result == FALSE) {
        mferror(
            "Could not LookupAccountSid() for (%s) which returned (%lu)",
            StringSid ? StringSid : "unknown",
            GetLastError());
        goto cleanup;
    }

    /* Success */
    status = 1;

cleanup:
    if (status == 0) {
        free(event->user);
        free(event->domain);

        event->user = NULL;
        event->domain = NULL;
    }

    if (StringSid) {
        LocalFree(StringSid);
    }

    return (status);
}

char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags)
{
    char *message = NULL;
    EVT_HANDLE publisher = NULL;
    DWORD size = 0;
    wchar_t *buffer = NULL;
    int result = 0;

    publisher = EvtOpenPublisherMetadata(NULL,
                                         provider_name,
                                         NULL,
                                         0,
                                         0);
    if (publisher == NULL) {
        mferror(
            "Could not EvtOpenPublisherMetadata() with flags (%lu) which returned (%lu)",
            flags,
            GetLastError());
        goto cleanup;
    }

    /* Make initial call to determine buffer size */
    result = EvtFormatMessage(publisher,
                              evt,
                              0,
                              0,
                              NULL,
                              flags,
                              0,
                              NULL,
                              &size);
    if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        mferror(
            "Could not EvtFormatMessage() to determine buffer size with flags (%lu) which returned (%lu)",
            flags,
            GetLastError());
        goto cleanup;
    }

    if ((buffer = calloc(size, sizeof(wchar_t))) == NULL) {
        mferror(
            "Could not calloc() memory which returned [(%d)-(%s)]",
            errno,
            strerror(errno));
        goto cleanup;
    }

    result = EvtFormatMessage(publisher,
                              evt,
                              0,
                              0,
                              NULL,
                              flags,
                              size,
                              buffer,
                              &size);
    if (result == FALSE) {
        mferror(
            "Could not EvtFormatMessage() with flags (%lu) which returned (%lu)",
            flags,
            GetLastError());
        goto cleanup;
    }

    message = convert_windows_string(buffer);

cleanup:
    free(buffer);

    if (publisher != NULL) {
        EvtClose(publisher);
    }

    return (message);
}

/* Read an existing bookmark (if one exists) */
EVT_HANDLE read_bookmark(os_channel *channel)
{
    EVT_HANDLE bookmark = NULL;
    size_t size = 0;
    FILE *fp = NULL;
    wchar_t bookmark_xml[OS_MAXSTR];

    /* If we have a stored bookmark, start from it */
    if ((fp = fopen(channel->bookmark_filename, "r")) == NULL) {
        /* Check if the error was not because the
         * file did not exist which should be logged
         */
        if (errno != ENOENT) {
            mferror(
                "Could not fopen() existing bookmark (%s) for (%s) which returned [(%d)-(%s)]",
                channel->bookmark_filename,
                channel->evt_log,
                errno,
                strerror(errno));
        }
        return (NULL);
    }

    size = fread(bookmark_xml, sizeof(wchar_t), OS_MAXSTR, fp);
    if (ferror(fp)) {
        mferror(
            "Could not fread() bookmark (%s) for (%s) which returned [(%d)-(%s)]",
            channel->bookmark_filename,
            channel->evt_log,
            errno,
            strerror(errno));
        fclose(fp);
        return (NULL);
    }

    fclose(fp);

    /* Make sure bookmark data was read */
    if (size == 0) {
        return (NULL);
    }

    /* Make sure bookmark is terminated properly */
    bookmark_xml[size] = L'\0';

    /* Create bookmark from saved XML */
    if ((bookmark = EvtCreateBookmark(bookmark_xml)) == NULL) {
        mferror(
            "Could not EvtCreateBookmark() bookmark (%s) for (%s) which returned (%lu)",
            channel->bookmark_filename,
            channel->evt_log,
            GetLastError());
        return (NULL);
    }

    return (bookmark);
}

/* Format Timestamp from EventLog */
char *WinEvtTimeToString(ULONGLONG ulongTime)
{
    SYSTEMTIME sysTime;
    FILETIME fTime, lfTime;
    ULARGE_INTEGER ulargeTime;
    struct tm tm_struct;
    char *timestamp = NULL;
    int size = 80;

    if ((timestamp = malloc(size)) == NULL) {
        mferror(
            "Could not malloc() memory to convert timestamp which returned [(%d)-(%s)]",
            errno,
            strerror(errno));
        goto cleanup;
    }

    /* Zero out structure */
    memset(&tm_struct, 0, sizeof(tm_struct));

    /* Convert from ULONGLONG to usable FILETIME value */
    ulargeTime.QuadPart = ulongTime;

    fTime.dwLowDateTime = ulargeTime.LowPart;
    fTime.dwHighDateTime = ulargeTime.HighPart;

    /* Adjust time value to reflect current timezone then convert to a
     * SYSTEMTIME
     */
    if (FileTimeToLocalFileTime(&fTime, &lfTime) == 0) {
        mferror(
            "Could not FileTimeToLocalFileTime() to convert timestamp which returned (%lu)",
            GetLastError());
        goto cleanup;
    }

    if (FileTimeToSystemTime(&lfTime, &sysTime) == 0) {
        mferror(
            "Could not FileTimeToSystemTime() to convert timestamp which returned (%lu)",
            GetLastError());
        goto cleanup;
    }

    /* Convert SYSTEMTIME to tm */
    tm_struct.tm_year = sysTime.wYear - 1900;
    tm_struct.tm_mon  = sysTime.wMonth - 1;
    tm_struct.tm_mday = sysTime.wDay;
    tm_struct.tm_hour = sysTime.wHour;
    tm_struct.tm_wday = sysTime.wDayOfWeek;
    tm_struct.tm_min  = sysTime.wMinute;
    tm_struct.tm_sec  = sysTime.wSecond;

    /* Format timestamp string */
    strftime(timestamp, size, "%Y %b %d %H:%M:%S", &tm_struct);

    return (timestamp);

cleanup:
    free(timestamp);

    return (NULL);
}

void send_channel_event(EVT_HANDLE evt, os_channel *channel)
{
    DWORD buffer_length = 0;
    PEVT_VARIANT properties_values = NULL;
    DWORD count = 0;
    int result = 0;
    wchar_t *wprovider_name = NULL;
    char *msg_sent = NULL;
    char *provider_name = NULL;
    char *msg_from_prov = NULL;
    char *xml_event = NULL;
    char *filtered_msg = NULL;
    char *avoid_dup = NULL;
    char *beg_prov = NULL;
    char *end_prov = NULL;
    char *find_prov = NULL;
    size_t num;

    cJSON *event_json = cJSON_CreateObject();

    os_malloc(OS_MAXSTR, filtered_msg);
    os_malloc(OS_MAXSTR, provider_name);
    os_malloc(OS_MAXSTR, xml_event);

    result = EvtRender(NULL,
                       evt,
                       EvtRenderEventXml,
                       0,
                       NULL,
                       &buffer_length,
                       &count);
    if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        mferror(
            "Could not EvtRender() to determine buffer size for (%s) which returned (%lu)",
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    if ((properties_values = malloc(buffer_length)) == NULL) {
        mferror(
            "Could not malloc() memory to process event (%s) which returned [(%d)-(%s)]",
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    if (!EvtRender(NULL,
                   evt,
                   EvtRenderEventXml,
                   buffer_length,
                   properties_values,
                   &buffer_length,
                   &count)) {
        mferror(
            "Could not EvtRender() for (%s) which returned (%lu)",
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }
    xml_event = convert_windows_string((LPCWSTR) properties_values);
    
    find_prov = strstr(xml_event, "Provider Name=");
  
    if(find_prov){
        beg_prov = strchr(find_prov, '\'');
        if(beg_prov){
            end_prov = strchr(beg_prov+1, '\'');

            if (end_prov){
                num = end_prov - beg_prov - 1;

                if(num > OS_MAXSTR - 1){
                    mwarn("The event message has exceeded the maximum size.");
                    goto cleanup;
                }

                memcpy(provider_name, beg_prov+1, num);
                provider_name[num] = '\0';
                find_prov = '\0';
                beg_prov = '\0';
                end_prov = '\0';
            }
        }
    }
    
    if (provider_name) {
        wprovider_name = convert_unix_string(provider_name);

        if (wprovider_name && (msg_from_prov = get_message(evt, wprovider_name, EvtFormatMessageEvent)) == NULL) {
            mferror(
                "Could not get message for (%s)",
                channel->evt_log);
        }
        else {
            avoid_dup = strchr(msg_from_prov, '\r');

            if (avoid_dup){
                num = avoid_dup - msg_from_prov;
                memcpy(filtered_msg, msg_from_prov, num);
                filtered_msg[num] = '\0';
                cJSON_AddStringToObject(event_json, "Message", filtered_msg);
            } else {
                win_format_event_string(msg_from_prov);
                
                cJSON_AddStringToObject(event_json, "Message", msg_from_prov);
            }
            avoid_dup = '\0';
        }
    } else {
        cJSON_AddStringToObject(event_json, "Message", "No message");
    }

    cJSON_AddStringToObject(event_json, "Event", xml_event);
    msg_sent = cJSON_PrintUnformatted(event_json);

    if (SendMSG(logr_queue, msg_sent, "EventChannel", WIN_EVT_MQ) < 0) {
        merror(QUEUE_SEND);
    }

cleanup:
    os_free(msg_from_prov);
    os_free(xml_event);
    os_free(msg_sent);
    os_free(filtered_msg);
    os_free(properties_values);
    os_free(provider_name);
    os_free(wprovider_name);
    cJSON_Delete(event_json);

    return;
}

DWORD WINAPI event_channel_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, os_channel *channel, EVT_HANDLE evt)
{
    if (action == EvtSubscribeActionDeliver) {
        send_channel_event(evt, channel);
    }

    return (0);
}

void win_start_event_channel(char *evt_log, char future, char *query)
{
    wchar_t *wchannel = NULL;
    wchar_t *wquery = NULL;
    char *filtered_query = NULL;
    os_channel *channel = NULL;
    DWORD flags = EvtSubscribeToFutureEvents;
    EVT_HANDLE bookmark = NULL;
    EVT_HANDLE result = NULL;
    int status = 0;

    if ((channel = calloc(1, sizeof(os_channel))) == NULL) {
        mferror(
            "Could not calloc() memory for channel to start reading (%s) which returned [(%d)-(%s)]",
            evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    channel->evt_log = evt_log;

    /* Create copy of event log string */
    if ((channel->bookmark_name = strdup(channel->evt_log)) == NULL) {
        mferror(
            "Could not strdup() event log name to start reading (%s) which returned [(%d)-(%s)]",
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    /* Replace '/' with '_' */
    if (strchr(channel->bookmark_name, '/')) {
        *(strrchr(channel->bookmark_name, '/')) = '_';
    }

    /* Convert evt_log to Windows string */
    if ((wchannel = convert_unix_string(channel->evt_log)) == NULL) {
        mferror(
            "Could not convert_unix_string() evt_log for (%s) which returned [(%d)-(%s)]",
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    /* Convert query to Windows string */
    if (query) {
        if ((filtered_query = filter_special_chars(query)) == NULL) {
            mferror(
                "Could not filter_special_chars() query for (%s) which returned [(%d)-(%s)]",
                channel->evt_log,
                errno,
                strerror(errno));
            goto cleanup;
        }

        if ((wquery = convert_unix_string(filtered_query)) == NULL) {
            mferror(
                "Could not convert_unix_string() query for (%s) which returned [(%d)-(%s)]",
                channel->evt_log,
                errno,
                strerror(errno));
            goto cleanup;
        }
    }

    channel->bookmark_enabled = !future;

    if (channel->bookmark_enabled) {
        /* Create bookmark file name */
        snprintf(channel->bookmark_filename,
                 sizeof(channel->bookmark_filename), "%s/%s", BOOKMARKS_DIR,
                 channel->bookmark_name);

        /* Try to read existing bookmark */
        if ((bookmark = read_bookmark(channel)) != NULL) {
            flags = EvtSubscribeStartAfterBookmark;
        }
    }

    result = EvtSubscribe(NULL,
                          NULL,
                          wchannel,
                          wquery,
                          bookmark,
                          channel,
                          (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
                          flags);

    if (result == NULL && flags == EvtSubscribeStartAfterBookmark) {
        result = EvtSubscribe(NULL,
                              NULL,
                              wchannel,
                              wquery,
                              NULL,
                              channel,
                              (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
                              EvtSubscribeToFutureEvents);
    }

    if (result == NULL) {
        mferror(
            "Could not EvtSubscribe() for (%s) which returned (%lu)",
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    /* Success */
    status = 1;

cleanup:
    free(wchannel);
    free(wquery);
    free(filtered_query);

    if (status == 0) {
        free(channel->bookmark_name);
        free(channel);

        if (result != NULL) {
            EvtClose(result);
        }
    }

    if (bookmark != NULL) {
        EvtClose(bookmark);
    }

    return;
}

#endif /* EVENTCHANNEL_SUPPORT */
#endif /* WIN32 */
