/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
#include "state.h"

#include <stdint.h>
#include <winevt.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>
#include <sddl.h>

#ifdef WAZUH_UNIT_TESTING
#include "../unit_tests/wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#include "../unit_tests/wrappers/windows/winbase_wrappers.h"
#include "../unit_tests/wrappers/windows/winevt_wrappers.h"

// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

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
    char *query;
    int reconnect_time;
    EVT_HANDLE subscription;
} os_channel;

STATIC char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags);
STATIC EVT_HANDLE read_bookmark(os_channel *channel);

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
        merror(
            "Could not MultiByteToWideChar() when determining size which returned (%lu)",
            GetLastError());
        return (NULL);
    }

    if ((dest = calloc(size, sizeof(wchar_t))) == NULL) {
        merror(
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
        merror(
            "Could not MultiByteToWideChar() which returned (%lu)",
            GetLastError());
        free(dest);
        return (NULL);
    }

    return (dest);
}

STATIC char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags)
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
        LSTATUS err = GetLastError();
        char error_msg[OS_SIZE_1024];
        memset(error_msg, 0, OS_SIZE_1024);
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
                | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &error_msg, OS_SIZE_1024, NULL);

        mdebug1(
            "Could not EvtOpenPublisherMetadata() with flags (%lu) which returned (%lu): %s",
            flags,
            err,
            error_msg);
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
        merror(
            "Could not EvtFormatMessage() to determine buffer size with flags (%lu) which returned (%lu)",
            flags,
            GetLastError());
        goto cleanup;
    }

    /* Increase buffer size by one due to the difference in the size count between EvtFormatMessage() and
       WideCharToMultiByte() */
    size += 1;
    if ((buffer = calloc(size, sizeof(wchar_t))) == NULL) {
        merror(
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
        merror(
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
    if ((fp = wfopen(channel->bookmark_filename, "r")) == NULL) {
        /* Check if the error was not because the
         * file did not exist which should be logged
         */
        if (errno != ENOENT) {
            merror(
                "Could not wfopen() existing bookmark (%s) for (%s) which returned [(%d)-(%s)]",
                channel->bookmark_filename,
                channel->evt_log,
                errno,
                strerror(errno));
        }
        return (NULL);
    }

    size = fread(bookmark_xml, sizeof(wchar_t), OS_MAXSTR, fp);
    if (ferror(fp)) {
        merror(
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
        merror(
            "Could not EvtCreateBookmark() bookmark (%s) for (%s) which returned (%lu)",
            channel->bookmark_filename,
            channel->evt_log,
            GetLastError());
        return (NULL);
    }

    return (bookmark);
}

/* Update the log position of a bookmark */
int update_bookmark(EVT_HANDLE evt, os_channel *channel)
{
    DWORD size = 0;
    DWORD count = 0;
    void *buffer = NULL;
    int result = 0;
    int status = 0;
    EVT_HANDLE bookmark = NULL;
    FILE *fp = NULL;

    if ((bookmark = EvtCreateBookmark(NULL)) == NULL) {
        merror(
            "Could not EvtCreateBookmark() bookmark (%s) for (%s) which returned (%lu)",
            channel->bookmark_filename,
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    if (!EvtUpdateBookmark(bookmark, evt)) {
        merror(
            "Could not EvtUpdateBookmark() bookmark (%s) for (%s) which returned (%lu)",
            channel->bookmark_filename,
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    /* Make initial call to determine buffer size */
    result = EvtRender(NULL,
                       bookmark,
                       EvtRenderBookmark,
                       0,
                       NULL,
                       &size,
                       &count);
    if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        merror(
            "Could not EvtRender() to get buffer size to update bookmark (%s) for (%s) which returned (%lu)",
            channel->bookmark_filename,
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    if (buffer = calloc(size, sizeof(void)), buffer == NULL) {
        merror(
            "Could not calloc() memory to save bookmark (%s) for (%s) which returned [(%d)-(%s)]",
            channel->bookmark_filename,
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    if (!EvtRender(NULL,
                   bookmark,
                   EvtRenderBookmark,
                   size,
                   buffer,
                   &size,
                   &count)) {
        merror(
            "Could not EvtRender() bookmark (%s) for (%s) which returned (%lu)",
            channel->bookmark_filename, channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    if ((fp = wfopen(channel->bookmark_filename, "w")) == NULL) {
        mwarn(
            "Could not wfopen() bookmark (%s) for (%s) which returned [(%d)-(%s)]",
            channel->bookmark_filename,
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    if ((fwrite(buffer, 1, size, fp)) < size) {
        merror(
            "Could not fwrite() to bookmark (%s) for (%s) which returned [(%d)-(%s)]",
            channel->bookmark_filename,
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    fclose(fp);

    /* Success */
    status = 1;

cleanup:
    free(buffer);

    if (bookmark != NULL) {
        EvtClose(bookmark);
    }

    if (fp) {
        fclose(fp);
    }

    return (status);
}


void send_channel_event(EVT_HANDLE evt, os_channel *channel)
{
    DWORD buffer_length = 0;
    PEVT_VARIANT properties_values = NULL;
    DWORD count = 0;
    int result = 0;
    wchar_t *wprovider_name = NULL;
    char *provider_name = NULL;
    char *msg_from_prov = NULL;
    char *xml_event = NULL;
    char *beg_prov = NULL;
    char *end_prov = NULL;
    char *find_prov = NULL;
    size_t num;

    os_malloc(OS_MAXSTR, provider_name);

    result = EvtRender(NULL,
                       evt,
                       EvtRenderEventXml,
                       0,
                       NULL,
                       &buffer_length,
                       &count);
    if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        merror(
            "Could not EvtRender() to determine buffer size for (%s) which returned (%lu)",
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }

    if ((properties_values = malloc(buffer_length)) == NULL) {
        merror(
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
        merror(
            "Could not EvtRender() for (%s) which returned (%lu)",
            channel->evt_log,
            GetLastError());
        goto cleanup;
    }
    xml_event = convert_windows_string((LPCWSTR) properties_values);

    if (!xml_event) {
        goto cleanup;
    }

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
            merror(
                "Could not get message for (%s)",
                channel->evt_log);
        }
    }

    win_format_event_string(xml_event);

    w_logcollector_state_update_file(channel->evt_log, strlen(xml_event));

    if (SendMSG(logr_queue, xml_event, "EventChannel", WIN_EVT_MQ) < 0) {
        merror(QUEUE_SEND);
        w_logcollector_state_update_target(channel->evt_log, "agent", true);
    } else {
        w_logcollector_state_update_target(channel->evt_log, "agent", false);
    }

    if (channel->bookmark_enabled) {
        update_bookmark(evt, channel);
    }

cleanup:
    os_free(msg_from_prov);
    os_free(xml_event);
    os_free(properties_values);
    os_free(provider_name);
    os_free(wprovider_name);

    return;
}

/**
 * @brief Destroy os_channel structure
 *
 * This function closes the subscription and frees the tructure, including bookmark_name.
 * Nothing happens if channel is NULL.
 *
 * @param channel Pointer to an os_channel structure.
 */
void os_channel_destroy(os_channel * channel) {
    if (channel != NULL) {
        free(channel->bookmark_name);

        if (channel->subscription != NULL) {
            if (!EvtClose(channel->subscription)) {
                merror("Could not close subscription to channel '%s': %lu", channel->evt_log, GetLastError());
            }
        }

        free(channel);
    }
}

DWORD WINAPI event_channel_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, os_channel *channel, EVT_HANDLE evt)
{
    if (action == EvtSubscribeActionDeliver) {
        send_channel_event(evt, channel);
    } else {
        mwarn("The eventlog service is down. Unable to collect logs from '%s' channel.", channel->evt_log);

        while(1) {
            /* Try to restart EventChannel */
            if (win_start_event_channel(channel->evt_log, !channel->bookmark_enabled, channel->query, channel->reconnect_time) == -1) {
                mdebug1("Trying to reconnect %s channel in %i seconds.", channel->evt_log, channel->reconnect_time );
                sleep(channel->reconnect_time);
            } else {
                minfo("'%s' channel has been reconnected succesfully.", channel->evt_log);
                os_channel_destroy(channel);
                break;
            }
        }
    }

    return (0);
}

int win_start_event_channel(char *evt_log, char future, char *query, int reconnect_time)
{
    wchar_t *wchannel = NULL;
    wchar_t *wquery = NULL;
    char *filtered_query = NULL;
    os_channel *channel = NULL;
    DWORD flags = EvtSubscribeToFutureEvents;
    EVT_HANDLE bookmark = NULL;
    int status = 0;

    os_calloc(1, sizeof(os_channel), channel);

    channel->evt_log = evt_log;
    channel->reconnect_time = reconnect_time;

    /* Create copy of event log string */
    os_strdup(channel->evt_log, channel->bookmark_name);

    /* Create copy of query string */
    channel->query = query;

    /* Replace '/' with '_' */
    if (strchr(channel->bookmark_name, '/')) {
        *(strrchr(channel->bookmark_name, '/')) = '_';
    }

    /* Convert evt_log to Windows string */
    if ((wchannel = convert_unix_string(channel->evt_log)) == NULL) {
        merror(
            "Could not convert_unix_string() evt_log for (%s) which returned [(%d)-(%s)]",
            channel->evt_log,
            errno,
            strerror(errno));
        goto cleanup;
    }

    /* Convert query to Windows string */
    if (query) {
        if ((filtered_query = filter_special_chars(query)) == NULL) {
            merror(
                "Could not filter_special_chars() query for (%s) which returned [(%d)-(%s)]",
                channel->evt_log,
                errno,
                strerror(errno));
            goto cleanup;
        }

        if ((wquery = convert_unix_string(filtered_query)) == NULL) {
            merror(
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

    channel->subscription = EvtSubscribe(NULL,
                          NULL,
                          wchannel,
                          wquery,
                          bookmark,
                          channel,
                          (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
                          flags);

    if (channel->subscription == NULL && flags == EvtSubscribeStartAfterBookmark) {
        channel->subscription = EvtSubscribe(NULL,
                              NULL,
                              wchannel,
                              wquery,
                              NULL,
                              channel,
                              (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
                              EvtSubscribeToFutureEvents);
    }

    if (channel->subscription == NULL) {
        unsigned long id = GetLastError();
        if (id != RPC_S_SERVER_UNAVAILABLE && id != RPC_S_UNKNOWN_IF) {
            merror(
                "Could not EvtSubscribe() for (%s) which returned (%lu)",
                channel->evt_log,
                id);
        }
        goto cleanup;
    }

    w_logcollector_state_add_file(channel->evt_log);
    w_logcollector_state_add_target(channel->evt_log, "agent");

    /* Success */
    status = 1;

cleanup:
    free(wchannel);
    free(wquery);
    free(filtered_query);

    if (status == 0) {
        os_channel_destroy(channel);
    }

    if (bookmark != NULL) {
        EvtClose(bookmark);
    }

    return status ? 0 : -1;
}

#endif /* EVENTCHANNEL_SUPPORT */
#endif /* WIN32 */
