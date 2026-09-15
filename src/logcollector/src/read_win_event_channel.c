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
#define MAX_SID_STRING_LENGTH 256

#include "shared.h"
#include "logcollector.h"
#include "state.h"

#include <stdint.h>
#include <winevt.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>
#include <sddl.h>

#ifdef WAZUH_UNIT_TESTING
#include "../../unit_tests/wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/sddl_wrappers.h"
#include "../../unit_tests/wrappers/windows/winbase_wrappers.h"
#include "../../unit_tests/wrappers/windows/winevt_wrappers.h"

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

STATIC EVT_HANDLE read_bookmark(os_channel *channel);

STATIC int find_event_data(const char *xml,
                           const char *name,
                           const char **value_start,
                           const char **value_end,
                           int *self_closing)
{
    const char *event_data;
    const char *event_data_end;
    const char *data;
    size_t name_length = strlen(name);
    int found = 0;

    if ((event_data = strstr(xml, "<EventData>")) == NULL ||
        (event_data_end = strstr(event_data + strlen("<EventData>"), "</EventData>")) == NULL) {
        return 0;
    }

    data = event_data + strlen("<EventData>");
    while ((data = strstr(data, "<Data")) != NULL && data < event_data_end) {
        const char *tag_end;
        const char *attributes_end;
        const char *self_closing_start = NULL;
        const char *cursor;
        const char *closing_tag = NULL;
        const char *nested_data;
        int matches_name = 0;
        int is_self_closing = 0;

        if (data[5] != ' ' && data[5] != '\t' && data[5] != '\r' && data[5] != '\n') {
            data += 5;
            continue;
        }

        if ((tag_end = strchr(data, '>')) == NULL || tag_end >= event_data_end) {
            return 0;
        }

        attributes_end = tag_end;
        while (attributes_end > data && isspace((unsigned char)attributes_end[-1])) {
            --attributes_end;
        }
        if (attributes_end > data && attributes_end[-1] == '/') {
            is_self_closing = 1;
            self_closing_start = attributes_end - 1;
            --attributes_end;
            while (attributes_end > data && isspace((unsigned char)attributes_end[-1])) {
                --attributes_end;
            }
        }

        cursor = data + strlen("<Data");
        while (cursor < attributes_end) {
            const char *attribute_name_start;
            const char *attribute_name_end;
            const char *attribute_value_start;
            const char *attribute_value_end;
            char quote;

            while (cursor < attributes_end && isspace((unsigned char)*cursor)) {
                ++cursor;
            }

            if (cursor == attributes_end) {
                break;
            }

            attribute_name_start = cursor;
            while (cursor < attributes_end && !isspace((unsigned char)*cursor) && *cursor != '=') {
                ++cursor;
            }
            attribute_name_end = cursor;

            while (cursor < attributes_end && isspace((unsigned char)*cursor)) {
                ++cursor;
            }
            if (cursor == attributes_end || *cursor++ != '=') {
                return 0;
            }

            while (cursor < attributes_end && isspace((unsigned char)*cursor)) {
                ++cursor;
            }
            if (cursor == attributes_end || (*cursor != '\'' && *cursor != '"')) {
                return 0;
            }

            quote = *cursor++;
            attribute_value_start = cursor;
            if ((attribute_value_end = memchr(cursor, quote, attributes_end - cursor)) == NULL) {
                return 0;
            }

            if ((size_t)(attribute_name_end - attribute_name_start) == strlen("Name") &&
                strncmp(attribute_name_start, "Name", strlen("Name")) == 0 &&
                (size_t)(attribute_value_end - attribute_value_start) == name_length &&
                strncmp(attribute_value_start, name, name_length) == 0) {
                matches_name = 1;
            }

            cursor = attribute_value_end + 1;
        }

        if (!is_self_closing) {
            if ((closing_tag = strstr(tag_end + 1, "</Data>")) == NULL || closing_tag > event_data_end) {
                return 0;
            }

            nested_data = strstr(tag_end + 1, "<Data");
            if (nested_data != NULL && nested_data < closing_tag) {
                return 0;
            }
        }

        if (matches_name) {
            if (found) {
                return 0;
            }
            if (is_self_closing) {
                *value_start = self_closing_start;
                *value_end = tag_end + 1;
            } else {
                *value_start = tag_end + 1;
                *value_end = closing_tag;
            }
            *self_closing = is_self_closing;
            found = 1;
        }

        data = is_self_closing ? tag_end + 1 : closing_tag + strlen("</Data>");
    }

    return found;
}

STATIC char *escape_xml_text(const char *text)
{
    size_t length = 0;
    char *escaped;
    char *output;

    for (const char *current = text; *current; ++current) {
        size_t addition = 1;

        if (*current == '&') {
            addition = 5;
        } else if (*current == '<' || *current == '>') {
            addition = 4;
        }

        if (length > SIZE_MAX - addition - 1) {
            return NULL;
        }

        length += addition;
    }

    if ((escaped = malloc(length + 1)) == NULL) {
        return NULL;
    }

    output = escaped;
    for (const char *current = text; *current; ++current) {
        if (*current == '&') {
            memcpy(output, "&amp;", 5);
            output += 5;
        } else if (*current == '<') {
            memcpy(output, "&lt;", 4);
            output += 4;
        } else if (*current == '>') {
            memcpy(output, "&gt;", 4);
            output += 4;
        } else {
            *output++ = *current;
        }
    }
    *output = '\0';

    return escaped;
}

STATIC void enrich_member_name(char **xml_event)
{
    const char *member_name_start;
    const char *member_name_end;
    const char *member_sid_start;
    const char *member_sid_end;
    int member_name_self_closing;
    int member_sid_self_closing;
    size_t member_name_length;
    size_t member_sid_length;
    char *member_sid = NULL;
    PSID sid = NULL;
    char *account = NULL;
    char *domain = NULL;
    char *resolved = NULL;
    char *escaped = NULL;
    char *updated_xml = NULL;
    SID_NAME_USE sid_type;
    size_t account_length;
    size_t domain_length;
    size_t separator_length;
    size_t resolved_length;
    size_t prefix_length;
    size_t opening_length;
    size_t escaped_length;
    size_t closing_length;
    size_t suffix_length;
    size_t updated_length;

    if (xml_event == NULL || *xml_event == NULL) {
        return;
    }

    if (!find_event_data(*xml_event,
                         "MemberName",
                         &member_name_start,
                         &member_name_end,
                         &member_name_self_closing) ||
        !find_event_data(*xml_event,
                         "MemberSid",
                         &member_sid_start,
                         &member_sid_end,
                         &member_sid_self_closing)) {
        return;
    }

    member_name_length = member_name_self_closing ? 0 : member_name_end - member_name_start;
    if (member_name_length != 0 && (member_name_length != 1 || member_name_start[0] != '-')) {
        return;
    }

    if (member_sid_self_closing) {
        return;
    }

    member_sid_length = member_sid_end - member_sid_start;
    if (member_sid_length == 0 || member_sid_length > MAX_SID_STRING_LENGTH ||
        (member_sid_length == 1 && member_sid_start[0] == '-')) {
        return;
    }

    if (member_sid_length == SIZE_MAX || (member_sid = malloc(member_sid_length + 1)) == NULL) {
        goto cleanup;
    }
    memcpy(member_sid, member_sid_start, member_sid_length);
    member_sid[member_sid_length] = '\0';

    if (!ConvertStringSidToSidA(member_sid, &sid) || sid == NULL) {
        goto cleanup;
    }

    if (!utf8_LookupAccountSid(NULL, sid, &account, NULL, &domain, NULL, &sid_type) ||
        account == NULL || account[0] == '\0' || domain == NULL) {
        goto cleanup;
    }

    account_length = strlen(account);
    domain_length = strlen(domain);
    separator_length = domain_length ? 1 : 0;

    if (domain_length > SIZE_MAX - separator_length ||
        domain_length + separator_length > SIZE_MAX - account_length ||
        domain_length + separator_length + account_length == SIZE_MAX) {
        goto cleanup;
    }
    resolved_length = domain_length + separator_length + account_length;

    if ((resolved = malloc(resolved_length + 1)) == NULL) {
        goto cleanup;
    }

    if (domain_length) {
        memcpy(resolved, domain, domain_length);
        resolved[domain_length] = '\\';
    }
    memcpy(resolved + domain_length + separator_length, account, account_length + 1);

    if ((escaped = escape_xml_text(resolved)) == NULL) {
        goto cleanup;
    }

    prefix_length = member_name_start - *xml_event;
    opening_length = member_name_self_closing ? 1 : 0;
    escaped_length = strlen(escaped);
    closing_length = member_name_self_closing ? strlen("</Data>") : 0;
    suffix_length = strlen(member_name_end);

    if (prefix_length > SIZE_MAX - opening_length ||
        prefix_length + opening_length > SIZE_MAX - escaped_length ||
        prefix_length + opening_length + escaped_length > SIZE_MAX - closing_length ||
        prefix_length + opening_length + escaped_length + closing_length > SIZE_MAX - suffix_length ||
        prefix_length + opening_length + escaped_length + closing_length + suffix_length == SIZE_MAX) {
        goto cleanup;
    }
    updated_length = prefix_length + opening_length + escaped_length + closing_length + suffix_length;

    if ((updated_xml = malloc(updated_length + 1)) == NULL) {
        goto cleanup;
    }

    memcpy(updated_xml, *xml_event, prefix_length);
    if (member_name_self_closing) {
        updated_xml[prefix_length] = '>';
        memcpy(updated_xml + prefix_length + opening_length, escaped, escaped_length);
        memcpy(updated_xml + prefix_length + opening_length + escaped_length, "</Data>", closing_length);
    } else {
        memcpy(updated_xml + prefix_length, escaped, escaped_length);
    }
    memcpy(updated_xml + prefix_length + opening_length + escaped_length + closing_length,
           member_name_end,
           suffix_length + 1);

    os_free(*xml_event);
    *xml_event = updated_xml;
    updated_xml = NULL;

cleanup:
    os_free(updated_xml);
    os_free(escaped);
    os_free(resolved);
    os_free(domain);
    os_free(account);
    if (sid != NULL) {
        LocalFree(sid);
    }
    os_free(member_sid);
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
    char *xml_event = NULL;

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

    if (_stricmp(channel->evt_log, "Security") == 0) {
        enrich_member_name(&xml_event);
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
    os_free(xml_event);
    os_free(properties_values);

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
