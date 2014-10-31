/* @(#) $Id: ./src/logcollector/read_win_event_channel.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* This is only for windows */
#ifdef WIN32

// With event channel support
#ifdef EVENTCHANNEL_SUPPORT

// Saying we are on Vista in order to have the API
#define _WIN32_WINNT 0x0600

// Using Secure APIs
#define MINGW_HAS_SECURE_API

// Bookmarks directory
#define BOOKMARKS_DIR "bookmarks"

#include "shared.h"
#include "logcollector.h"

#include <winevt.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>

typedef struct _os_event
{
	char *name;
	char *level;
	unsigned int id;
	char *source;
	SID *uid;
	char *user;
	char *domain;
	char *computer;
	char *message;
	ULONGLONG time_created;
} os_event;

typedef struct _os_channel
{
	char bookmark_enabled;
	EVT_HANDLE bookmark;
	FILE *bookmark_file;
} os_channel;

EVT_HANDLE bookmark = NULL;

void free_event(os_event *event)
{
	free(event->name);
	free(event->level);
	free(event->source);
	free(event->user);
	free(event->domain);
	free(event->computer);
	free(event->message);
}

char *convert_windows_string(LPCWSTR string)
{
	char new_value[OS_MAXSTR];
	size_t len = 0;

	if (string == NULL)
		return (NULL);
	
	wcstombs_s(&len, new_value, OS_MAXSTR, string, OS_MAXSTR - 1);
	
	return (strdup(new_value));
}

char *get_property_value(PEVT_VARIANT value)
{
	if (EvtVarTypeNull == value->Type)
		return (NULL);

	return (convert_windows_string(value->StringVal));
}

void get_username_and_domain(os_event *event)
{
	DWORD user_length = 0;
	DWORD domain_length = 0;
	SID_NAME_USE account_type;
	
	LookupAccountSid(NULL, event->uid, NULL, &user_length,
					 NULL, &domain_length, &account_type);
	
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		event->user = calloc(user_length, sizeof (char));
		event->domain = calloc(domain_length, sizeof (char));
		
		if ((event->user != NULL) && (event->domain != NULL))
			LookupAccountSid(NULL, event->uid, event->user, &user_length,
							 event->domain, &domain_length, &account_type);
	}
	else
	{
		event->user = NULL;
		event->domain = NULL;
	}
}

void get_messages(os_event *event, EVT_HANDLE evt, LPCWSTR publisher_name)
{
	EVT_HANDLE publisher;
	DWORD size = 0;
	wchar_t *buffer = NULL;
	
	publisher = EvtOpenPublisherMetadata(NULL, publisher_name, NULL, 0, 0);
	
	EvtFormatMessage(publisher, evt, 0, 0, NULL, EvtFormatMessageEvent, 0, NULL, &size);
	buffer = calloc(size, sizeof (wchar_t));
	EvtFormatMessage(publisher, evt, 0, 0, NULL, EvtFormatMessageEvent, size, buffer, &size);
	event->message = convert_windows_string(buffer);
	free(buffer);
	
	EvtFormatMessage(publisher, evt, 0, 0, NULL, EvtFormatMessageLevel, 0, NULL, &size);
	buffer = calloc(size, sizeof (wchar_t));
	EvtFormatMessage(publisher, evt, 0, 0, NULL, EvtFormatMessageLevel, size, buffer, &size);
	event->level = convert_windows_string(buffer);
	free(buffer);
}

void update_bookmark(EVT_HANDLE evt, os_channel *context)
{
	DWORD size = 0;
	DWORD count = 0;
	wchar_t *buffer = NULL;
	int i = 0;
	
	EvtUpdateBookmark(context->bookmark, evt);
	EvtRender(NULL, context->bookmark, EvtRenderBookmark, 0, NULL, &size, &count);
	
	buffer = calloc(size, 1);
	if (buffer == NULL)
	{
		merror("%s: Not enough memory, could not save bookmark", ARGV0);
		return;
	}
	if (!EvtRender(NULL, context->bookmark, EvtRenderBookmark, size, buffer, &size, &count))
		merror("%s: could not render bookmark (%ld)", ARGV0, GetLastError());
	else
	{
		fseek(context->bookmark_file, 0, SEEK_SET);
		if (fwrite(buffer, 1, size, context->bookmark_file) < size)
			merror("%s: could not save bookmark (%ld)", ARGV0, GetLastError());
			
		// Write spaces to be certain to overwrite previous content
		for (i = 0; i < size; ++i)
			fputc(' ', context->bookmark_file); 
	
		fflush(context->bookmark_file);
	}
}

/* Format Timestamp from EventLog */
char *WinEvtTimeToString(ULONGLONG ulongTime)
{
	SYSTEMTIME sysTime;
	FILETIME fTime, lfTime;
	ULARGE_INTEGER ulargeTime;
	struct tm tm_struct;
	char *result;

	if (NULL == (result = malloc(80))) {
		merror("%s: Not enough memory, could not process convert Timestanp", ARGV0);
		goto error;
	}

	memset(&tm_struct, 0, sizeof(tm_struct));

	/* Convert from ULONGLONG to usable FILETIME value */
	ulargeTime.QuadPart = ulongTime;
	
	fTime.dwLowDateTime = ulargeTime.LowPart;
	fTime.dwHighDateTime = ulargeTime.HighPart;

	/* Adjust time value to reflect current timezone */
	/* then convert to a SYSTEMTIME */
	if (FileTimeToLocalFileTime(&fTime, &lfTime) == 0) {
		merror("%s: Error formatting event time", ARGV0);
		goto error;
	}

	if (FileTimeToSystemTime(&lfTime, &sysTime) == 0) {
		merror("%s: Error formatting event time", ARGV0);
		goto error;
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
	strftime(result, 80, "%Y %b %d %H:%M:%S", &tm_struct);

	return (result);

error:
	if (result) free(result);
	return NULL; 
}

void send_channel_event(EVT_HANDLE evt, os_channel *channel)
{
	DWORD buffer_length = 0;
	PEVT_VARIANT properties_values = NULL;
	LPCWSTR properties[] = {
		L"Event/System/Channel",
		L"Event/System/EventID",
		L"Event/System/Provider/@EventSourceName",
		L"Event/System/Security/@UserID",
		L"Event/System/Computer",
		L"Event/System/Provider/@Name",
		L"Event/System/TimeCreated/@SystemTime"
	};
    DWORD count = sizeof(properties)/sizeof(LPWSTR);
	EVT_HANDLE context = NULL;
	os_event event;
	char final_msg[OS_MAXSTR];
	char *timestamp;
	
	context = EvtCreateRenderContext(count, properties, EvtRenderContextValues);
	
	EvtRender(context, evt, EvtRenderEventValues, 0, NULL, &buffer_length, &count);
	
	if (NULL == (properties_values = malloc(buffer_length))) {
		merror("%s: Not enough memory, could not process event", ARGV0);
		return;
	}
	
	EvtRender(context, evt, EvtRenderEventValues, buffer_length, properties_values, &buffer_length, &count);
	
	event.name = get_property_value(&properties_values[0]);
	event.id = properties_values[1].UInt16Val;
	event.source = get_property_value(&properties_values[2]);
	event.uid = properties_values[3].Type == EvtVarTypeNull ? NULL : properties_values[3].SidVal;
	event.computer = get_property_value(&properties_values[4]);
	event.time_created = properties_values[6].FileTimeVal;
	
	get_username_and_domain(&event);
	get_messages(&event, evt, properties_values[5].StringVal);

	timestamp = WinEvtTimeToString(event.time_created);
	snprintf(final_msg, OS_MAXSTR, "%s WinEvtLog: %s: %s(%d): %s: %s: %s: %s: %s",
			 timestamp,
			 event.name,
			 event.level && strlen(event.level) ? event.level : "UNKNOWN",
			 event.id,
			 event.source && strlen(event.source) ? event.source : "no source",
			 event.user && strlen(event.user) ? event.user : "no user",
			 event.domain && strlen(event.domain) ? event.domain : "no domain",
			 event.computer && strlen(event.computer) ? event.computer : "no computer",
			 event.message && strlen(event.message) ? event.message : "no message");

	free(timestamp);

	if(SendMSG(logr_queue, final_msg, "WinEvtLog", LOCALFILE_MQ) < 0)
    {
		merror(QUEUE_SEND, ARGV0);
    }
    
    if (channel->bookmark_enabled)
		update_bookmark(evt, channel);
		
	free(properties_values);
	free_event(&event);
}

DWORD WINAPI event_channel_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
									os_channel *context,
									EVT_HANDLE evt)
{	
    if (action == EvtSubscribeActionDeliver)
	{
		send_channel_event(evt, context);
	}
	
	return (0);
}

void win_start_event_channel(char *evt_log, char future, char *query)
{
	wchar_t		*channel = NULL;
	wchar_t		*wquery = NULL;
	size_t		size = 0;
	os_channel  *context = NULL;
	DWORD		flags = EvtSubscribeToFutureEvents;
	EVT_HANDLE	bookmark = NULL;
	
	size = strlen(evt_log) + 1;

	channel = calloc(size, sizeof (wchar_t));
	if(channel == NULL) 
	{
		merror("%s: Not enough memory, skipping %s", ARGV0, evt_log);
		goto error;
        }
	context = calloc(1, sizeof (os_channel));
	
	if (context == NULL)
	{
		merror("%s: Not enough memory, skipping %s", ARGV0, evt_log);
		goto error;
	}

	// Convert 'evt_log' to windows string
	mbstowcs_s(&size, channel, size, evt_log, size - 1);
	
	// Convert 'query' to windows string
	if (query)
	{
		size = strlen(query) + 1;
		wquery = calloc(size, sizeof (wchar_t));
		if (wquery)
			mbstowcs_s(&size, wquery, size, query, size - 1);
	}
	
	context->bookmark_enabled = !future;

	if (context->bookmark_enabled)
	{
		char        file_name[OS_MAXSTR];
		wchar_t     bookmark_xml[OS_MAXSTR];
	
		snprintf(file_name, OS_MAXSTR, "%s/%s", BOOKMARKS_DIR, evt_log); 
		// Replace '/' by ' ' in the channel name
		if (strchr(evt_log, '/'))
			*(strrchr(file_name, '/')) = ' ';
	
		// If we have a stored bookmark, start from it
		if (access(file_name, F_OK) != -1)
		{	
			// Open the file and read storet bookmark
			context->bookmark_file = fopen(file_name, "r+");
			fseek(context->bookmark_file, 0, SEEK_SET);
			size = fread(bookmark_xml, sizeof (wchar_t), OS_MAXSTR, context->bookmark_file);
			bookmark_xml[size] = L'\0';
		
			// Create bookmark from saved xml
			context->bookmark = EvtCreateBookmark(bookmark_xml);
			if (context->bookmark == NULL)
			{
				merror("%s: Could not create bookmark from save (%ld)", ARGV0, GetLastError());
				context->bookmark = EvtCreateBookmark(NULL);
			}
			else
			{
				flags = EvtSubscribeStartAfterBookmark;
				bookmark = context->bookmark;
			}
		}
		else
		{
			// Create new bookmark
			context->bookmark = EvtCreateBookmark(NULL);
			// Create the file
			context->bookmark_file = fopen(file_name, "w");
			if (context->bookmark_file == NULL)
				merror("%s: could not create bookmark file %s (%ld)", ARGV0, file_name, GetLastError());
		}
	}
	
	if (EvtSubscribe(NULL, NULL, channel, wquery, bookmark, context,
					 (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
					 flags) == NULL)
	{
		// If it fails, fallback to future events only
		if (flags == EvtSubscribeStartAfterBookmark)
		{
			if (EvtSubscribe(NULL, NULL, channel, wquery, NULL, context,
							 (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
							 EvtSubscribeToFutureEvents) == NULL)
				merror("%s: Subscription error: %ld", ARGV0, GetLastError());
		}
		else 
			merror("%s: Subscription error: %ld", ARGV0, GetLastError());
	}
	
	free(channel);
	return;

error: 
	if(channel) free(channel); 
	if(context) free(context); 
	return; 
}

#endif
#endif
