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

/* With event channel support */
#ifdef EVENTCHANNEL_SUPPORT

/* Saying we are on Vista in order to have the API */
#define _WIN32_WINNT 0x0600

/* Using Secure APIs */
#define MINGW_HAS_SECURE_API

/* Bookmarks directory */
#define BOOKMARKS_DIR "bookmarks"

#ifndef WC_ERR_INVALID_CHARS
    #define WC_ERR_INVALID_CHARS 0x80
#endif

/* Logging levels */
#define WINEVENT_AUDIT		0
#define WINEVENT_CRITICAL	1
#define WINEVENT_ERROR		2
#define WINEVENT_WARNING	3
#define WINEVENT_INFORMATION	4
#define WINEVENT_VERBOSE	5

/* Audit types */
#define WINEVENT_AUDIT_FAILURE 0x10000000000000LL
#define WINEVENT_AUDIT_SUCCESS 0x20000000000000L

#include "shared.h"
#include "logcollector.h"

#include <stdint.h>
#include <winevt.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>
#include <sddl.h>

typedef struct _os_event
{
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

typedef struct _os_channel
{
	char bookmark_enabled;
	EVT_HANDLE bookmark;
	char *evt_log;
	char bookmark_filename[OS_MAXSTR];
} os_channel;

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

void replace_slash(char *string)
{
	/* Replace '/' with underscore */
	if (strchr(string, '/'))
		*(strrchr(string, '/')) = '_';
}

char *convert_windows_string(LPCWSTR string)
{
	char *dest = NULL;
	size_t size = 0;
	int result = 0;

	if (string == NULL)
		return(NULL);

	/* determine size required */
	size = WideCharToMultiByte(
		CP_UTF8,
		WC_ERR_INVALID_CHARS,
		string,
		-1,
		NULL,
		0,
		NULL,
		NULL
	);

	if (size == 0)
	{
		log2file(
			"%s: ERROR: Could not WideCharToMultiByte() when determining size which returned (%lu)",
			ARGV0,
			GetLastError()
		);

		return(NULL);
	}

	if ((dest = calloc(size, sizeof(char))) == NULL)
	{
		log2file(
			"%s: ERROR: Could not calloc() memory for WideCharToMultiByte() which returned [(%d)-(%s)]",
			ARGV0,
			errno,
			strerror(errno)
		);

		return(NULL);
	}

	result = WideCharToMultiByte(
		CP_UTF8,
		WC_ERR_INVALID_CHARS,
		string,
		-1,
		dest,
		size,
		NULL,
		NULL
	);

	if (result == 0)
	{
		log2file(
			"%s: ERROR: Could not WideCharToMultiByte() which returned (%lu)",
			ARGV0,
			GetLastError()
		);

		free(dest);
		return(NULL);
	}

	return(dest);
}

wchar_t *convert_unix_string(char *string)
{
	wchar_t *dest = NULL;
	size_t size = 0;
	int result = 0;

	if (string == NULL)
		return(NULL);

	/* determine size required */
	size = MultiByteToWideChar(
		CP_UTF8,
		MB_ERR_INVALID_CHARS,
		string,
		-1,
		NULL,
		0
	);

	if (size == 0)
	{
		log2file(
			"%s: ERROR: Could not MultiByteToWideChar() when determining size which returned (%lu)",
			ARGV0,
			GetLastError()
		);

		return(NULL);
	}

	if ((dest = calloc(size, sizeof(wchar_t))) == NULL)
	{
		log2file(
			"%s: ERROR: Could not calloc() memory for MultiByteToWideChar() which returned [(%d)-(%s)]",
			ARGV0,
			errno,
			strerror(errno)
		);

		return(NULL);
	}

	result = MultiByteToWideChar(
		CP_UTF8,
		MB_ERR_INVALID_CHARS,
		string,
		-1,
		dest,
		size
	);

	if (result == 0)
	{
		log2file(
			"%s: ERROR: Could not MultiByteToWideChar() which returned (%lu)",
			ARGV0,
			GetLastError()
		);

		free(dest);
		return(NULL);
	}

	return(dest);
}

char *get_property_value(PEVT_VARIANT value)
{
	if (value->Type == EvtVarTypeNull)
		return(NULL);

	return(convert_windows_string(value->StringVal));
}

int get_username_and_domain(os_event *event)
{
	int result = 0;
	DWORD user_length = 0;
	DWORD domain_length = 0;
	SID_NAME_USE account_type;
	LPTSTR StringSid = NULL;

	/* Try to convert SID to a string. This isn't necessary to make
	 * things work but it is nice to have for error and debug logging.
	 */
	if (!ConvertSidToStringSid(event->uid, &StringSid))
	{
		debug1(
			"%s: WARN: Could not convert SID to string which returned (%lu)",
			ARGV0,
			GetLastError()
		);

		StringSid = "unknown";
	}

	debug1(
		"%s: DEBUG: Performing a LookupAccountSid() on (%s)",
		ARGV0,
		StringSid
	);

	/* Make initial call to get buffer size */
	result = LookupAccountSid(
		NULL,
		event->uid,
		NULL,
		&user_length,
		NULL,
		&domain_length,
		&account_type
	);

	if (result == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		if ((event->user = calloc(user_length, sizeof(char))) == NULL)
		{
			log2file(
				"%s: ERROR: Could not lookup SID (%s) due to calloc() failure on user which returned [(%d)-(%s)]",
				ARGV0,
				StringSid,
				errno,
				strerror(errno)
			);

			goto error;
		}

		if ((event->domain = calloc(domain_length, sizeof (char))) == NULL)
		{
			log2file(
				"%s: ERROR: Could not lookup SID (%s) due to calloc() failure on domain which returned [(%d)-(%s)]",
				ARGV0,
				StringSid,
				errno,
				strerror(errno)
			);

			goto error;
		}

		result = LookupAccountSid(
			NULL,
			event->uid,
			event->user,
			&user_length,
			event->domain,
			&domain_length,
			&account_type
		);

		if (result == FALSE)
		{
			log2file(
				"%s: ERROR: Could not LookupAccountSid() for (%s) which returned (%lu)",
				ARGV0,
				StringSid,
				GetLastError()
			);

			goto error;
		}
	}

	LocalFree(StringSid);

	/* success */
	return(1);

error:
	event->user = NULL;
	event->domain = NULL;
	LocalFree(StringSid);

	return(0);
}

char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags)
{
	char *message = NULL;
	EVT_HANDLE publisher = NULL;
	DWORD size = 0;
	wchar_t *buffer = NULL;
	int result = 0;

	publisher = EvtOpenPublisherMetadata(NULL, provider_name, NULL, 0, 0);

	if (publisher == NULL)
	{
		log2file(
			"%s: ERROR: Could not EvtOpenPublisherMetadata() with flags (%lu) which returned (%lu)",
			ARGV0,
			flags,
			GetLastError()
		);

		return(NULL);
	}

	/* Make initial call to determine buffer size */
	result = EvtFormatMessage(
		publisher,
		evt,
		0,
		0,
		NULL,
		flags,
		0,
		NULL,
		&size
	);

	if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		log2file(
			"%s: ERROR: Could not EvtFormatMessage() to determine buffer size with flags (%lu) which returned (%lu)",
			ARGV0,
			flags,
			GetLastError()
		);

		return(NULL);
	}

	if ((buffer = calloc(size, sizeof(wchar_t))) == NULL)
	{
		log2file(
			"%s: ERROR: Could not calloc() memory which returned [(%d)-(%s)]",
			ARGV0,
			errno,
			strerror(errno)
		);

		return(NULL);
	}

	result = EvtFormatMessage(
		publisher,
		evt,
		0,
		0,
		NULL,
		flags,
		size,
		buffer,
		&size
	);

	if (result == TRUE)
	{
		message = convert_windows_string(buffer);
	}

	free(buffer);

	if (result == FALSE)
	{
		log2file(
			"%s: ERROR: Could not EvtFormatMessage() with flags (%lu) which returned (%lu)",
			ARGV0,
			flags,
			GetLastError()
		);

		return(NULL);
	}

	return(message);
}

/* Read an existing bookmark (if one exists) */
EVT_HANDLE read_bookmark(os_channel *channel)
{
	EVT_HANDLE bookmark = NULL;
	size_t size = 0;
	FILE *fp = NULL;
	wchar_t bookmark_xml[OS_MAXSTR];

	/* If we have a stored bookmark, start from it */
	if ((fp = fopen(channel->bookmark_filename, "r")) == NULL)
	{
		/* Check if the error was not because the
		 * file did not exist which should be logged
		 */
		if (errno != ENOENT)
		{
			log2file(
				"%s: ERROR: Could not fopen() existing bookmark (%s) for (%s) which returned [(%d)-(%s)]",
				ARGV0,
				channel->bookmark_filename,
				channel->evt_log,
				errno,
				strerror(errno)
			);
		}

		return(NULL);
	}

	size = fread(bookmark_xml, sizeof(wchar_t), OS_MAXSTR, fp);

	if (ferror(fp))
	{
		log2file(
			"%s: ERROR: Could not fread() bookmark (%s) for (%s) which returned [(%d)-(%s)]",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			errno,
			strerror(errno)
		);

		fclose(fp);
		return(NULL);
	}

	fclose(fp);

	/* Make sure bookmark data was read */
	if (size == 0)
		return(NULL);

	/* Make sure bookmark is terminated properly */
	bookmark_xml[size] = L'\0';

	/* Create bookmark from saved xml */
	if ((bookmark = EvtCreateBookmark(bookmark_xml)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not EvtCreateBookmark() bookmark (%s) for (%s) which returned (%lu)",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			GetLastError()
		);

		return(NULL);
	}

	return(bookmark);
}

/* Update the log position of a bookmark */
int update_bookmark(EVT_HANDLE evt, os_channel *channel)
{
	DWORD size = 0;
	DWORD count = 0;
	wchar_t *buffer = NULL;
	int result = 0;
	EVT_HANDLE bookmark = NULL;
	FILE *fp = NULL;
	char tmp_file[OS_MAXSTR];

	/* Create bookmark temporary file name */
	snprintf(
		tmp_file,
		sizeof(tmp_file),
		"%s/%s-XXXXXX",
		TMP_DIR,
		channel->evt_log
	);

	replace_slash(tmp_file);

	if ((bookmark = EvtCreateBookmark(NULL)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not EvtCreateBookmark() bookmark (%s) for (%s) which returned (%lu)",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			GetLastError()
		);

		return(0);
	}

	if (!EvtUpdateBookmark(bookmark, evt))
	{
		log2file(
			"%s: ERROR: Could not EvtUpdateBookmark() bookmark (%s) for (%s) which returned (%lu)",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			GetLastError()
		);

		return(0);
	}

	/* Make initial call to determine buffer size */
	result = EvtRender(NULL, bookmark, EvtRenderBookmark, 0, NULL, &size, &count);

	if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		log2file(
			"%s: ERROR: Could not EvtRender() to get buffer size to update bookmark (%s) for (%s) which returned (%lu)",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			GetLastError()
		);

		return(0);
	}

	if ((buffer = calloc(size, 1)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not calloc() memory to save bookmark (%s) for (%s) which returned [(%d)-(%s)]",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			errno,
			strerror(errno)
		);

		return(0);
	}

	if (!EvtRender(NULL, bookmark, EvtRenderBookmark, size, buffer, &size, &count))
	{
		log2file(
			"%s: ERROR: Could not EvtRender() bookmark (%s) for (%s) which returned (%lu)",
			ARGV0,
			channel->bookmark_filename,
			channel->evt_log,
			GetLastError()
		);

		return(0);
	}

	if (mkstemp_ex(tmp_file))
	{
		log2file(
			"%s: ERROR: Could not mkstemp_ex() temporary bookmark (%s) for (%s)",
			ARGV0,
			tmp_file,
			channel->evt_log
		);

		return(0);
	}

	if ((fp = fopen(tmp_file, "w")) == NULL)
	{
		log2file(
			"%s: ERROR: Could not fopen() temporary bookmark (%s) for (%s) which returned [(%d)-(%s)]",
			ARGV0,
			tmp_file,
			channel->evt_log,
			errno,
			strerror(errno)
		);

		goto error;
	}

	if ((fwrite(buffer, 1, size, fp)) < size)
	{
		log2file(
			"%s: ERROR: Could not fwrite() to temporary bookmark (%s) for (%s) which returned [(%d)-(%s)]",
			ARGV0,
			tmp_file,
			channel->evt_log,
			errno,
			strerror(errno)
		);

		goto error;
	}

	fclose(fp);

	if (rename_ex(tmp_file, channel->bookmark_filename))
	{
		log2file(
			"%s: ERROR: Could not rename_ex() temporary bookmark (%s) to (%s) for (%s)",
			ARGV0,
			tmp_file,
			channel->bookmark_filename,
			channel->evt_log
		);

		goto error;
	}

	/* success */
	return(1);

error:
	if (fp)
		fclose(fp);

	if (unlink(tmp_file))
	{
		log2file(DELETE_ERROR, ARGV0, tmp_file, errno, strerror(errno));
	}

	return(0);
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

	if ((timestamp = malloc(size)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not malloc() memory to convert timestamp which returned [(%d)-(%s)]",
			ARGV0,
			errno,
			strerror(errno)
		);

		goto error;
	}

	/* Zero out structure */
	memset(&tm_struct, 0, sizeof(tm_struct));

	/* Convert from ULONGLONG to usable FILETIME value */
	ulargeTime.QuadPart = ulongTime;

	fTime.dwLowDateTime = ulargeTime.LowPart;
	fTime.dwHighDateTime = ulargeTime.HighPart;

	/* Adjust time value to reflect current timezone */
	/* then convert to a SYSTEMTIME */
	if (FileTimeToLocalFileTime(&fTime, &lfTime) == 0)
	{
		log2file(
			"%s: ERROR: Could not FileTimeToLocalFileTime() to convert timestamp which returned (%lu)",
			ARGV0,
			GetLastError()
		);

		goto error;
	}

	if (FileTimeToSystemTime(&lfTime, &sysTime) == 0)
	{
		log2file(
			"%s: ERROR: Could not FileTimeToSystemTime() to convert timestamp which returned (%lu)",
			ARGV0,
			GetLastError()
		);

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
	strftime(timestamp, size, "%Y %b %d %H:%M:%S", &tm_struct);

	return(timestamp);

error:
	free(timestamp);

	return(NULL);
}

void send_channel_event(EVT_HANDLE evt, os_channel *channel)
{
	DWORD buffer_length = 0;
	PEVT_VARIANT properties_values = NULL;
	DWORD count = 0;
	EVT_HANDLE context = NULL;
	os_event event = {0};
	char final_msg[OS_MAXSTR];
	int result = 0;

	if ((context = EvtCreateRenderContext(count, NULL, EvtRenderContextSystem)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not EvtCreateRenderContext() for (%s) which returned (%lu)",
			ARGV0,
			channel->evt_log,
			GetLastError()
		);

		goto error;
	}

	/* Make initial call to determine buffer size necessary */
	result = EvtRender(context, evt, EvtRenderEventValues, 0, NULL, &buffer_length, &count);

	if (result != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		log2file(
			"%s: ERROR: Could not EvtRender() to determine buffer size for (%s) which returned (%lu)",
			ARGV0,
			channel->evt_log,
			GetLastError()
		);

		goto error;
	}

	if ((properties_values = malloc(buffer_length)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not malloc() memory to process event (%s) which returned [(%d)-(%s)]",
			ARGV0,
			channel->evt_log,
			errno,
			strerror(errno)
		);

		goto error;
	}

	if (!EvtRender(context, evt, EvtRenderEventValues, buffer_length, properties_values, &buffer_length, &count))
	{
		log2file(
			"%s: ERROR: Could not EvtRender() for (%s) which returned (%lu)",
			ARGV0,
			channel->evt_log,
			GetLastError()
		);

		goto error;
	}

	event.name = get_property_value(&properties_values[EvtSystemChannel]);
	event.id = properties_values[EvtSystemEventID].UInt16Val;
	event.source = get_property_value(&properties_values[EvtSystemProviderName]);
	event.uid = properties_values[EvtSystemUserID].Type == EvtVarTypeNull ? NULL : properties_values[EvtSystemUserID].SidVal;
	event.computer = get_property_value(&properties_values[EvtSystemComputer]);
	event.time_created = properties_values[EvtSystemTimeCreated].FileTimeVal;
	event.keywords = properties_values[EvtSystemKeywords].Type == EvtVarTypeNull ? 0 : properties_values[EvtSystemKeywords].UInt64Val;
	event.level = properties_values[EvtSystemLevel].Type == EvtVarTypeNull ? -1 : properties_values[EvtSystemLevel].ByteVal;

	switch(event.level)
	{
		case WINEVENT_CRITICAL:
			event.category = "CRITICAL";
			break;
		case WINEVENT_ERROR:
			event.category = "ERROR";
			break;
		case WINEVENT_WARNING:
			event.category = "WARNING";
			break;
		case WINEVENT_INFORMATION:
			event.category = "INFORMATION";
			break;
		case WINEVENT_VERBOSE:
			event.category = "DEBUG";
			break;
		case WINEVENT_AUDIT:
			if (event.keywords & WINEVENT_AUDIT_FAILURE)
			{
				event.category = "AUDIT_FAILURE";
				break;
			}
			else if (event.keywords & WINEVENT_AUDIT_SUCCESS)
			{
				event.category = "AUDIT_SUCCESS";
				break;
			}
			/* else fall through */
		default:
			event.category = "Unknown";
			break;
	}

	if ((event.timestamp = WinEvtTimeToString(event.time_created)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not convert timestamp for (%s)",
			ARGV0,
			channel->evt_log
		);

		goto error;
	}

	/* Determine user and domain */
	get_username_and_domain(&event);

	/* Get event log message */
	if ((event.message = get_message(evt, properties_values[EvtSystemProviderName].StringVal, EvtFormatMessageEvent)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not get message for (%s)",
			ARGV0,
			channel->evt_log
		);
	}
	else
	{
		/* format message */
		win_format_event_string(event.message);
	}

	snprintf(
		final_msg,
		sizeof(final_msg),
		"%s WinEvtLog: %s: %s(%d): %s: %s: %s: %s: %s",
		event.timestamp,
		event.name,
		event.category,
		event.id,
		event.source && strlen(event.source) ? event.source : "no source",
		event.user && strlen(event.user) ? event.user : "(no user)",
		event.domain && strlen(event.domain) ? event.domain : "no domain",
		event.computer && strlen(event.computer) ? event.computer : "no computer",
		event.message && strlen(event.message) ? event.message : "(no message)"
	);

	if(SendMSG(logr_queue, final_msg, "WinEvtLog", LOCALFILE_MQ) < 0)
    	{
		merror(QUEUE_SEND, ARGV0);
    	}

    	if (channel->bookmark_enabled)
		update_bookmark(evt, channel);

error:
	free(properties_values);
	free_event(&event);

	return;
}

DWORD WINAPI event_channel_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, os_channel *channel, EVT_HANDLE evt)
{
	if (action == EvtSubscribeActionDeliver)
	{
		send_channel_event(evt, channel);
	}

	return(0);
}

void win_start_event_channel(char *evt_log, char future, char *query)
{
	wchar_t		*wchannel = NULL;
	wchar_t		*wquery = NULL;
	os_channel  	*channel = NULL;
	DWORD		flags = EvtSubscribeToFutureEvents;
	EVT_HANDLE 	bookmark = NULL;
	EVT_HANDLE	result = NULL;

	if ((channel = calloc(1, sizeof(os_channel))) == NULL)
	{
		log2file(
			"%s: ERROR: Could not calloc() memory for channel to start reading (%s) which returned [(%d)-(%s)]",
			ARGV0,
			evt_log,
			errno,
			strerror(errno)
		);

		goto error;
	}

	channel->evt_log = evt_log;

	/* Convert evt_log to windows string */
	if ((wchannel = convert_unix_string(channel->evt_log)) == NULL)
	{
		log2file(
			"%s: ERROR: Could not convert_unix_string() evt_log for (%s) which returned [(%d)-(%s)]",
			ARGV0,
			channel->evt_log,
			errno,
			strerror(errno)
		);

		goto error;
	}

	/* Convert query to windows string */
	if (query)
	{
		if ((wquery = convert_unix_string(query)) == NULL)
		{
			log2file(
				"%s: ERROR: Could not convert_unix_string() query for (%s) which returned [(%d)-(%s)]",
				ARGV0,
				channel->evt_log,
				errno,
				strerror(errno)
			);

			goto error;
		}
	}

	channel->bookmark_enabled = !future;

	if (channel->bookmark_enabled)
	{
		/* Create bookmark file name */
		snprintf(
			channel->bookmark_filename,
			sizeof(channel->bookmark_filename),
			"%s/%s",
			BOOKMARKS_DIR,
			channel->evt_log
		);

		replace_slash(channel->bookmark_filename);

		/* Try to read existing bookmark */
		if ((bookmark = read_bookmark(channel)) != NULL)
		{
			flags = EvtSubscribeStartAfterBookmark;
		}
	}

	result = EvtSubscribe(
		NULL,
		NULL,
		wchannel,
		wquery,
		bookmark,
		channel,
		(EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
		flags
	);

	if (result == NULL && flags == EvtSubscribeStartAfterBookmark)
	{
		result = EvtSubscribe(
			NULL,
			NULL,
			wchannel,
			wquery,
			NULL,
			channel,
			(EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
			EvtSubscribeToFutureEvents
		);
	}

	if (result == NULL)
	{
		log2file(
			"%s: ERROR: Could not EvtSubscribe() for (%s) which returned (%lu)",
			ARGV0,
			channel->evt_log,
			GetLastError()
		);

		goto error;
	}

	free(wchannel);
	free(wquery);

	return;

error:
	free(wchannel);
	free(wquery);
	free(channel);

	return;
}

#endif
#endif
