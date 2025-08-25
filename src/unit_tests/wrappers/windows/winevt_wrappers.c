/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "winevt_wrappers.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <tchar.h>

BOOL wrap_EvtRender(EVT_HANDLE Context,
                    EVT_HANDLE Fragment,
                    DWORD      Flags,
                    DWORD      BufferSize,
                    PVOID      Buffer,
                    PDWORD     BufferUsed,
                    PDWORD     PropertyCount) {
  check_expected_ptr(Context);
  check_expected_ptr(Fragment);
  check_expected(Flags);
  check_expected(BufferSize);
  PEVT_VARIANT output = mock_ptr_type(PEVT_VARIANT);
  *BufferUsed = mock_type(int);
  *PropertyCount = mock_type(int);
  if (output && Buffer && *BufferUsed <= BufferSize) {
    memcpy(Buffer, output, *BufferUsed);
  }
  return mock();
}

EVT_HANDLE wrap_EvtCreateRenderContext(DWORD   ValuePathsCount,
                                       LPCWSTR *ValuePaths,
                                       DWORD   Flags) {
    check_expected(ValuePathsCount),
    check_expected_ptr(ValuePaths);
    check_expected(Flags);
    return mock_type(EVT_HANDLE);
}

EVT_HANDLE wrap_EvtSubscribe(EVT_HANDLE             Session,
                             HANDLE                 SignalEvent,
                             LPCWSTR                ChannelPath,
                             LPCWSTR                Query,
                             EVT_HANDLE             Bookmark,
                             PVOID                  Context,
                             EVT_SUBSCRIBE_CALLBACK Callback,
                             DWORD                  Flags) {
    check_expected_ptr(Session);
    check_expected(SignalEvent);
    check_expected(ChannelPath);
    check_expected(Query);
    check_expected(Bookmark);
    check_expected(Context);
    check_expected_ptr(Callback);
    check_expected(Flags);
    return mock_type(EVT_HANDLE);
}

BOOL wrap_EvtClose(__UNUSED_PARAM(EVT_HANDLE object)) {
    return mock_type(BOOL);
}

EVT_HANDLE wrap_EvtOpenPublisherMetadata(EVT_HANDLE Session,
                                         LPCWSTR    PublisherId,
                                         LPCWSTR    LogFilePath,
                                         LCID       Locale,
                                         DWORD      Flags) {
  check_expected_ptr(Session);
  check_expected(PublisherId);
  check_expected(LogFilePath);
  check_expected(Locale);
  check_expected(Flags);
  return mock_type(EVT_HANDLE);
}

BOOL wrap_EvtFormatMessage(__UNUSED_PARAM(EVT_HANDLE   PublisherMetadata),
                           __UNUSED_PARAM(EVT_HANDLE   Event),
                           __UNUSED_PARAM(DWORD        MessageId),
                           __UNUSED_PARAM(DWORD        ValueCount),
                           __UNUSED_PARAM(PEVT_VARIANT Values),
                           __UNUSED_PARAM(DWORD        Flags),
                           DWORD        BufferSize,
                           LPWSTR       Buffer,
                           PDWORD       BufferUsed) {

  if(BufferSize) {
    char *mockMessage = mock_type(char*);
    _stprintf_s(Buffer, BufferSize, _T("%hs"), mockMessage);
    *BufferUsed = BufferSize;
  }
  else {
    *BufferUsed = mock_type(int);
  }
  return mock_type(BOOL);
}
