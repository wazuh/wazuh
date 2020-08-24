/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include <cmocka.h>

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
