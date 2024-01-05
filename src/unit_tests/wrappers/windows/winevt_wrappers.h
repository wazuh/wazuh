
/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WINEVT_WRAPPERS_H
#define WINEVT_WRAPPERS_H

#include <windows.h>
#include <winevt.h>

#undef EvtRender
#define EvtRender wrap_EvtRender
#undef EvtCreateRenderContext
#define EvtCreateRenderContext wrap_EvtCreateRenderContext
#undef EvtSubscribe
#define EvtSubscribe wrap_EvtSubscribe
#undef EvtClose
#define EvtClose wrap_EvtClose
#undef EvtOpenPublisherMetadata
#define EvtOpenPublisherMetadata wrap_EvtOpenPublisherMetadata
#undef EvtFormatMessage
#define EvtFormatMessage wrap_EvtFormatMessage

BOOL wrap_EvtRender(EVT_HANDLE Context,
                    EVT_HANDLE Fragment,
                    DWORD      Flags,
                    DWORD      BufferSize,
                    PVOID      Buffer,
                    PDWORD     BufferUsed,
                    PDWORD     PropertyCount);

EVT_HANDLE wrap_EvtCreateRenderContext(DWORD   ValuePathsCount,
                                       LPCWSTR *ValuePaths,
                                       DWORD   Flags);

EVT_HANDLE wrap_EvtSubscribe(EVT_HANDLE             Session,
                             HANDLE                 SignalEvent,
                             LPCWSTR                ChannelPath,
                             LPCWSTR                Query,
                             EVT_HANDLE             Bookmark,
                             PVOID                  Context,
                             EVT_SUBSCRIBE_CALLBACK Callback,
                             DWORD                  Flags);

BOOL wrap_EvtClose(EVT_HANDLE object);

EVT_HANDLE wrap_EvtOpenPublisherMetadata(EVT_HANDLE Session,
                                         LPCWSTR    PublisherId,
                                         LPCWSTR    LogFilePath,
                                         LCID       Locale,
                                         DWORD      Flags);

BOOL wrap_EvtFormatMessage(EVT_HANDLE   PublisherMetadata,
                           EVT_HANDLE   Event,
                           DWORD        MessageId,
                           DWORD        ValueCount,
                           PEVT_VARIANT Values,
                           DWORD        Flags,
                           DWORD        BufferSize,
                           LPWSTR       Buffer,
                           PDWORD       BufferUsed);
#endif
