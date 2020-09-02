
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#define EvtRender wrap_EvtRender
#define EvtCreateRenderContext wrap_EvtCreateRenderContext
#define EvtSubscribe wrap_EvtSubscribe

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

#endif
