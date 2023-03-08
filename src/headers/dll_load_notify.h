/*
 * Dll load notification helper.
 * Copyright (C) 2015, Wazuh Inc.
 * November 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DLL_LOAD_NOTIFY_H
#define _DLL_LOAD_NOTIFY_H

#ifdef WIN32
#include "cryptography.h"
#include <winternl.h>
#include <windows.h>
#include <psapi.h>

enum LDR_DLL_NOTIFICATION_REASON
{
	LDR_DLL_NOTIFICATION_REASON_LOADED = 1,
	LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2,
};

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG flags;                      //Reserved.
	PCUNICODE_STRING full_dll_name;   //The full path name of the DLL module.
	PCUNICODE_STRING base_dll_name;   //The base file name of the DLL module.
	PVOID dll_base;                   //A pointer to the base address for the DLL in memory.
	ULONG size_of_image;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG flags;                      //Reserved.
	PCUNICODE_STRING full_dll_name;   //The full path name of the DLL module.
	PCUNICODE_STRING base_dll_name;   //The base file name of the DLL module.
	PVOID dll_base;                   //A pointer to the base address for the DLL in memory.
	ULONG size_of_image;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;


typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
	_In_     ULONG                       notification_reason,
	_In_     PLDR_DLL_NOTIFICATION_DATA  notification_data,
	_In_opt_ PVOID                       context
);


typedef NTSTATUS (NTAPI *_LdrRegisterDllNotification)(
	_In_     ULONG                          flags,
	_In_     PLDR_DLL_NOTIFICATION_FUNCTION notification_function,
	_In_opt_ PVOID                          context,
	_Out_    PVOID                          *cookie
);

typedef NTSTATUS (NTAPI *_LdrUnregisterDllNotification)(
	_In_ PVOID Cookie
);

/**
 * @brief Enable and verify the DLL load notifications.
 */
void enable_dll_verification();

#endif // WIN32
#endif // _DLL_LOAD_NOTIFY_H
