/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Stub implementations for Windows-specific functions that are called
 * from shared library code but are only meaningful in the agent context.
 */

#ifdef WIN32

#include "shared.h"

/* Stub for WinSetError */
void WinSetError() {
    /* Active-response executables don't need this */
}

#endif /* WIN32 */
