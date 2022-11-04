/*
 * Hooking helper.
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 3, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef HOOKING_H
#define HOOKING_H

/**
 * @brief Hook LdrLoadDll function.
 *
 */
void hook_LdrLoadDll();

#endif // HOOKING_H
