/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef H_MATHOP_OS
#define H_MATHOP_OS

/**
 * @brief Get the first available prime after the provided value.
 *
 * @param val Provided value.
 * @return Returns the first available prime or 0 on error.
 */
unsigned int os_getprime(unsigned int val);

#endif
