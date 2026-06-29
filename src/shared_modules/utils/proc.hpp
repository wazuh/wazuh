/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef PROC_HPP
#define PROC_HPP

extern "C" int get_nproc();

inline unsigned int cpp_get_nproc()
{
    return static_cast<unsigned int>(get_nproc());
}

#endif // PROC_HPP
