/*
 * Wazuh - Indexer connector unit tests
 * Copyright (C) Wazuh Inc.
 * September 08, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "loggerHelper.h"
#include <gtest/gtest.h>

int main(int argc, char** argv)
{
    Log::assignLogFunction([](const int, const char*, const char*, const int, const char*, const char*, va_list) {});
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
