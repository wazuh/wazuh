/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfo.hpp"

// sysinfo_unit_test only compiles sysInfo.cpp (see CMakeLists.txt), not sysInfoWin.cpp,
// so on Windows it never gets the real implementation of releaseThreadResources() --
// and sysInfo.cpp's own fallback is guarded out under _WIN32 to avoid colliding with
// that real one in a full agent build. This stub plugs that gap for this test binary
// only. Guarded so it stays an empty translation unit on non-Windows platforms, where
// this directory's *.cpp glob (see CMakeLists.txt) would otherwise pick it up too and
// collide with sysInfo.cpp's own fallback definition.
#ifdef _WIN32
void SysInfo::releaseThreadResources() {}
#endif
