/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "osPrimitivesInterfaceMac.h"
#include "osPrimitives_mock.h"
#include "processesWrapperImplMac.h"

using ::testing::_;
using ::testing::Return;

namespace
{
    // wazuh#39126 regression: proc_listallpids() takes its buffersize argument in
    // bytes, not in pid_t count. Pins that listAllPids() always multiplies the
    // process count reported by kern.maxproc by sizeof(pid_t) before calling it.
    TEST(SysInfoProcessesMacTest, ListAllPids_PassesBufferSizeInBytesNotCount)
    {
        constexpr int32_t maxProc { 100 };
        OsPrimitivesMacMock mockPrimitives;

        EXPECT_CALL(mockPrimitives, sysctlbyname(testing::StrEq("kern.maxproc"), _, _, _, _))
        .WillOnce([](const char*, void* oldp, size_t*, void*, size_t)
        {
            *static_cast<int32_t*>(oldp) = maxProc;
            return 0;
        });

        EXPECT_CALL(mockPrimitives, proc_listallpids(_, maxProc * static_cast<int32_t>(sizeof(pid_t))))
        .WillOnce(Return(3));

        const auto pids { listAllPids(mockPrimitives) };
        EXPECT_EQ(3u, pids.size());
    }

    TEST(SysInfoProcessesMacTest, ListAllPids_ThrowsWhenKernMaxprocCannotBeRead)
    {
        OsPrimitivesMacMock mockPrimitives;

        EXPECT_CALL(mockPrimitives, sysctlbyname(testing::StrEq("kern.maxproc"), _, _, _, _))
        .WillOnce(Return(-1));

        EXPECT_CALL(mockPrimitives, proc_listallpids(_, _))
        .Times(0);

        EXPECT_THROW(listAllPids(mockPrimitives), std::system_error);
    }

    // proc_listallpids() documents -1 as its failure return; make sure that
    // doesn't turn into a huge/negative resize() on the result vector.
    TEST(SysInfoProcessesMacTest, ListAllPids_ClampsNegativeProcessesCountToEmpty)
    {
        constexpr int32_t maxProc { 100 };
        OsPrimitivesMacMock mockPrimitives;

        EXPECT_CALL(mockPrimitives, sysctlbyname(testing::StrEq("kern.maxproc"), _, _, _, _))
        .WillOnce([](const char*, void* oldp, size_t*, void*, size_t)
        {
            *static_cast<int32_t*>(oldp) = maxProc;
            return 0;
        });

        EXPECT_CALL(mockPrimitives, proc_listallpids(_, _))
        .WillOnce(Return(-1));

        const auto pids { listAllPids(mockPrimitives) };
        EXPECT_TRUE(pids.empty());
    }
}
