/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "proc.hpp"
#include <gtest/gtest.h>

TEST(ProcTest, coresFromQuotaNoLimit)
{
    // Negative quota (cgroups v1 "-1") or zero means "no limit".
    EXPECT_EQ(0u, proc_detail::coresFromQuota(-1, 100000));
    EXPECT_EQ(0u, proc_detail::coresFromQuota(0, 100000));
}

TEST(ProcTest, coresFromQuotaInvalidPeriod)
{
    EXPECT_EQ(0u, proc_detail::coresFromQuota(100000, 0));
    EXPECT_EQ(0u, proc_detail::coresFromQuota(100000, -1));
}

TEST(ProcTest, coresFromQuotaFractionalRoundsUpToOne)
{
    // 500m -> 0.5 cores -> ceil -> 1
    EXPECT_EQ(1u, proc_detail::coresFromQuota(50000, 100000));
}

TEST(ProcTest, coresFromQuotaExact)
{
    EXPECT_EQ(2u, proc_detail::coresFromQuota(200000, 100000));
    EXPECT_EQ(4u, proc_detail::coresFromQuota(400000, 100000));
}

TEST(ProcTest, coresFromQuotaRoundsUp)
{
    // 1.5 cores -> ceil -> 2
    EXPECT_EQ(2u, proc_detail::coresFromQuota(150000, 100000));
    // 2.01 cores -> ceil -> 3
    EXPECT_EQ(3u, proc_detail::coresFromQuota(201000, 100000));
}

TEST(ProcTest, parseCpuMaxV2NoLimit)
{
    EXPECT_EQ(0u, proc_detail::parseCpuMaxV2("max 100000"));
}

TEST(ProcTest, parseCpuMaxV2WithLimit)
{
    EXPECT_EQ(1u, proc_detail::parseCpuMaxV2("50000 100000"));
    EXPECT_EQ(2u, proc_detail::parseCpuMaxV2("200000 100000"));
    EXPECT_EQ(2u, proc_detail::parseCpuMaxV2("150000 100000"));
}

TEST(ProcTest, parseCpuMaxV2Malformed)
{
    EXPECT_EQ(0u, proc_detail::parseCpuMaxV2(""));
    EXPECT_EQ(0u, proc_detail::parseCpuMaxV2("garbage"));
    EXPECT_EQ(0u, proc_detail::parseCpuMaxV2("abc 100000"));
}

TEST(ProcTest, getNprocAtLeastOne)
{
    EXPECT_GE(cpp_get_nproc(), 1u);
}
