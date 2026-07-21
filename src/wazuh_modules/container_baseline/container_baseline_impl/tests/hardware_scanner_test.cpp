#include "hardware_scanner.hpp"

#include <gtest/gtest.h>

using wazuh::container_baseline::CoresFromCpuMax;
using wazuh::container_baseline::ParseCgroupBytes;

TEST(CoresFromCpuMax, HalfCoreRoundsUpToOne)
{
    EXPECT_EQ(CoresFromCpuMax("50000 100000"), 1);
}

TEST(CoresFromCpuMax, OneAndHalfCoresRoundsUpToTwo)
{
    EXPECT_EQ(CoresFromCpuMax("150000 100000"), 2);
}

TEST(CoresFromCpuMax, WholeCores)
{
    EXPECT_EQ(CoresFromCpuMax("200000 100000"), 2);
    EXPECT_EQ(CoresFromCpuMax("100000 100000"), 1);
}

TEST(CoresFromCpuMax, UnlimitedIsZero)
{
    EXPECT_EQ(CoresFromCpuMax("max 100000"), 0);
}

TEST(ParseCgroupBytes, ParsesByteCount)
{
    EXPECT_EQ(ParseCgroupBytes("536870912"), 536870912);
}

TEST(ParseCgroupBytes, MaxIsZero)
{
    EXPECT_EQ(ParseCgroupBytes("max"), 0);
    EXPECT_EQ(ParseCgroupBytes(""), 0);
}
