#include "id_map.hpp"

#include <unistd.h>

#include <gtest/gtest.h>

using wazuh::container_baseline::IdMap;

TEST(IdMap, DefaultIsIdentity)
{
    const IdMap map;

    EXPECT_TRUE(map.isIdentity());
    EXPECT_EQ(map.toContainer(0), 0U);
    EXPECT_EQ(map.toContainer(1000), 1000U);
    EXPECT_EQ(map.toContainer(4294967294U), 4294967294U);
}

TEST(IdMap, FullRangeIdentityLineCollapsesToIdentity)
{
    // What a container WITHOUT a user namespace reports.
    const auto map = IdMap::Parse("         0          0 4294967295\n");

    EXPECT_TRUE(map.isIdentity());
    EXPECT_EQ(map.toContainer(0), 0U);
    EXPECT_EQ(map.toContainer(100000), 100000U);
}

TEST(IdMap, TranslatesARemappedRange)
{
    // The common rootless/userns layout: container uid 0 is host uid 100000,
    // for 65536 ids. This is the case that made file ownership disagree with
    // the container's own /etc/passwd.
    const auto map = IdMap::Parse("0 100000 65536\n");

    EXPECT_FALSE(map.isIdentity());
    EXPECT_EQ(map.toContainer(100000), 0U);      // host root-of-container -> container root
    EXPECT_EQ(map.toContainer(100001), 1U);
    EXPECT_EQ(map.toContainer(101000), 1000U);
    EXPECT_EQ(map.toContainer(165535), 65535U);  // last id in range
}

TEST(IdMap, IdOutsideEveryRangeIsPassedThrough)
{
    const auto map = IdMap::Parse("0 100000 65536\n");

    // 165536 is one past the range; there is no meaningful in-namespace id, so
    // the host value is kept rather than fabricating a translation.
    EXPECT_EQ(map.toContainer(165536), 165536U);
    EXPECT_EQ(map.toContainer(0), 0U);
}

TEST(IdMap, HandlesMultipleRanges)
{
    const auto map = IdMap::Parse("0 100000 1\n"
                                  "1 200000 10\n");

    EXPECT_EQ(map.toContainer(100000), 0U);
    EXPECT_EQ(map.toContainer(200000), 1U);
    EXPECT_EQ(map.toContainer(200009), 10U);
    EXPECT_EQ(map.toContainer(200010), 200010U); // past the second range
}

TEST(IdMap, IgnoresMalformedAndZeroLengthLines)
{
    const auto map = IdMap::Parse("not a mapping\n"
                                  "0 100000 0\n"      // zero length
                                  "1 2\n"             // too few fields
                                  "0 100000 65536\n");

    EXPECT_EQ(map.toContainer(100000), 0U);
}

TEST(IdMap, EmptyContentsIsIdentity)
{
    const auto map = IdMap::Parse("");

    EXPECT_TRUE(map.isIdentity());
    EXPECT_EQ(map.toContainer(1234), 1234U);
}

TEST(IdMap, UnreadableProcFileDegradesToIdentity)
{
    // A failure to read the map must leave ids untouched rather than
    // translating them wrongly.
    const auto map = IdMap::FromProc(0, "uid_map");

    EXPECT_TRUE(map.isIdentity());
    EXPECT_EQ(map.toContainer(4242), 4242U);
}

TEST(IdMap, SelfIsIdentityOnANonRemappedHost)
{
    // The test process is not userns-remapped, so its own map must translate
    // to itself — this is the path every non-userns container takes.
    const auto map = IdMap::FromProc(::getpid(), "uid_map");

    EXPECT_EQ(map.toContainer(::getuid()), static_cast<uint32_t>(::getuid()));
}
