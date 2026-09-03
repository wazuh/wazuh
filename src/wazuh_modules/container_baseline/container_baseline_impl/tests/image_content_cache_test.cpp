#include "image_content_cache.hpp"

#include <unistd.h>

#include <gtest/gtest.h>

using wazuh::container_baseline::FingerprintImageSources;
using wazuh::container_baseline::ImageContentCache;

namespace {

ImageContentCache::Entry MakeEntry(const std::string& fingerprint, const std::string& userName)
{
    ImageContentCache::Entry entry;
    entry.fingerprint = fingerprint;

    wazuh::container_baseline::UserBaselineRow user;
    user.name = userName;
    entry.users.push_back(std::move(user));

    return entry;
}

} // namespace

TEST(ImageContentCache, MissOnUnknownDigest)
{
    ImageContentCache cache;

    EXPECT_EQ(cache.find("sha256:abc", "fp"), nullptr);
    EXPECT_EQ(cache.misses(), 1U);
    EXPECT_EQ(cache.hits(), 0U);
}

TEST(ImageContentCache, HitWhenDigestAndFingerprintMatch)
{
    ImageContentCache cache;
    cache.store("sha256:abc", MakeEntry("fp-1", "root"));

    const auto* found = cache.find("sha256:abc", "fp-1");

    ASSERT_NE(found, nullptr);
    ASSERT_EQ(found->users.size(), 1U);
    EXPECT_EQ(found->users[0].name, "root");
    EXPECT_EQ(cache.hits(), 1U);
}

TEST(ImageContentCache, StaleFingerprintIsAMiss)
{
    // The case the fingerprint exists for: same image, but this container
    // modified one of the backing files in its own writable layer. Serving the
    // cached rows would report another container's accounts or packages.
    ImageContentCache cache;
    cache.store("sha256:abc", MakeEntry("fp-1", "root"));

    EXPECT_EQ(cache.find("sha256:abc", "fp-2"), nullptr);
    EXPECT_EQ(cache.misses(), 1U);
}

TEST(ImageContentCache, EmptyDigestIsNeverCached)
{
    // A container whose metadata never resolved has no digest to key on, so it
    // must always be scanned rather than sharing another image's rows.
    ImageContentCache cache;
    cache.store("", MakeEntry("fp-1", "root"));

    EXPECT_EQ(cache.find("", "fp-1"), nullptr);
}

TEST(ImageContentCache, StoreOverwritesPreviousEntryForTheSameDigest)
{
    ImageContentCache cache;
    cache.store("sha256:abc", MakeEntry("fp-1", "root"));
    cache.store("sha256:abc", MakeEntry("fp-2", "nobody"));

    EXPECT_EQ(cache.find("sha256:abc", "fp-1"), nullptr);

    const auto* found = cache.find("sha256:abc", "fp-2");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->users[0].name, "nobody");
}

TEST(ImageContentCache, DistinctDigestsDoNotShareEntries)
{
    ImageContentCache cache;
    cache.store("sha256:aaa", MakeEntry("fp", "alice"));
    cache.store("sha256:bbb", MakeEntry("fp", "bob"));

    ASSERT_NE(cache.find("sha256:aaa", "fp"), nullptr);
    ASSERT_NE(cache.find("sha256:bbb", "fp"), nullptr);
    EXPECT_EQ(cache.find("sha256:aaa", "fp")->users[0].name, "alice");
    EXPECT_EQ(cache.find("sha256:bbb", "fp")->users[0].name, "bob");
}

TEST(FingerprintImageSources, IsStableForTheSamePid)
{
    // Two reads with nothing changed in between must agree, or every container
    // would miss the cache every time and the dedup would be worthless.
    const auto first = FingerprintImageSources(::getpid());
    const auto second = FingerprintImageSources(::getpid());

    EXPECT_FALSE(first.empty());
    EXPECT_EQ(first, second);
}

TEST(FingerprintImageSources, UnreadableRootfsStillYieldsAFingerprint)
{
    // PID 0 has no /proc entry, so every probe is absent. The result must be a
    // well-formed "everything absent" fingerprint rather than an empty string,
    // so it cannot accidentally compare equal to a real one.
    const auto absent = FingerprintImageSources(0);

    EXPECT_FALSE(absent.empty());
    EXPECT_NE(absent, FingerprintImageSources(::getpid()));
}
