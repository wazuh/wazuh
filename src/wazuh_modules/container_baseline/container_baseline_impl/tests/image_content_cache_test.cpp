#include "image_content_cache.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

using wazuh::container_baseline::FingerprintImageSources;
using wazuh::container_baseline::FingerprintImageSourcesAt;
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

    const auto found = cache.find("sha256:abc", "fp-1");

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

    const auto found = cache.find("sha256:abc", "fp-2");
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

/* --- cross-run lifetime and bounding -------------------------------------
 *
 * The cache now outlives a single scan, which is what makes it worth anything
 * to a delta-driven pass: that pass may scan one container, and caching by
 * image digest only pays when twenty replicas of an image parse its package
 * database once between them.
 *
 * Outliving the scan brings two problems that a per-run cache did not have —
 * unbounded growth on a node that pulls a new image every deploy, and readers
 * holding rows while another caller evicts them. Both are pinned here.
 */

TEST(ImageContentCache, RetainedEntriesAreBounded)
{
    ImageContentCache cache;

    // A node that deploys a new image tag every few minutes would otherwise
    // accumulate an entry per digest for the life of the process, each holding
    // every user, group and package row of an image.
    for (std::size_t i = 0; i < ImageContentCache::MAX_DIGESTS + 10; ++i)
    {
        ImageContentCache::Entry entry;
        entry.fingerprint = "fp";
        cache.store("sha256:" + std::to_string(i), std::move(entry));
    }

    EXPECT_LE(cache.size(), ImageContentCache::MAX_DIGESTS);
}

TEST(ImageContentCache, EvictionDropsTheLeastRecentlyUsedNotTheOldest)
{
    ImageContentCache cache;

    ImageContentCache::Entry first;
    first.fingerprint = "fp";
    cache.store("sha256:kept", std::move(first));

    // Keep using it while other digests arrive. An image that is still running
    // must stay resident however long ago it was first seen — evicting by
    // insertion order would throw out exactly the images being scanned.
    for (std::size_t i = 0; i < ImageContentCache::MAX_DIGESTS; ++i)
    {
        EXPECT_NE(nullptr, cache.find("sha256:kept", "fp")) << "evicted at i=" << i;

        ImageContentCache::Entry entry;
        entry.fingerprint = "fp";
        cache.store("sha256:filler-" + std::to_string(i), std::move(entry));
    }

    EXPECT_NE(nullptr, cache.find("sha256:kept", "fp"));
}

TEST(ImageContentCache, ABorrowedEntrySurvivesEvictionOfItsDigest)
{
    // A scan iterates these rows after looking them up. Evicting while it reads
    // would be a use-after-free, and the bound makes eviction routine rather
    // than exceptional — so a lookup has to keep what it returned alive.
    ImageContentCache cache;

    ImageContentCache::Entry entry;
    entry.fingerprint = "fp";
    entry.packages.resize(3);
    cache.store("sha256:doomed", std::move(entry));

    const auto borrowed = cache.find("sha256:doomed", "fp");
    ASSERT_NE(nullptr, borrowed);

    for (std::size_t i = 0; i < ImageContentCache::MAX_DIGESTS + 5; ++i)
    {
        ImageContentCache::Entry filler;
        filler.fingerprint = "fp";
        cache.store("sha256:evictor-" + std::to_string(i), std::move(filler));
    }

    // Gone from the cache...
    EXPECT_EQ(nullptr, cache.find("sha256:doomed", "fp"));
    // ...but still readable through the reference that was taken.
    EXPECT_EQ(3u, borrowed->packages.size());
}

TEST(ImageContentCache, TheSharedInstanceIsOneObject)
{
    // Two scans must meet the same cache or none of this pays off.
    EXPECT_EQ(&wazuh::container_baseline::SharedImageContentCache(),
              &wazuh::container_baseline::SharedImageContentCache());
}

/* --- what a triggered re-scan relies on ----------------------------------
 *
 * A re-scan triggered by a write to a source file arrives within seconds of
 * that write, so the fingerprint has to change for every write the scanners
 * would see. Timestamps are set explicitly, so neither the filesystem's
 * timestamp granularity nor a same-second write decides the outcome.
 */

namespace {

constexpr time_t kPast = 1000000000;

class TempRootfs
{
    public:
        TempRootfs()
        {
            char tmpl[] = "/tmp/cb_fingerprint_XXXXXX";
            m_path = ::mkdtemp(tmpl) ? tmpl : "";
        }
        ~TempRootfs()
        {
            std::error_code ec;
            std::filesystem::remove_all(m_path, ec);
        }
        TempRootfs(const TempRootfs&) = delete;
        TempRootfs& operator=(const TempRootfs&) = delete;

        std::string at(const std::string& rel) const { return m_path + "/" + rel; }

        void write(const std::string& rel, const std::string& content) const
        {
            std::filesystem::create_directories(std::filesystem::path(at(rel)).parent_path());
            std::ofstream(at(rel), std::ios::binary | std::ios::trunc) << content;
        }

        // Follows links, like the fingerprint.
        void setMtime(const std::string& rel, long nsec = 0) const
        {
            const struct timespec times[2] = {{kPast, nsec}, {kPast, nsec}};
            ASSERT_EQ(0, ::utimensat(AT_FDCWD, at(rel).c_str(), times, 0));
        }

        std::string fingerprint() const { return FingerprintImageSourcesAt(m_path); }

    private:
        std::string m_path;
};

constexpr auto kRpmDb  = "var/lib/rpm/rpmdb.sqlite";
constexpr auto kRpmWal = "var/lib/rpm/rpmdb.sqlite-wal";
constexpr auto kStatusDir = "var/lib/dpkg/status.d";

} // namespace

TEST(FingerprintImageSources, PidAndRootfsFormsAgree)
{
    EXPECT_EQ(FingerprintImageSources(::getpid()),
              FingerprintImageSourcesAt("/proc/" + std::to_string(::getpid()) + "/root"));
}

TEST(FingerprintImageSources, AnEmptyWalReadsAsNoWal)
{
    // Readers create the WAL, or copy it up, in each container; an empty one
    // holds nothing the database lacks.
    TempRootfs root;
    root.write(kRpmDb, "db");
    root.setMtime(kRpmDb);
    const auto before = root.fingerprint();

    root.write(kRpmWal, "");
    EXPECT_EQ(before, root.fingerprint());
}

TEST(FingerprintImageSources, CommittedRowsInTheWalChangeIt)
{
    TempRootfs root;
    root.write(kRpmDb, "db");
    root.write(kRpmWal, "");
    root.setMtime(kRpmDb);
    const auto before = root.fingerprint();

    root.write(kRpmWal, "frames");
    EXPECT_NE(before, root.fingerprint());

    // rpm's closing checkpoint truncates it. The database file is left alone
    // here, so the fingerprint returns to where it was.
    root.write(kRpmWal, "");
    EXPECT_EQ(before, root.fingerprint());
}

TEST(FingerprintImageSources, ReplicasWithTheSameWalAgree)
{
    // Different inodes, same size and mtime: the WAL contributes no inode, so
    // replicas of one image keep sharing a cache entry.
    TempRootfs a;
    TempRootfs b;

    for (const auto* root : {&a, &b})
    {
        root->write(kRpmWal, "frames");
        root->setMtime(kRpmWal);
    }
    EXPECT_EQ(a.fingerprint(), b.fingerprint());
}

TEST(FingerprintImageSources, AnInPlaceRewriteWithinTheSameSecondChangesIt)
{
    TempRootfs root;
    root.write(kRpmDb, "aaaa");
    root.setMtime(kRpmDb, 100);
    const auto before = root.fingerprint();

    root.write(kRpmDb, "bbbb");
    root.setMtime(kRpmDb, 200);
    EXPECT_NE(before, root.fingerprint());
}

TEST(FingerprintImageSources, StatusDirectoryEntriesAreFingerprinted)
{
    const std::string baseFiles = std::string(kStatusDir) + "/base-files";
    TempRootfs root;
    root.write(baseFiles, "a");
    root.setMtime(baseFiles);
    root.setMtime(kStatusDir);
    const auto before = root.fingerprint();

    // Rewritten in place: the directory itself does not change.
    root.write(baseFiles, "b");
    root.setMtime(kStatusDir);
    const auto rewritten = root.fingerprint();
    EXPECT_NE(before, rewritten);

    // Added, with the directory's mtime held still.
    root.write(std::string(kStatusDir) + "/tzdata", "c");
    root.setMtime(kStatusDir);
    EXPECT_NE(rewritten, root.fingerprint());
}

TEST(FingerprintImageSources, ASymlinkedSourceFollowsItsTarget)
{
    // The scanners read through the link, so the target is what counts.
    TempRootfs root;
    root.write("etc/os-release.real", "ID=a");
    std::filesystem::create_symlink("os-release.real", root.at("etc/os-release"));
    root.setMtime("etc/os-release.real", 100);
    const auto before = root.fingerprint();

    root.write("etc/os-release.real", "ID=b");
    root.setMtime("etc/os-release.real", 200);
    EXPECT_NE(before, root.fingerprint());
}
