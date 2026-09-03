#include "container_images_config.hpp"
#include "container_images_db.hpp"
#include "container_images_impl.hpp"
#include "archive_image_reader.hpp"
#include "image_fixtures.hpp"
#include "ci_logging_helper.hpp"

#include "dbsync.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <thread>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

using namespace containerimages;

namespace
{
    /// @brief Unique name for a temporary directory, so concurrent test runs never collide.
    std::string uniqueName()
    {
        static std::atomic<unsigned> counter {0};
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return "container_images_test_" + std::to_string(now) + "_" + std::to_string(counter++);
    }

    /// @brief Builds a minimal OCI layout on disk for the reader tests.
    class OciLayoutFixture
    {
        public:
            OciLayoutFixture()
                : m_root {std::filesystem::temp_directory_path() / uniqueName()}
            {
                std::filesystem::remove_all(m_root);
                std::filesystem::create_directories(m_root / "blobs" / "sha256");
            }

            ~OciLayoutFixture()
            {
                std::filesystem::remove_all(m_root);
            }

            std::string path() const
            {
                return m_root.string();
            }

            std::filesystem::path blobPath(const std::string& digest) const
            {
                return m_root / "blobs" / "sha256" / digest;
            }

            void writeMarker()
            {
                writeFile(m_root / "oci-layout", R"({"imageLayoutVersion":"1.0.0"})");
            }

            void writeBlob(const std::string& digest, const std::string& content)
            {
                writeFile(blobPath(digest), content);
            }

            void writeIndex(const std::string& content)
            {
                writeFile(m_root / "index.json", content);
            }

        private:
            static void writeFile(const std::filesystem::path& path, const std::string& content)
            {
                std::ofstream stream(path);
                stream << content;
            }

            std::filesystem::path m_root;
    };

    void setNullLogger()
    {
        LoggingHelper::setLogCallback([](const modules_log_level_t, const char*) {});
    }

    const std::string CONFIG_DIGEST {"configdigest1111111111111111111111111111111111111111111111111111"};
    const std::string MANIFEST_DIGEST {"manifestdigest11111111111111111111111111111111111111111111111111"};

    /// @brief Writes a complete single-image layout and returns its root path.
    std::unique_ptr<OciLayoutFixture> buildSingleImageLayout()
    {
        auto fixture = std::make_unique<OciLayoutFixture>();
        fixture->writeMarker();

        fixture->writeBlob(CONFIG_DIGEST,
                           R"({"os":"linux","architecture":"amd64","variant":"v8","os.version":""})");
        fixture->writeBlob(MANIFEST_DIGEST,
                           R"({"config":{"digest":"sha256:)" + CONFIG_DIGEST + R"("}})");
        fixture->writeIndex(R"({"manifests":[{"digest":"sha256:)" + MANIFEST_DIGEST +
                            R"(","annotations":{"org.opencontainers.image.ref.name":"alpine:latest"}}]})");

        return fixture;
    }

    /// @brief Writes a single-image layout whose layer carries a dpkg database.
    std::unique_ptr<OciLayoutFixture> buildSingleImageLayoutWithPackages()
    {
        const std::string LAYER_DIGEST {"layerdigest111111111111111111111111111111111111111111111111111111"};

        auto fixture = std::make_unique<OciLayoutFixture>();
        fixture->writeMarker();

        fixture->writeBlob(CONFIG_DIGEST, R"({"os":"linux","architecture":"amd64"})");
        fixture->writeBlob(LAYER_DIGEST,
                           imagefixtures::gzip(imagefixtures::tarMember("var/lib/dpkg/status",
                                                                        imagefixtures::dpkgStanza("curl", "7.88.1-10")) +
                                               imagefixtures::tarEnd()));
        fixture->writeBlob(MANIFEST_DIGEST,
                           R"({"config":{"digest":"sha256:)" + CONFIG_DIGEST +
                           R"("},"layers":[{"digest":"sha256:)" + LAYER_DIGEST + R"("}]})");
        fixture->writeIndex(R"({"manifests":[{"digest":"sha256:)" + MANIFEST_DIGEST + R"("}]})");

        return fixture;
    }

    /// @brief Writes a layout whose index holds the given raw `manifests` array.
    std::unique_ptr<OciLayoutFixture> buildLayoutWithIndex(const std::string& index)
    {
        auto fixture = std::make_unique<OciLayoutFixture>();
        fixture->writeMarker();
        fixture->writeIndex(index);

        return fixture;
    }
} // namespace

class ContainerImagesTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            setNullLogger();
        }
};

TEST_F(ContainerImagesTest, ArchiveReaderSourceType)
{
    ArchiveImageReader reader("");
    EXPECT_EQ(reader.sourceType(), "archive");
}

TEST_F(ContainerImagesTest, ArchiveReaderEmptyPathReturnsNothing)
{
    ArchiveImageReader reader("");
    EXPECT_TRUE(reader.discover().records.empty());
}

TEST_F(ContainerImagesTest, ArchiveReaderMissingLayoutReturnsNothing)
{
    ArchiveImageReader reader("/nonexistent/path/to/layout");
    EXPECT_TRUE(reader.discover().records.empty());
}

TEST_F(ContainerImagesTest, ArchiveReaderReadsSingleReference)
{
    const auto fixture = buildSingleImageLayout();

    ArchiveImageReader reader(fixture->path());
    const auto references = reader.discover().records;

    ASSERT_EQ(references.size(), 1U);

    const auto& reference = references.front();
    EXPECT_EQ(reference.configDigest, "sha256:configdigest1111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(reference.os, "linux");
    EXPECT_EQ(reference.architecture, "amd64");
    EXPECT_EQ(reference.variant, "v8");
    EXPECT_EQ(reference.tag, "alpine:latest");
    EXPECT_EQ(reference.source.sourceType, "archive");
    EXPECT_EQ(reference.source.location, fixture->path());
}

TEST_F(ContainerImagesTest, ArchiveReaderUnknownFormatReturnsNothing)
{
    // A directory that exists but holds no recognizable layout.
    const auto dir = std::filesystem::temp_directory_path() / (uniqueName() + "_unknown_fmt");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    ArchiveImageReader reader(dir.string());
    EXPECT_TRUE(reader.discover().records.empty());

    std::filesystem::remove_all(dir);
}

TEST_F(ContainerImagesTest, ArchiveReaderContainerdStoreNotImplemented)
{
    // The containerd content store is read through the container engine, which is the
    // `<local>` reference type and a follow-up issue.
    const auto dir = std::filesystem::temp_directory_path() / (uniqueName() + "_containerd");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir / "io.containerd.content.v1.content");

    ArchiveImageReader reader(dir.string());
    EXPECT_TRUE(reader.discover().records.empty());

    std::filesystem::remove_all(dir);
}

TEST_F(ContainerImagesTest, ArchiveReaderRejectsTraversalDigest)
{
    // A digest that escapes the layout directory must never reach the filesystem.
    const auto fixture = buildLayoutWithIndex(R"({"manifests":[{"digest":"sha256:../../../../etc/hostname"}]})");

    ArchiveImageReader reader(fixture->path());
    EXPECT_TRUE(reader.discover().records.empty());
}

TEST_F(ContainerImagesTest, ArchiveReaderRejectsDriveRelativeDigest)
{
    // "C:foo" splits at the first colon and passes a separator blacklist, but on
    // Windows operator/ would replace the layout path with a drive-relative one.
    const auto fixture = buildLayoutWithIndex(R"({"manifests":[{"digest":"sha256:C:foo"}]})");

    ArchiveImageReader reader(fixture->path());
    EXPECT_TRUE(reader.discover().records.empty());
}

TEST_F(ContainerImagesTest, ArchiveReaderNonObjectManifestEntryIsSkipped)
{
    const auto fixture = buildLayoutWithIndex(R"({"manifests":["oops"]})");

    ArchiveImageReader reader(fixture->path());
    EXPECT_NO_THROW(EXPECT_TRUE(reader.discover().records.empty()));
}

TEST_F(ContainerImagesTest, ArchiveReaderNonStringDigestIsSkipped)
{
    const auto fixture = buildLayoutWithIndex(R"({"manifests":[{"digest":123}]})");

    ArchiveImageReader reader(fixture->path());
    EXPECT_NO_THROW(EXPECT_TRUE(reader.discover().records.empty()));
}

TEST_F(ContainerImagesTest, ArchiveReaderNonObjectManifestConfigIsSkipped)
{
    const auto fixture = buildSingleImageLayout();
    fixture->writeBlob(MANIFEST_DIGEST, R"({"config":"x"})");

    ArchiveImageReader reader(fixture->path());
    EXPECT_NO_THROW(EXPECT_TRUE(reader.discover().records.empty()));
}

TEST_F(ContainerImagesTest, ArchiveReaderUnparseableConfigBlobKeepsReferenceWithoutMetadata)
{
    // The image reference is still known from the manifest, so it is reported; only
    // the platform metadata is missing. What must not happen is an exception.
    const auto fixture = buildSingleImageLayout();
    fixture->writeBlob(CONFIG_DIGEST, "{not json");

    ArchiveImageReader reader(fixture->path());

    std::vector<ImageReferenceRecord> references;
    ASSERT_NO_THROW(references = reader.discover().records);
    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().os.empty());
    EXPECT_TRUE(references.front().architecture.empty());
}

TEST_F(ContainerImagesTest, ArchiveReaderWrongTypedConfigFieldIsIgnored)
{
    const auto fixture = buildSingleImageLayout();
    fixture->writeBlob(CONFIG_DIGEST, R"({"os":5,"architecture":"amd64"})");

    ArchiveImageReader reader(fixture->path());

    std::vector<ImageReferenceRecord> references;
    ASSERT_NO_THROW(references = reader.discover().records);
    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().os.empty());
    EXPECT_EQ(references.front().architecture, "amd64");
}

#ifndef _WIN32
TEST_F(ContainerImagesTest, ArchiveReaderSkipsNonRegularBlob)
{
    // Opening a FIFO with no writer blocks forever, which would hang the module
    // thread past the point where a stop can reach it.
    const auto fixture = buildSingleImageLayout();
    const auto fifo = fixture->blobPath(MANIFEST_DIGEST);

    std::filesystem::remove(fifo);

    if (mkfifo(fifo.string().c_str(), 0600) != 0)
    {
        GTEST_SKIP() << "FIFOs are not available on this filesystem.";
    }

    ArchiveImageReader reader(fixture->path());
    EXPECT_TRUE(reader.discover().records.empty());
}
#endif

TEST_F(ContainerImagesTest, ArchiveReaderKeepsOnlyOneImageOfAMultiManifestIndex)
{
    // Two full images, such as `docker save debian:12 ubuntu:24.04` produces, not a
    // multi-platform variant of one. The references table's primary key is
    // (reference_type, reference_value): one row per reference, so more than one
    // descriptor for the same location must not become more than one record.
    const std::string CONFIG_DIGEST_2 {"configdigest2222222222222222222222222222222222222222222222222222"};
    const std::string MANIFEST_DIGEST_2 {"manifestdigest22222222222222222222222222222222222222222222222222"};

    auto fixture = buildSingleImageLayout();
    fixture->writeBlob(CONFIG_DIGEST_2, R"({"os":"linux","architecture":"arm64"})");
    fixture->writeBlob(MANIFEST_DIGEST_2, R"({"config":{"digest":"sha256:)" + CONFIG_DIGEST_2 + R"("}})");
    fixture->writeIndex(R"({"manifests":[)"
                        R"({"digest":"sha256:)" + MANIFEST_DIGEST +
                        R"(","annotations":{"org.opencontainers.image.ref.name":"debian:12"}},)" +
                        R"({"digest":"sha256:)" + MANIFEST_DIGEST_2 +
                        R"(","annotations":{"org.opencontainers.image.ref.name":"ubuntu:24.04"}}]})");

    ArchiveImageReader reader(fixture->path());
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().tag, "debian:12");
}

TEST_F(ContainerImagesTest, ArchiveReaderSkipsAttestationManifestEntries)
{
    // buildx and containerd both write "unknown"/"unknown" as the platform of an
    // attestation or provenance manifest entry; it carries no image content and must
    // not compete with the real image for the one reference row this location can hold.
    const std::string ATTESTATION_CONFIG_DIGEST {"attestationconfig111111111111111111111111111111111111111111111"};
    const std::string ATTESTATION_MANIFEST_DIGEST {"attestationmanifest11111111111111111111111111111111111111111111"};

    auto fixture = buildSingleImageLayout();
    fixture->writeBlob(ATTESTATION_CONFIG_DIGEST, R"({"os":"unknown","architecture":"unknown"})");
    fixture->writeBlob(ATTESTATION_MANIFEST_DIGEST,
                       R"({"config":{"digest":"sha256:)" + ATTESTATION_CONFIG_DIGEST + R"("}})");
    fixture->writeIndex(R"({"manifests":[)"
                        R"({"digest":"sha256:)" + MANIFEST_DIGEST +
                        R"(","annotations":{"org.opencontainers.image.ref.name":"alpine:latest"}},)" +
                        R"({"digest":"sha256:)" + ATTESTATION_MANIFEST_DIGEST +
                        R"(","platform":{"os":"unknown","architecture":"unknown"}}]})");

    ArchiveImageReader reader(fixture->path());
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().tag, "alpine:latest");
}

TEST_F(ContainerImagesTest, ArchiveReaderBoundsAFanOutIndexInsteadOfRunningForSeconds)
{
    // A self-referencing index with fan-out N is walked N^5 times without a shared
    // visited-digest set and a total node budget: MAX_INDEX_DEPTH alone bounds nesting,
    // not fan-out. The review measured N=12 at ~4.1s on a real harness; this uses a
    // slightly higher N so an unfixed traversal would run for several seconds, while
    // the fix keeps it near-instant regardless of N (every distinct digest here is
    // visited once, thanks to the shared visited set). A wall-clock ceiling is the only
    // externally observable signal for a bug that is fundamentally about unbounded
    // work, which is how the review itself measured it; the margin between "fixed"
    // (tens of milliseconds) and "unfixed" (several seconds) is large enough not to
    // flake on a loaded CI machine.
    constexpr int FAN_OUT {14};

    auto fixture = std::make_unique<OciLayoutFixture>();
    fixture->writeMarker();

    std::vector<std::string> digests;

    for (int i = 0; i < FAN_OUT; ++i)
    {
        digests.push_back("cyclenode" + std::to_string(i) + std::string(40, '0'));
    }

    std::string manifestsArray;

    for (const auto& digest : digests)
    {
        manifestsArray += manifestsArray.empty() ? "" : ",";
        manifestsArray += R"({"digest":"sha256:)" + digest + R"("})";
    }

    const std::string nodeBody {R"({"manifests":[)" + manifestsArray + R"(]})"};

    for (const auto& digest : digests)
    {
        fixture->writeBlob(digest, nodeBody);
    }

    fixture->writeIndex(nodeBody);

    ArchiveImageReader reader(fixture->path());

    const auto start {std::chrono::steady_clock::now()};
    const auto references {reader.discover().records};
    const auto elapsed {std::chrono::steady_clock::now() - start};

    EXPECT_LT(elapsed, std::chrono::seconds(5));
    // Every node here is a nested index pointing at other nested indexes, never a real
    // manifest with a config digest, so no reference is ever produced either way; the
    // bound under test is the elapsed time, not this.
    EXPECT_TRUE(references.empty());
}

// ---------------------------------------------------------------------------
// Persistence layer (ContainerImagesDB) — DBSync round trip and deltas.
// ---------------------------------------------------------------------------

namespace
{
    /// @brief Builds a reference carrying the given packages, for the DB tests.
    ImageReferenceRecord makeReference(const std::string& value, std::vector<ImagePackageRecord> packages)
    {
        ImageReferenceRecord reference;
        reference.source = {"local", value};
        reference.tag = "latest";
        reference.configDigest = "sha256:cfg-" + value;
        reference.os = "linux";
        reference.architecture = "amd64";
        reference.packages = std::move(packages);
        return reference;
    }

    ImagePackageRecord makePackage(const std::string& name, const std::string& version)
    {
        ImagePackageRecord package;
        package.name = name;
        package.version = version;
        package.architecture = "amd64";
        package.type = "deb";
        return package;
    }

    /// @brief Tally of delta operations seen, keyed by table.
    struct DeltaTally
    {
        int created {0};
        int modified {0};
        int deleted {0};

        containerimages::DeltaCallback callback()
        {
            return [this](ReturnTypeCallback op, const std::string&, const std::string&, const std::string&, std::uint64_t)
            {
                if (op == INSERTED) ++created;
                else if (op == MODIFIED) ++modified;
                else if (op == DELETED) ++deleted;
            };
        }
    };

    std::string tempDbPath()
    {
        return (std::filesystem::temp_directory_path() /
                ("ci_db_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".db"))
               .string();
    }

    /// @brief Reads @p columns back from @p table of an existing database.
    ///
    /// Opening the file again at the same schema version reuses it, so this reads exactly
    /// what the module stored. Selecting a column the CREATE statement does not define
    /// makes DBSync throw, which is what pins the created schema.
    std::vector<std::map<std::string, std::string>> storedRows(const std::string& dbPath,
                                                               const std::string& table,
                                                               const std::vector<std::string>& columns)
    {
        DBSync db {HostType::AGENT,
                   DbEngineType::SQLITE3,
                   dbPath,
                   ContainerImagesDB::getCreateStatement(),
                   DbManagement::PERSISTENT,
                   ContainerImagesDB::getUpgradeStatements()};

        std::vector<std::map<std::string, std::string>> rows;

        const auto callback = [&rows](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (result != SELECTED)
            {
                return;
            }

            std::map<std::string, std::string> row;

            for (const auto& field : data.items())
            {
                row[field.key()] = field.value().is_string()
                                   ? field.value().get<std::string>()
                                   : field.value().dump();
            }

            rows.push_back(std::move(row));
        };

        auto query = SelectQuery::builder().table(table).columnList(columns).build();
        db.selectRows(query.query(), callback);

        return rows;
    }
}

class ContainerImagesDBTest : public ContainerImagesTest
{
    protected:
        void SetUp() override
        {
            ContainerImagesTest::SetUp();
            DBSync::initialize([](const std::string&) {});
            m_dbPath = tempDbPath();
        }

        void TearDown() override
        {
            std::filesystem::remove(m_dbPath);
        }

        std::string m_dbPath;
};

TEST_F(ContainerImagesDBTest, StoredTagsAreRecoveredByLoadStored)
{
    // Regression test. loadStored() brace-initialized the parsed json, which selected
    // nlohmann's initializer-list constructor: ["1.4","latest"] was read as a key and a
    // value and became the object {"1.4":"latest"}, so is_array() was false and every
    // stored tag was dropped. Nothing covered the tag round trip, which is why it shipped.
    ContainerImagesDB db(m_dbPath);

    auto reference {makeReference("debian:12", {makePackage("apt", "2.6.1")})};
    reference.tags = {"12", "12.4", "latest"};

    DeltaTally tally;
    db.syncReferences({reference}, tally.callback());

    const auto stored {db.loadStored("local", "debian:12")};

    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->tags, std::vector<std::string>({"12", "12.4", "latest"}));
}

TEST_F(ContainerImagesDBTest, ASingleStoredTagIsRecovered)
{
    // A one-element array took a different wrong path than a two-element one: it was
    // wrapped into a nested array rather than turned into an object. Both are covered.
    ContainerImagesDB db(m_dbPath);

    auto reference {makeReference("debian:12", {makePackage("apt", "2.6.1")})};
    reference.tags = {"only"};

    DeltaTally tally;
    db.syncReferences({reference}, tally.callback());

    const auto stored {db.loadStored("local", "debian:12")};

    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->tags, std::vector<std::string>({"only"}));
}

TEST_F(ContainerImagesDBTest, AReferenceWithNoTagsRoundTripsAsEmpty)
{
    ContainerImagesDB db(m_dbPath);

    const auto reference {makeReference("debian:12", {makePackage("apt", "2.6.1")})};

    DeltaTally tally;
    db.syncReferences({reference}, tally.callback());

    const auto stored {db.loadStored("local", "debian:12")};

    ASSERT_TRUE(stored.has_value());
    EXPECT_TRUE(stored->tags.empty());
}

TEST_F(ContainerImagesDBTest, ReSyncingAStoredRecordDoesNotDropItsTags)
{
    // The consequence the defect actually had. An unchanged or unreadable reference is
    // handed back to storage as whatever loadStored() returned, so an empty tag list
    // overwrote the column and emitted a MODIFIED delta for a change that never
    // happened. With the digest short-circuit, that was every rescan of every image.
    ContainerImagesDB db(m_dbPath);

    auto reference {makeReference("debian:12", {makePackage("apt", "2.6.1")})};
    reference.tags = {"12", "latest"};

    DeltaTally first;
    db.syncReferences({reference}, first.callback());
    ASSERT_EQ(first.created, 1);

    const auto stored {db.loadStored("local", "debian:12")};
    ASSERT_TRUE(stored.has_value());

    DeltaTally second;
    db.syncReferences({*stored}, second.callback());

    EXPECT_EQ(second.modified, 0);
    EXPECT_EQ(second.deleted, 0);

    const auto reloaded {db.loadStored("local", "debian:12")};
    ASSERT_TRUE(reloaded.has_value());
    EXPECT_EQ(reloaded->tags, std::vector<std::string>({"12", "latest"}));
}

TEST_F(ContainerImagesDBTest, FirstSyncReportsAllRowsAsCreated)
{
    ContainerImagesDB db(m_dbPath);

    const std::vector<ImageReferenceRecord> references {
        makeReference("debian:12", {makePackage("apt", "2.6.1"), makePackage("curl", "7.88.1")})};

    DeltaTally references_tally;
    DeltaTally packages_tally;

    db.syncReferences(references, references_tally.callback());
    db.syncPackages(references, packages_tally.callback());

    EXPECT_EQ(references_tally.created, 1);
    EXPECT_EQ(packages_tally.created, 2);
}

TEST_F(ContainerImagesDBTest, UnchangedSecondSyncReportsNoDeltas)
{
    ContainerImagesDB db(m_dbPath);

    const std::vector<ImageReferenceRecord> references {
        makeReference("debian:12", {makePackage("apt", "2.6.1")})};

    DeltaTally first;
    db.syncReferences(references, first.callback());
    db.syncPackages(references, first.callback());

    DeltaTally second;
    db.syncReferences(references, second.callback());
    db.syncPackages(references, second.callback());

    EXPECT_EQ(second.created, 0);
    EXPECT_EQ(second.modified, 0);
    EXPECT_EQ(second.deleted, 0);
}

TEST_F(ContainerImagesDBTest, PackageVersionChangeReportsDeleteAndCreate)
{
    ContainerImagesDB db(m_dbPath);

    DeltaTally first;
    db.syncPackages({makeReference("debian:12", {makePackage("base-files", "12.4u10")})}, first.callback());

    DeltaTally second;
    db.syncPackages({makeReference("debian:12", {makePackage("base-files", "12.4u11")})}, second.callback());

    // A different version is a different primary key: the old row is deleted and the new
    // one created. (version_ is part of the package identity.)
    EXPECT_EQ(second.created, 1);
    EXPECT_EQ(second.deleted, 1);
}

TEST_F(ContainerImagesDBTest, AddedAndRemovedPackagesReportCreateAndDelete)
{
    ContainerImagesDB db(m_dbPath);

    db.syncPackages({makeReference("debian:12", {makePackage("apt", "2.6.1"), makePackage("perl", "5.36")})},
                    DeltaTally().callback());

    DeltaTally second;
    db.syncPackages({makeReference("debian:12", {makePackage("apt", "2.6.1"), makePackage("curl", "7.88")})},
                    second.callback());

    EXPECT_EQ(second.created, 1); // curl added
    EXPECT_EQ(second.deleted, 1); // perl removed
    EXPECT_EQ(second.modified, 0);
}

TEST_F(ContainerImagesDBTest, AttributeChangeReportsModified)
{
    ContainerImagesDB db(m_dbPath);

    auto withSize = [](long long size)
    {
        auto package = makePackage("apt", "2.6.1");
        package.size = size;
        return std::vector<ImageReferenceRecord> {makeReference("debian:12", {package})};
    };

    db.syncPackages(withSize(100), DeltaTally().callback());

    DeltaTally second;
    db.syncPackages(withSize(200), second.callback()); // same PK, different attribute

    EXPECT_EQ(second.modified, 1);
    EXPECT_EQ(second.created, 0);
    EXPECT_EQ(second.deleted, 0);
}

TEST_F(ContainerImagesDBTest, DeltaCarriesTheStoredDocumentVersion)
{
    // The version is what lets the manager order and deduplicate documents once the
    // synchronization layer attaches to this callback. DBSync stores it as a signed
    // integer, so a guard that only accepts an unsigned one reports 0 for every row.
    ContainerImagesDB db(m_dbPath);

    std::vector<std::uint64_t> versions;

    const auto capture = [&versions](ReturnTypeCallback, const std::string&, const std::string&,
                                     const std::string&, std::uint64_t version)
    {
        versions.push_back(version);
    };

    auto withSize = [](long long size)
    {
        auto package = makePackage("apt", "2.6.1");
        package.size = size;
        return std::vector<ImageReferenceRecord> {makeReference("debian:12", {package})};
    };

    db.syncPackages(withSize(100), capture); // create
    ASSERT_EQ(versions.size(), 1U);
    EXPECT_EQ(versions.front(), 1U);

    versions.clear();

    db.syncPackages(withSize(200), capture); // modify, same primary key
    ASSERT_EQ(versions.size(), 1U);
    EXPECT_EQ(versions.front(), 2U);
}

// ---------------------------------------------------------------------------
// Orchestrator — scanOnce reads the configured sources and stores what it finds.
// ---------------------------------------------------------------------------
//
// Every case here injects the temporary database, so no test writes under the agent
// installation path.

TEST_F(ContainerImagesDBTest, ImplScanOnceReturnsReferenceCount)
{
    const auto fixture = buildSingleImageLayout();

    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, fixture->path()}};

    ContainerImagesImpl impl(config, makeReader, std::make_shared<ContainerImagesDB>(m_dbPath));
    EXPECT_EQ(impl.scanOnce(), 1U);
}

TEST_F(ContainerImagesDBTest, ImplScanOnceAggregatesMultipleSources)
{
    const auto first = buildSingleImageLayout();
    const auto second = buildSingleImageLayout();

    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, first->path()}, {ReferenceType::Archive, second->path()}};

    ContainerImagesImpl impl(config, makeReader, std::make_shared<ContainerImagesDB>(m_dbPath));
    EXPECT_EQ(impl.scanOnce(), 2U);
}

TEST_F(ContainerImagesDBTest, ImplNoSourcesScansNothing)
{
    ContainerImagesConfig config; // no references

    int factoryCalls = 0;
    ContainerImagesImpl impl(config, [&factoryCalls](const ConfiguredReference&, const std::string&, const ReaderContext&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    }, std::make_shared<ContainerImagesDB>(m_dbPath));

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_EQ(factoryCalls, 0);
}

namespace
{
    /// @brief A reader whose outcome each test sets.
    class OutcomeReader final : public IImageReader
    {
        public:
            OutcomeReader(ImageReadResult result) : m_result {std::move(result)} {}

            ImageReadResult discover() override
            {
                return m_result;
            }

            std::string sourceType() const override
            {
                return "archive";
            }

        private:
            ImageReadResult m_result;
    };

    /// @brief One reference with @p packages packages, found at @p location.
    ImageReferenceRecord recordAt(const std::string& location, int packages)
    {
        ImageReferenceRecord reference;
        reference.source = {"archive", location};
        reference.tag = "debian:12";
        reference.configDigest = "sha256:config-aaaa";
        reference.manifestDigest = "sha256:manifest-aaaa";
        reference.os = "linux";
        reference.architecture = "amd64";

        for (int i = 0; i < packages; ++i)
        {
            ImagePackageRecord package;
            package.name = "pkg-" + std::to_string(i);
            package.version = "1.0";
            package.architecture = "amd64";
            package.type = "deb";
            package.packageDbPath = "var/lib/dpkg/status";
            reference.packages.push_back(std::move(package));
        }

        return reference;
    }

    std::size_t storedPackages(const std::string& dbPath)
    {
        return storedRows(dbPath, PACKAGES_TABLE, {"name", "version_"}).size();
    }

    std::size_t storedReferences(const std::string& dbPath)
    {
        return storedRows(dbPath, REFERENCES_TABLE, {"reference_type", "reference_value"}).size();
    }
} // namespace

TEST_F(ContainerImagesDBTest, AFailedReadKeepsTheInventoryAlreadyStored)
{
    // A reference that cannot be read this time says nothing about what it holds, so what
    // an earlier scan stored for it must survive. Leaving it out of the synced set would
    // have the storage layer report every one of its records as deleted.
    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, "/images/a"}};

    bool readable {true};
    const auto factory = [&readable](const ConfiguredReference & reference,
                                     const std::string&,
                                     const ReaderContext&) -> std::unique_ptr<IImageReader>
    {
        return std::make_unique<OutcomeReader>(readable
                                               ? ImageReadResult::success({recordAt(reference.location, 3)})
                                               : ImageReadResult::failed());
    };

    ContainerImagesImpl impl(config, factory, std::make_shared<ContainerImagesDB>(m_dbPath));

    impl.scanOnce();
    ASSERT_EQ(storedPackages(m_dbPath), 3U);

    readable = false;
    impl.scanOnce();

    EXPECT_EQ(storedReferences(m_dbPath), 1U);
    EXPECT_EQ(storedPackages(m_dbPath), 3U);
}

TEST_F(ContainerImagesDBTest, AnEmptyReadStillRemovesWhatTheReferenceHeld)
{
    // The other half of the rule: a reference that was read and holds nothing really is
    // empty, so its records go. This is what separates an empty read from a failed one.
    //
    // Asserted on what the storage layer reports rather than on rows read back through a
    // second connection, so the test says the same thing whatever the storage library's
    // commit timing is.
    ContainerImagesDB db {m_dbPath};

    const auto reference {recordAt("/images/a", 3)};
    db.syncReferences({reference}, [](ReturnTypeCallback, const std::string&, const std::string&,
                                      const std::string&, std::uint64_t) {});
    db.syncPackages({reference}, [](ReturnTypeCallback, const std::string&, const std::string&,
                                    const std::string&, std::uint64_t) {});

    std::size_t deletedPackages {0};
    std::size_t deletedReferences {0};

    const auto counting = [&](ReturnTypeCallback operation, const std::string & table, const std::string&,
                              const std::string&, std::uint64_t)
    {
        if (operation == DELETED)
        {
            table == PACKAGES_TABLE ? ++deletedPackages : ++deletedReferences;
        }
    };

    db.syncReferences({}, counting);
    db.syncPackages({}, counting);

    EXPECT_EQ(deletedReferences, 1U);
    EXPECT_EQ(deletedPackages, 3U);
}

TEST_F(ContainerImagesDBTest, AnUnchangedReferenceKeepsItsStoredInventory)
{
    // The reader reports the image still holds the stored digest, so it did not read the
    // layers. The stored inventory is that image's inventory, and it stays.
    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, "/images/a"}};

    bool firstScan {true};
    std::string digestSeenByTheReader;

    const auto factory = [&](const ConfiguredReference & reference,
                             const std::string & knownConfigDigest,
                             const ReaderContext&) -> std::unique_ptr<IImageReader>
    {
        digestSeenByTheReader = knownConfigDigest;

        if (firstScan)
        {
            return std::make_unique<OutcomeReader>(ImageReadResult::success({recordAt(reference.location, 5)}));
        }

        return std::make_unique<OutcomeReader>(ImageReadResult::unchanged());
    };

    ContainerImagesImpl impl(config, factory, std::make_shared<ContainerImagesDB>(m_dbPath));

    impl.scanOnce();
    ASSERT_EQ(storedPackages(m_dbPath), 5U);
    EXPECT_TRUE(digestSeenByTheReader.empty());   // nothing stored yet on the first scan

    firstScan = false;
    impl.scanOnce();

    // The digest of the stored image is handed to the reader, which is what lets it decide.
    EXPECT_EQ(digestSeenByTheReader, "sha256:config-aaaa");
    EXPECT_EQ(storedReferences(m_dbPath), 1U);
    EXPECT_EQ(storedPackages(m_dbPath), 5U);
}

TEST_F(ContainerImagesDBTest, AStopMidScanStoresNothing)
{
    // A scan cut short by a stop describes only the references it reached. Storing that
    // would report every reference it never got to as deleted.
    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, "/images/a"}, {ReferenceType::Archive, "/images/b"}};

    const auto db {std::make_shared<ContainerImagesDB>(m_dbPath)};

    {
        ContainerImagesImpl seed(config, [](const ConfiguredReference & reference, const std::string&, const ReaderContext&)
        {
            return std::unique_ptr<IImageReader>(
                       std::make_unique<OutcomeReader>(ImageReadResult::success({recordAt(reference.location, 4)})));
        }, db);
        seed.scanOnce();
    }

    ASSERT_EQ(storedReferences(m_dbPath), 2U);
    ASSERT_EQ(storedPackages(m_dbPath), 8U);

    ContainerImagesImpl* self {nullptr};
    auto stopping = [&](const ConfiguredReference & reference, const std::string&, const ReaderContext&) -> std::unique_ptr<IImageReader>
    {
        if (self != nullptr)
        {
            self->stop();   // the stop lands while the scan is between references
        }

        return std::make_unique<OutcomeReader>(ImageReadResult::success({recordAt(reference.location, 4)}));
    };

    ContainerImagesImpl impl(config, stopping, db);
    self = &impl;
    impl.scanOnce();

    EXPECT_EQ(storedReferences(m_dbPath), 2U);
    EXPECT_EQ(storedPackages(m_dbPath), 8U);
}

TEST_F(ContainerImagesDBTest, ImplUsesInjectedReaderFactory)
{
    std::vector<ConfiguredReference> factoryReferences;

    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, "/some/path"}};

    ContainerImagesImpl impl(config, [&factoryReferences](const ConfiguredReference & reference, const std::string&, const ReaderContext&)
    {
        factoryReferences.push_back(reference);
        return std::unique_ptr<IImageReader>(nullptr);
    }, std::make_shared<ContainerImagesDB>(m_dbPath));

    EXPECT_EQ(impl.scanOnce(), 0U);

    // The factory is driven by the configured reference, not by a fixed one.
    ASSERT_EQ(factoryReferences.size(), 1U);
    EXPECT_EQ(factoryReferences.front().location, "/some/path");
    EXPECT_EQ(factoryReferences.front().type, ReferenceType::Archive);
}

TEST_F(ContainerImagesDBTest, ScanOnceStoresTheReferenceFoundOnDisk)
{
    // The stored digest must be the one the configured layout actually holds: the module
    // ships the real reader, so nothing synthetic can reach the database.
    const auto fixture = buildSingleImageLayout();

    ContainerImagesConfig config;
    config.references = {{ReferenceType::Archive, fixture->path()}};

    {
        ContainerImagesImpl impl(config, makeReader, std::make_shared<ContainerImagesDB>(m_dbPath));
        ASSERT_EQ(impl.scanOnce(), 1U);
    }

    const auto rows {storedRows(m_dbPath, REFERENCES_TABLE, {"reference_type", "reference_value", "image_config_digest"})};

    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().at("reference_type"), "archive");
    EXPECT_EQ(rows.front().at("reference_value"), fixture->path());
    EXPECT_EQ(rows.front().at("image_config_digest"), "sha256:" + CONFIG_DIGEST);
}

TEST_F(ContainerImagesDBTest, ScanOncePersistsThePackagesFoundInTheImage)
{
    // End to end over the real reader: an image built on disk, its packages extracted from
    // the layer, and the rows stored. Nothing synthetic takes part.
    const auto fixture = buildSingleImageLayoutWithPackages();

    ContainerImagesConfig config;
    config.dbPath = m_dbPath;
    config.references = {{ReferenceType::Archive, fixture->path()}};

    {
        ContainerImagesImpl impl(config, makeReader, std::make_shared<ContainerImagesDB>(m_dbPath));
        EXPECT_EQ(impl.scanOnce(), 1U);
    }

    const auto rows {storedRows(m_dbPath, PACKAGES_TABLE, {"name", "version_", "type", "package_db_path"})};

    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().at("name"), "curl");
    EXPECT_EQ(rows.front().at("version_"), "7.88.1-10");
    EXPECT_EQ(rows.front().at("type"), "deb");
    EXPECT_EQ(rows.front().at("package_db_path"), "var/lib/dpkg/status");
}

TEST_F(ContainerImagesDBTest, ImplDisabledDoesNotScan)
{
    int factoryCalls = 0;

    ContainerImagesConfig config;
    config.enabled = false;
    config.scanOnStart = true;
    config.references = {{ReferenceType::Archive, "/some/path"}};

    ContainerImagesImpl impl(config, [&factoryCalls](const ConfiguredReference&, const std::string&, const ReaderContext&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    }, std::make_shared<ContainerImagesDB>(m_dbPath));

    impl.run();
    EXPECT_EQ(factoryCalls, 0);
}

TEST_F(ContainerImagesDBTest, ImplFailingScanDoesNotEndTheModule)
{
    // A reader that throws must cost one scan, not the module: run() has to return through
    // stop(), not through the exception.
    ContainerImagesConfig config;
    config.scanOnStart = true;
    config.interval = 1;
    config.references = {{ReferenceType::Archive, "/some/path"}};

    ContainerImagesImpl impl(config, [](const ConfiguredReference&, const std::string&, const ReaderContext&) -> std::unique_ptr<IImageReader>
    {
        throw std::runtime_error("reader failure");
    }, std::make_shared<ContainerImagesDB>(m_dbPath));

    std::thread runner([&impl] { ASSERT_NO_THROW(impl.run()); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    impl.stop();
    runner.join();
}

TEST_F(ContainerImagesDBTest, ImplRunStopsPromptly)
{
    ContainerImagesConfig config;
    config.scanOnStart = false;
    config.interval = 3600;

    ContainerImagesImpl impl(config, makeReader, std::make_shared<ContainerImagesDB>(m_dbPath));

    std::thread runner([&impl] { impl.run(); });

    // Let run() reach the interval wait before signalling it.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const auto stopRequested = std::chrono::steady_clock::now();
    impl.stop();
    runner.join();

    EXPECT_LT(std::chrono::steady_clock::now() - stopRequested, std::chrono::seconds(5));
}

TEST_F(ContainerImagesDBTest, ImplStopBeforeRunDoesNotScan)
{
    // The shutdown loop signals every module before joining any of them, so a stop
    // can land before the module thread ever reaches run(). It must be honoured.
    int factoryCalls = 0;

    ContainerImagesConfig config;
    config.scanOnStart = true;
    config.interval = 3600;
    config.references = {{ReferenceType::Archive, "/some/path"}};

    ContainerImagesImpl impl(config, [&factoryCalls](const ConfiguredReference&, const std::string&, const ReaderContext&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    }, std::make_shared<ContainerImagesDB>(m_dbPath));

    impl.stop();

    const auto before = std::chrono::steady_clock::now();
    impl.run();

    EXPECT_LT(std::chrono::steady_clock::now() - before, std::chrono::seconds(5));
    EXPECT_EQ(factoryCalls, 0);
}

TEST_F(ContainerImagesDBTest, HostPackageInventoryIsNotTouchedByAContainerImageSync)
{
    // Stand-in for the host package inventory: the table name Syscollector owns, in its own
    // database file. What must hold is that a container image scan cannot reach it.
    const auto hostDbPath {m_dbPath + "_host.db"};
    constexpr auto HOST_TABLE {"dbsync_packages"};
    const std::string hostSchema {R"(CREATE TABLE IF NOT EXISTS dbsync_packages (
        name TEXT, version TEXT, checksum TEXT, PRIMARY KEY (name)) WITHOUT ROWID;)"};

    nlohmann::json hostRows = nlohmann::json::array();
    hostRows.push_back({{"name", "apt"}, {"version", "2.6.1"}, {"checksum", "host-checksum"}});

    DBSync hostDb {HostType::AGENT, DbEngineType::SQLITE3, hostDbPath, hostSchema, DbManagement::PERSISTENT};

    const auto syncHost = [&hostDb, &hostRows, HOST_TABLE](DeltaTally & tally)
    {
        const auto callback = [&tally](ReturnTypeCallback result, const nlohmann::json&)
        {
            if (result == INSERTED) ++tally.created;
            else if (result == MODIFIED) ++tally.modified;
            else if (result == DELETED) ++tally.deleted;
        };

        nlohmann::json input;
        input["table"] = HOST_TABLE;
        input["data"] = hostRows;

        DBSyncTxn txn {hostDb.handle(), nlohmann::json {HOST_TABLE}, 0, 4096, callback};
        txn.syncTxnRow(input);
        txn.getDeletedRows(callback);
    };

    DeltaTally hostFirst;
    syncHost(hostFirst);
    ASSERT_EQ(hostFirst.created, 1);

    // A container image inventory carrying a package with the same name and version.
    const std::vector<ImageReferenceRecord> references {
        makeReference("debian:12", {makePackage("apt", "2.6.1")})};

    ContainerImagesDB db(m_dbPath);
    DeltaTally imageTally;
    db.syncReferences(references, imageTally.callback());
    db.syncPackages(references, imageTally.callback());
    ASSERT_EQ(imageTally.created, 2);

    // The host row is still there, unchanged: re-syncing the same content yields no delta.
    DeltaTally hostSecond;
    syncHost(hostSecond);
    EXPECT_EQ(hostSecond.created, 0);
    EXPECT_EQ(hostSecond.modified, 0);
    EXPECT_EQ(hostSecond.deleted, 0);

    // The two inventories live in different files, and the module's database has no host
    // package table to write to.
    EXPECT_NE(hostDbPath, m_dbPath);
    EXPECT_TRUE(std::filesystem::exists(hostDbPath));
    EXPECT_TRUE(std::filesystem::exists(m_dbPath));
    EXPECT_ANY_THROW(storedRows(m_dbPath, HOST_TABLE, {"name"}));

    std::filesystem::remove(hostDbPath);
}

TEST_F(ContainerImagesDBTest, SamePackageInTwoImagesIsStoredIndependently)
{
    ContainerImagesDB db(m_dbPath);

    // Byte-identical package records, differing only in the reference that owns them.
    const std::vector<ImageReferenceRecord> references {
        makeReference("debian:12", {makePackage("apt", "2.6.1")}),
        makeReference("ubuntu:24.04", {makePackage("apt", "2.6.1")})};

    DeltaTally tally;
    db.syncReferences(references, tally.callback());
    db.syncPackages(references, tally.callback());

    // Two references plus two package rows: the reference is part of the package identity,
    // so one image's inventory never overwrites another's.
    EXPECT_EQ(tally.created, 4);
    EXPECT_EQ(tally.modified, 0);
    EXPECT_EQ(tally.deleted, 0);

    // Removing one reference leaves the other reference's copy of the package in place.
    const std::vector<ImageReferenceRecord> remaining {
        makeReference("debian:12", {makePackage("apt", "2.6.1")})};

    DeltaTally second;
    db.syncReferences(remaining, second.callback());
    db.syncPackages(remaining, second.callback());

    EXPECT_EQ(second.deleted, 2); // the ubuntu reference and its package
    EXPECT_EQ(second.created, 0);
    EXPECT_EQ(second.modified, 0);
}

TEST_F(ContainerImagesDBTest, PackageAttributeFieldsArePersisted)
{
    ContainerImagesDB db(m_dbPath);

    auto package {makePackage("apt", "2.6.1")};
    package.vendor = "Debian";
    package.installed = "2026-01-15T09:12:44Z";
    package.path = "/usr/bin/apt";
    package.category = "admin";
    package.description = "commandline package manager";
    package.priority = "required";
    package.multiarch = "same";
    package.source = "apt";
    package.packageDbPath = "var/lib/dpkg/status";
    package.size = 4276224;

    auto reference {makeReference("debian:12", {package})};
    reference.tags = {"12", "bookworm"};

    std::string packageRow;
    std::string referenceRow;

    const auto capture = [&](ReturnTypeCallback, const std::string & table, const std::string&,
                             const std::string & data, std::uint64_t)
    {
        (table == PACKAGES_TABLE ? packageRow : referenceRow) = data;
    };

    db.syncReferences({reference}, capture);
    db.syncPackages({reference}, capture);

    for (const auto& field : {"\"vendor\":\"Debian\"",
                              "\"installed\":\"2026-01-15T09:12:44Z\"",
                              "\"path\":\"/usr/bin/apt\"",
                              "\"category\":\"admin\"",
                              "\"priority\":\"required\"",
                              "\"multiarch\":\"same\"",
                              "\"source\":\"apt\""})
    {
        EXPECT_NE(packageRow.find(field), std::string::npos) << "missing " << field;
    }

    // Tags are carried as a serialized JSON array next to the display tag.
    EXPECT_NE(referenceRow.find("bookworm"), std::string::npos);
}

TEST_F(ContainerImagesDBTest, DropTablesClearsTheInventory)
{
    ContainerImagesDB db(m_dbPath);

    const std::vector<ImageReferenceRecord> references {
        makeReference("debian:12", {makePackage("apt", "2.6.1"), makePackage("curl", "7.88.1")})};

    DeltaTally first;
    db.syncReferences(references, first.callback());
    db.syncPackages(references, first.callback());
    EXPECT_EQ(first.created, 3);

    db.dropTables();

    // With the rows gone the same inventory is new again, which would not happen if
    // dropTables() had left anything behind.
    DeltaTally afterDrop;
    db.syncReferences(references, afterDrop.callback());
    db.syncPackages(references, afterDrop.callback());

    EXPECT_EQ(afterDrop.created, 3);
    EXPECT_EQ(afterDrop.modified, 0);
    EXPECT_EQ(afterDrop.deleted, 0);
}

TEST_F(ContainerImagesDBTest, ReopeningAPersistedDatabaseKeepsItsRows)
{
    const std::vector<ImageReferenceRecord> references {
        makeReference("debian:12", {makePackage("apt", "2.6.1")})};

    {
        ContainerImagesDB db(m_dbPath);
        DeltaTally first;
        db.syncReferences(references, first.callback());
        db.syncPackages(references, first.callback());
        EXPECT_EQ(first.created, 2);
    }

    // Reopening at the same schema version must not recreate the database: the rows survive,
    // so the second scan reports no deltas.
    ContainerImagesDB reopened(m_dbPath);
    DeltaTally second;
    reopened.syncReferences(references, second.callback());
    reopened.syncPackages(references, second.callback());

    EXPECT_EQ(second.created, 0);
    EXPECT_EQ(second.modified, 0);
    EXPECT_EQ(second.deleted, 0);
}

TEST_F(ContainerImagesDBTest, CreatedTablesCarryTheDocumentedColumns)
{
    ContainerImagesDB db(m_dbPath);

    auto package {makePackage("apt", "2.6.1")};
    package.size = 4276224;
    const std::vector<ImageReferenceRecord> references {makeReference("debian:12", {package})};

    db.syncReferences(references, DeltaTally().callback());
    db.syncPackages(references, DeltaTally().callback());

    // Selecting a column the CREATE statement does not define makes DBSync throw, so this
    // asserts the created tables, not the string the module holds.
    const auto storedReferences {storedRows(m_dbPath, REFERENCES_TABLE,
    {
        "reference_type", "reference_value", "image_config_digest", "manifest_digest", "image_name",
        "tag", "tags", "platform_os", "platform_architecture", "platform_variant",
        "platform_os_version", "checksum", "version", "sync"
    })};

    ASSERT_EQ(storedReferences.size(), 1U);
    EXPECT_EQ(storedReferences.front().at("reference_type"), "local");
    EXPECT_EQ(storedReferences.front().at("platform_architecture"), "amd64");

    const auto storedPackages {storedRows(m_dbPath, PACKAGES_TABLE,
    {
        "reference_type", "reference_value", "name", "version_", "architecture", "type", "vendor",
        "installed", "path", "category", "description", "size", "priority", "multiarch", "source",
        "package_db_path", "checksum", "version", "sync"
    })};

    ASSERT_EQ(storedPackages.size(), 1U);
    EXPECT_EQ(storedPackages.front().at("name"), "apt");
    EXPECT_EQ(storedPackages.front().at("version_"), "2.6.1");
    EXPECT_EQ(storedPackages.front().at("size"), "4276224");
}

TEST_F(ContainerImagesDBTest, CreatedTablesEnforceTheDocumentedPrimaryKeys)
{
    ContainerImagesDB db(m_dbPath);

    auto packageWithSize = [](const std::string& version, long long size)
    {
        auto package = makePackage("apt", version);
        package.size = size;
        return package;
    };

    // A change outside the key updates the stored row in place.
    db.syncPackages({makeReference("debian:12", {packageWithSize("2.6.1", 100)})}, DeltaTally().callback());
    db.syncPackages({makeReference("debian:12", {packageWithSize("2.6.1", 200)})}, DeltaTally().callback());
    EXPECT_EQ(storedRows(m_dbPath, PACKAGES_TABLE, {"name", "version_", "size"}).size(), 1U);

    // A change inside the key is a different row, and so is the owning reference.
    db.syncPackages({makeReference("debian:12", {packageWithSize("2.6.1", 200), packageWithSize("2.6.2", 200)})},
                    DeltaTally().callback());
    EXPECT_EQ(storedRows(m_dbPath, PACKAGES_TABLE, {"name", "version_"}).size(), 2U);

    // References are keyed on (reference_type, reference_value): the digest is a change
    // signal carried as a column, not part of the identity.
    auto reference {makeReference("debian:12", {})};
    db.syncReferences({reference}, DeltaTally().callback());

    reference.configDigest = "sha256:rebuilt";
    db.syncReferences({reference}, DeltaTally().callback());
    EXPECT_EQ(storedRows(m_dbPath, REFERENCES_TABLE, {"reference_value", "image_config_digest"}).size(), 1U);

    db.syncReferences({reference, makeReference("ubuntu:24.04", {})}, DeltaTally().callback());
    EXPECT_EQ(storedRows(m_dbPath, REFERENCES_TABLE, {"reference_value"}).size(), 2U);
}
