#include "container_images_config.hpp"
#include "container_images_db.hpp"
#include "container_images_impl.hpp"
#include "local_image_reader.hpp"
#include "ci_logging_helper.hpp"

#include "dbsync.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
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

TEST_F(ContainerImagesTest, LocalReaderSourceType)
{
    LocalImageReader reader("");
    EXPECT_EQ(reader.sourceType(), "local");
}

TEST_F(ContainerImagesTest, LocalReaderEmptyPathReturnsNothing)
{
    LocalImageReader reader("");
    EXPECT_TRUE(reader.discover().empty());
}

TEST_F(ContainerImagesTest, LocalReaderMissingLayoutReturnsNothing)
{
    LocalImageReader reader("/nonexistent/path/to/layout");
    EXPECT_TRUE(reader.discover().empty());
}

TEST_F(ContainerImagesTest, LocalReaderReadsSingleReference)
{
    const auto fixture = buildSingleImageLayout();

    LocalImageReader reader(fixture->path());
    const auto references = reader.discover();

    ASSERT_EQ(references.size(), 1U);

    const auto& reference = references.front();
    EXPECT_EQ(reference.configDigest, "sha256:configdigest1111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(reference.os, "linux");
    EXPECT_EQ(reference.architecture, "amd64");
    EXPECT_EQ(reference.variant, "v8");
    EXPECT_EQ(reference.tag, "alpine:latest");
    EXPECT_EQ(reference.source.sourceType, "local");
    EXPECT_EQ(reference.source.location, fixture->path());
}

TEST_F(ContainerImagesTest, LocalReaderUnknownFormatReturnsNothing)
{
    // A directory that exists but holds no recognizable layout.
    const auto dir = std::filesystem::temp_directory_path() / (uniqueName() + "_unknown_fmt");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    LocalImageReader reader(dir.string());
    EXPECT_TRUE(reader.discover().empty());

    std::filesystem::remove_all(dir);
}

TEST_F(ContainerImagesTest, LocalReaderDockerArchiveNotImplemented)
{
    // A docker-save archive directory (manifest.json, no oci-layout) is detected
    // but not supported yet: it must be skipped, returning no references.
    const auto dir = std::filesystem::temp_directory_path() / (uniqueName() + "_docker_archive");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    std::ofstream(dir / "manifest.json") << "[]";

    LocalImageReader reader(dir.string());
    EXPECT_TRUE(reader.discover().empty());

    std::filesystem::remove_all(dir);
}

TEST_F(ContainerImagesTest, LocalReaderRejectsTraversalDigest)
{
    // A digest that escapes the layout directory must never reach the filesystem.
    const auto fixture = buildLayoutWithIndex(R"({"manifests":[{"digest":"sha256:../../../../etc/hostname"}]})");

    LocalImageReader reader(fixture->path());
    EXPECT_TRUE(reader.discover().empty());
}

TEST_F(ContainerImagesTest, LocalReaderRejectsDriveRelativeDigest)
{
    // "C:foo" splits at the first colon and passes a separator blacklist, but on
    // Windows operator/ would replace the layout path with a drive-relative one.
    const auto fixture = buildLayoutWithIndex(R"({"manifests":[{"digest":"sha256:C:foo"}]})");

    LocalImageReader reader(fixture->path());
    EXPECT_TRUE(reader.discover().empty());
}

TEST_F(ContainerImagesTest, LocalReaderNonObjectManifestEntryIsSkipped)
{
    const auto fixture = buildLayoutWithIndex(R"({"manifests":["oops"]})");

    LocalImageReader reader(fixture->path());
    EXPECT_NO_THROW(EXPECT_TRUE(reader.discover().empty()));
}

TEST_F(ContainerImagesTest, LocalReaderNonStringDigestIsSkipped)
{
    const auto fixture = buildLayoutWithIndex(R"({"manifests":[{"digest":123}]})");

    LocalImageReader reader(fixture->path());
    EXPECT_NO_THROW(EXPECT_TRUE(reader.discover().empty()));
}

TEST_F(ContainerImagesTest, LocalReaderNonObjectManifestConfigIsSkipped)
{
    const auto fixture = buildSingleImageLayout();
    fixture->writeBlob(MANIFEST_DIGEST, R"({"config":"x"})");

    LocalImageReader reader(fixture->path());
    EXPECT_NO_THROW(EXPECT_TRUE(reader.discover().empty()));
}

TEST_F(ContainerImagesTest, LocalReaderUnparseableConfigBlobKeepsReferenceWithoutMetadata)
{
    // The image reference is still known from the manifest, so it is reported; only
    // the platform metadata is missing. What must not happen is an exception.
    const auto fixture = buildSingleImageLayout();
    fixture->writeBlob(CONFIG_DIGEST, "{not json");

    LocalImageReader reader(fixture->path());

    std::vector<ImageReferenceRecord> references;
    ASSERT_NO_THROW(references = reader.discover());
    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().os.empty());
    EXPECT_TRUE(references.front().architecture.empty());
}

TEST_F(ContainerImagesTest, LocalReaderWrongTypedConfigFieldIsIgnored)
{
    const auto fixture = buildSingleImageLayout();
    fixture->writeBlob(CONFIG_DIGEST, R"({"os":5,"architecture":"amd64"})");

    LocalImageReader reader(fixture->path());

    std::vector<ImageReferenceRecord> references;
    ASSERT_NO_THROW(references = reader.discover());
    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().os.empty());
    EXPECT_EQ(references.front().architecture, "amd64");
}

#ifndef _WIN32
TEST_F(ContainerImagesTest, LocalReaderSkipsNonRegularBlob)
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

    LocalImageReader reader(fixture->path());
    EXPECT_TRUE(reader.discover().empty());
}
#endif

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

TEST_F(ContainerImagesDBTest, PackageVersionChangeReportsModified)
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

// ---------------------------------------------------------------------------
// Orchestrator — scanOnce drives the stub reader through the DB.
// ---------------------------------------------------------------------------

TEST_F(ContainerImagesDBTest, ScanOnceWithStubReaderPersistsPackages)
{
    ContainerImagesConfig config;
    config.dbPath = m_dbPath;

    // Default reader factory yields the stub reader; inject the temp DB so nothing is
    // written under the working directory. No sync protocol is injected, so persistence
    // is exercised without requiring the manager transport.
    auto db = std::make_shared<ContainerImagesDB>(m_dbPath);
    ContainerImagesImpl impl(config, makeReader, db);

    EXPECT_GT(impl.scanOnce(), 0U);
}

TEST_F(ContainerImagesTest, ImplDisabledDoesNotScan)
{
    int factoryCalls = 0;

    ContainerImagesConfig config;
    config.enabled = false;
    config.scanOnStart = true;

    auto db = std::make_shared<ContainerImagesDB>(
                  (std::filesystem::temp_directory_path() / "ci_disabled.db").string());

    ContainerImagesImpl impl(config, [&factoryCalls](const std::string&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    }, db);

    impl.run();
    EXPECT_EQ(factoryCalls, 0);
}

TEST_F(ContainerImagesTest, ImplRunStopsPromptly)
{
    ContainerImagesConfig config;
    config.scanOnStart = false;
    config.interval = 3600;

    ContainerImagesImpl impl(config);

    std::thread runner([&impl] { impl.run(); });

    // Let run() reach the interval wait before signalling it.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const auto stopRequested = std::chrono::steady_clock::now();
    impl.stop();
    runner.join();

    EXPECT_LT(std::chrono::steady_clock::now() - stopRequested, std::chrono::seconds(5));
}

TEST_F(ContainerImagesTest, ImplStopBeforeRunDoesNotScan)
{
    // The shutdown loop signals every module before joining any of them, so a stop
    // can land before the module thread ever reaches run(). It must be honoured.
    int factoryCalls = 0;

    ContainerImagesConfig config;
    config.scanOnStart = true;
    config.interval = 3600;
    config.localPaths = {"/some/path"};

    ContainerImagesImpl impl(config, [&factoryCalls](const std::string&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    });

    impl.stop();

    const auto before = std::chrono::steady_clock::now();
    impl.run();

    EXPECT_LT(std::chrono::steady_clock::now() - before, std::chrono::seconds(5));
    EXPECT_EQ(factoryCalls, 0);
}

TEST_F(ContainerImagesDBTest, SchemaDoesNotCollideWithHostPackageInventory)
{
    const auto statement {ContainerImagesDB::getCreateStatement()};

    EXPECT_NE(statement.find(REFERENCES_TABLE), std::string::npos);
    EXPECT_NE(statement.find(PACKAGES_TABLE), std::string::npos);

    // The host package inventory owns dbsync_packages. Creating or writing that table here
    // would let container image packages overwrite host packages.
    EXPECT_EQ(statement.find("dbsync_packages("), std::string::npos);
    EXPECT_EQ(statement.find("dbsync_packages "), std::string::npos);
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

TEST_F(ContainerImagesDBTest, UpgradeStatementsDefineTheSchemaVersion)
{
    // DBSync derives the current schema version from this list (size + 1). The list is empty
    // while the schema is on its first revision; each later schema change appends one entry.
    EXPECT_TRUE(ContainerImagesDB::getUpgradeStatements().empty());
}
