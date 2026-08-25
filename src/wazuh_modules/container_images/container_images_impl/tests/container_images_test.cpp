#include "container_images_config.hpp"
#include "container_images_impl.hpp"
#include "local_image_reader.hpp"
#include "ci_logging_helper.hpp"

#include <gtest/gtest.h>

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

TEST_F(ContainerImagesTest, ImplScanOnceReturnsReferenceCount)
{
    const auto fixture = buildSingleImageLayout();

    ContainerImagesConfig config;
    config.localPaths = {fixture->path()};

    ContainerImagesImpl impl(config);
    EXPECT_EQ(impl.scanOnce(), 1U);
}

TEST_F(ContainerImagesTest, ImplScanOnceAggregatesMultipleSources)
{
    const auto fixture = buildSingleImageLayout();

    ContainerImagesConfig config;
    config.localPaths = {fixture->path(), fixture->path()};

    ContainerImagesImpl impl(config);
    EXPECT_EQ(impl.scanOnce(), 2U);
}

TEST_F(ContainerImagesTest, ImplNoSourcesScansNothing)
{
    ContainerImagesConfig config; // no localPaths

    int factoryCalls = 0;
    ContainerImagesImpl impl(config, [&factoryCalls](const std::string&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    });

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_EQ(factoryCalls, 0);
}

TEST_F(ContainerImagesTest, ImplUsesInjectedReaderFactory)
{
    bool factoryCalled = false;

    ContainerImagesConfig config;
    config.localPaths = {"/some/path"};

    ContainerImagesImpl impl(config, [&factoryCalled](const std::string&)
    {
        factoryCalled = true;
        return std::unique_ptr<IImageReader>(nullptr);
    });

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_TRUE(factoryCalled);
}

TEST_F(ContainerImagesTest, ImplDisabledDoesNotScan)
{
    int factoryCalls = 0;

    ContainerImagesConfig config;
    config.enabled = false;
    config.scanOnStart = true;
    config.localPaths = {"/some/path"};

    ContainerImagesImpl impl(config, [&factoryCalls](const std::string&)
    {
        ++factoryCalls;
        return std::unique_ptr<IImageReader>(nullptr);
    });

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
