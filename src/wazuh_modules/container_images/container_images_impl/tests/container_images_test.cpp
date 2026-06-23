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

using namespace containerimages;

namespace
{
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

            void writeMarker()
            {
                writeFile(m_root / "oci-layout", R"({"imageLayoutVersion":"1.0.0"})");
            }

            void writeBlob(const std::string& digest, const std::string& content)
            {
                writeFile(m_root / "blobs" / "sha256" / digest, content);
            }

            void writeIndex(const std::string& content)
            {
                writeFile(m_root / "index.json", content);
            }

        private:
            static std::string uniqueName()
            {
                static std::atomic<unsigned> counter {0};
                const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
                return "container_images_test_" + std::to_string(now) + "_" + std::to_string(counter++);
            }

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

    /// @brief Writes a complete single-image layout and returns its root path.
    std::unique_ptr<OciLayoutFixture> buildSingleImageLayout()
    {
        auto fixture = std::make_unique<OciLayoutFixture>();
        fixture->writeMarker();

        const std::string configDigest = "configdigest1111111111111111111111111111111111111111111111111111";
        const std::string manifestDigest = "manifestdigest11111111111111111111111111111111111111111111111111";

        fixture->writeBlob(configDigest,
                           R"({"os":"linux","architecture":"amd64","variant":"v8","os.version":""})");
        fixture->writeBlob(manifestDigest,
                           R"({"config":{"digest":"sha256:)" + configDigest + R"("}})");
        fixture->writeIndex(R"({"manifests":[{"digest":"sha256:)" + manifestDigest +
                            R"(","annotations":{"org.opencontainers.image.ref.name":"alpine:latest"}}]})");

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
    const auto dir = std::filesystem::temp_directory_path() / "container_images_unknown_fmt";
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
    const auto dir = std::filesystem::temp_directory_path() / "container_images_docker_archive";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    std::ofstream(dir / "manifest.json") << "[]";

    LocalImageReader reader(dir.string());
    EXPECT_TRUE(reader.discover().empty());

    std::filesystem::remove_all(dir);
}

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
