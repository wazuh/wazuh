/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_images_config.hpp"
#include "container_images_db.hpp"
#include "container_images_impl.hpp"
#include "ci_logging_helper.hpp"
#include "docker_image_source.hpp"
#include "engine_image_reader.hpp"
#include "image_fixtures.hpp"
#include "oci_metadata.hpp"
#include "packageDbParser.hpp"
#include "platform_selection.hpp"

#include "dbsync.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <stdexcept>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace containerimages;
using namespace imagefixtures;

namespace
{
    std::string uniqueName()
    {
        static std::atomic<unsigned> counter {0};
        const auto now {std::chrono::steady_clock::now().time_since_epoch().count()};
        return "ci_engine_" + std::to_string(now) + "_" + std::to_string(counter++);
    }

    /// @brief A digest-shaped id: the reader accepts any `algorithm:encoded` made of the OCI characters.
    std::string idOf(const char letter)
    {
        return "sha256:" + std::string(64, letter);
    }

    /// @brief What `docker save <id>` writes for an image with one dpkg package: no RepoTags, since it was saved by id.
    std::string dockerSave(const std::string& id, const std::string& package)
    {
        const auto config {id.substr(std::string {"sha256:"}.size())};
        const auto layer {gzip(tarMember("var/lib/dpkg/status", dpkgStanza(package, "1.0")) + tarEnd())};

        std::string archive;
        archive += tarMember("layer0/layer.tar", layer);
        archive += tarMember(config + ".json", R"({"os":"linux","architecture":"amd64"})");
        archive += tarMember("manifest.json",
                             R"([{"Config":")" + config + R"(.json","RepoTags":null,"Layers":["layer0/layer.tar"]}])");
        archive += tarEnd();

        return archive;
    }

#ifdef __linux__
    /// @brief The export of an image whose only package database is an rpm Berkeley DB one, holding bash.
    std::string dockerSaveWithBerkeleyDb(const std::string& id)
    {
        const auto config {id.substr(std::string {"sha256:"}.size())};
        RpmPackage bash;
        bash.name = "bash";
        bash.version = "4.2.46";
        const auto layer {gzip(tarMember("var/lib/rpm/Packages", rpmBerkeleyDatabase({rpmHeaderBlob(bash)})) + tarEnd())};

        std::string archive;
        archive += tarMember("layer0/layer.tar", layer);
        archive += tarMember(config + ".json", R"({"os":"linux","architecture":"amd64"})");
        archive += tarMember("manifest.json",
                             R"([{"Config":")" + config + R"(.json","RepoTags":null,"Layers":["layer0/layer.tar"]}])");
        archive += tarEnd();

        return archive;
    }
#endif

    /// @brief An export of one image that holds two platform manifests, each with its own configuration and one package.
    std::string dockerSaveTwoPlatforms(const std::string& firstArchitecture, const std::string& secondArchitecture)
    {
        const auto first {std::string(64, '1')};
        const auto second {std::string(64, '2')};
        const auto layer = [](const std::string & package)
        {
            return gzip(tarMember("var/lib/dpkg/status", dpkgStanza(package, "1.0")) + tarEnd());
        };

        std::string archive;
        archive += tarMember("first/layer.tar", layer("first"));
        archive += tarMember("second/layer.tar", layer("second"));
        archive += tarMember(first + ".json", R"({"os":"linux","architecture":")" + firstArchitecture + R"("})");
        archive += tarMember(second + ".json", R"({"os":"linux","architecture":")" + secondArchitecture + R"("})");
        archive += tarMember("manifest.json",
                             R"([{"Config":")" + first + R"(.json","RepoTags":null,"Layers":["first/layer.tar"]},)" +
                             R"({"Config":")" + second + R"(.json","RepoTags":null,"Layers":["second/layer.tar"]}])");
        archive += tarEnd();

        return archive;
    }

    /// @brief An export held in memory. A truncated one stops halfway and reports the transfer as failed.
    class MemoryExport final : public IBlobStream
    {
        public:
            MemoryExport(std::string content, const bool breaks)
                : m_content {breaks ? content.substr(0, content.size() / 2) : std::move(content)}
                , m_breaks {breaks}
            {
            }

            std::size_t read(char* buffer, const std::size_t size) override
            {
                const auto count {std::min(size, m_content.size() - m_offset)};
                std::copy_n(m_content.data() + m_offset, count, buffer);
                m_offset += count;

                if (count == 0 && m_breaks)
                {
                    m_failed = true;
                    m_error = "the connection to the engine was closed";
                }

                return count;
            }

            bool failed() const override
            {
                return m_failed;
            }

            const std::string& error() const override
            {
                return m_error;
            }

            long status() const override
            {
                return 200;
            }

            std::uint64_t bytesDelivered() const override
            {
                return m_offset;
            }

            bool abortedLocally() const override
            {
                return false;
            }

            const std::string& retryAfter() const override
            {
                return m_retryAfter;
            }

        private:
            std::string m_content;
            bool m_breaks;
            std::size_t m_offset {0};
            bool m_failed {false};
            std::string m_error;
            std::string m_retryAfter;
    };

    /// @brief An export that fails before delivering anything, ended by the engine's answer or by this side's own bound.
    class DeadExport final : public IBlobStream
    {
        public:
            explicit DeadExport(const bool endedLocally)
                : m_endedLocally {endedLocally}
            {
            }

            std::size_t read(char*, std::size_t) override
            {
                return 0;
            }

            bool failed() const override
            {
                return true;
            }

            const std::string& error() const override
            {
                return m_error;
            }

            long status() const override
            {
                return 503;
            }

            std::uint64_t bytesDelivered() const override
            {
                return 0;
            }

            bool abortedLocally() const override
            {
                return m_endedLocally;
            }

            const std::string& retryAfter() const override
            {
                return m_retryAfter;
            }

        private:
            bool m_endedLocally;
            std::string m_error {"the transfer failed before any data"};
            std::string m_retryAfter;
    };

    /// @brief A container engine that holds what a test puts in it.
    class FakeEngine final : public IEngineImageSource
    {
        public:
            bool listImages(std::vector<EngineImage>& out, std::string& error) override
            {
                if (!available)
                {
                    error = "connection refused";
                    return false;
                }

                out = images;
                return true;
            }

            std::unique_ptr<IBlobStream> exportImage(const std::string& id, const std::uint64_t maxBytes, std::string& error) override
            {
                exported.push_back(id);
                lastMaxBytes = maxBytes;

                if (unexportable.count(id) > 0)
                {
                    error = "no such image";
                    return nullptr;
                }

                if (refused.count(id) > 0 || idleBound.count(id) > 0)
                {
                    return std::make_unique<DeadExport>(idleBound.count(id) > 0);
                }

                const auto archive {archives.find(id)};
                return std::make_unique<MemoryExport>(archive != archives.end() ? archive->second : std::string {}, broken.count(id) > 0);
            }

            /// @brief Put an image in the engine, with the export `docker save` would give.
            void add(const std::string& id, const std::string& package, std::vector<std::string> tags = {}, std::vector<std::string> digests = {})
            {
                images.push_back({id, std::move(tags), std::move(digests)});
                archives[id] = dockerSave(id, package);
            }

            void remove(const std::string& id)
            {
                images.erase(std::remove_if(images.begin(), images.end(), [&id](const EngineImage & image)
                {
                    return image.id == id;
                }), images.end());
            }

            /// @brief The images exported, each once. An export is read in two passes, so each shows up twice in @ref exported.
            std::set<std::string> exportedIds() const
            {
                return {exported.begin(), exported.end()};
            }

            bool available {true};
            std::vector<EngineImage> images;
            std::map<std::string, std::string> archives;
            std::set<std::string> unexportable;
            std::set<std::string> broken;
            std::set<std::string> refused;   ///< Exports that fail before any data, as a restarting engine's do.
            std::set<std::string> idleBound; ///< Exports that end on the agent's own idle bound before any data.
            std::vector<std::string> exported;
            std::uint64_t lastMaxBytes {0};
    };

    std::vector<std::string> packageNames(const ImageReferenceRecord& record)
    {
        std::vector<std::string> names;

        for (const auto& package : record.packages)
        {
            names.push_back(package.name);
        }

        return names;
    }

    std::string tempDbPath()
    {
        return (std::filesystem::temp_directory_path() / (uniqueName() + ".db")).string();
    }
} // namespace

class EngineImageTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            DBSync::initialize([](const std::string&) {});
            LoggingHelper::setLogCallback([this](const modules_log_level_t level, const char* message)
            {
                std::lock_guard<std::mutex> lock {m_logMutex};

                if (level == LOG_WARNING)
                {
                    m_warnings.emplace_back(message);
                }
            });

            m_dbPath = tempDbPath();
            m_engine = std::make_shared<FakeEngine>();
            m_db = std::make_shared<ContainerImagesDB>(m_dbPath);
            m_config.references = {{ReferenceType::EngineStore, DOCKER_ENGINE}};
        }

        void TearDown() override
        {
            LoggingHelper::setLogCallback([](const modules_log_level_t, const char*) {});
            m_db.reset();
            std::filesystem::remove(m_dbPath);
        }

        /// @brief One scan of the engine, through the module's own loop and database.
        std::size_t scan()
        {
            ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
            {
                return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
            }, m_db);

            return impl.scanOnce();
        }

        /// @brief A module that lives across scans, as the real one does, so what it remembers is tested.
        std::unique_ptr<ContainerImagesImpl> module()
        {
            return std::make_unique<ContainerImagesImpl>(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
            {
                auto given {context};
                given.packageReads.options = m_databaseOptions;
                return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, given));
            }, m_db);
        }

        /// @brief Store a row for an image id as an earlier scan would have, with a configuration the
        /// engine's id does not match, so the image is not recognised and has to be exported.
        void seedStaleImage(const std::string& id)
        {
            ImageReferenceRecord record;
            record.source = {"local", std::string {DOCKER_ENGINE} + "/" + id};
            record.configDigest = idOf('0');
            record.digests = {record.configDigest};

            ImagePackageRecord package;
            package.name = "old";
            package.version = "0";
            package.architecture = "amd64";
            package.type = "deb";
            record.packages.push_back(package);

            const DeltaCallback ignore = [](ReturnTypeCallback, const std::string&, const std::string&, const std::string&, std::uint64_t) {};
            m_db->syncReferences({record}, ignore);
            m_db->syncPackages({record}, ignore);
        }

        std::vector<ImageReferenceRecord> stored()
        {
            return m_db->loadStoredEngine("local", DOCKER_ENGINE);
        }

        const ImageReferenceRecord* storedImage(const std::vector<ImageReferenceRecord>& records, const std::string& id)
        {
            for (const auto& record : records)
            {
                if (record.source.location == std::string {DOCKER_ENGINE} + "/" + id)
                {
                    return &record;
                }
            }

            return nullptr;
        }

        bool warned(const std::string& text)
        {
            std::lock_guard<std::mutex> lock {m_logMutex};

            return std::any_of(m_warnings.begin(), m_warnings.end(), [&text](const std::string & line)
            {
                return line.find(text) != std::string::npos;
            });
        }

        std::string m_dbPath;
        ContainerImagesConfig m_config;
        const PackageDb::BerkeleyDbOptions* m_databaseOptions {nullptr}; ///< How the databases are read, which a test changes to fail the read.
        std::shared_ptr<FakeEngine> m_engine;
        std::shared_ptr<ContainerImagesDB> m_db;
        std::mutex m_logMutex;
        std::vector<std::string> m_warnings;
};

TEST_F(EngineImageTest, EveryImageOfTheEngineIsOneRowKeyedByItsId)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1.25", "nginx:latest"}, {"nginx@sha256:" + std::string(64, 'd')});
    m_engine->add(idOf('b'), "wget", {"ghcr.io/owner/app:2"});

    EXPECT_EQ(scan(), 2U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 2U);

    const auto* nginx {storedImage(rows, idOf('a'))};
    ASSERT_NE(nginx, nullptr);
    EXPECT_EQ(nginx->source.sourceType, "local");
    EXPECT_EQ(nginx->source.location, "docker/" + idOf('a'));
    EXPECT_EQ(nginx->configDigest, idOf('a'));
    EXPECT_EQ(nginx->name, "docker.io/library/nginx");
    EXPECT_EQ(nginx->tags, std::vector<std::string>({"1.25", "latest"}));
    EXPECT_EQ(packageNames(*nginx), std::vector<std::string>({"curl"}));

    const auto* app {storedImage(rows, idOf('b'))};
    ASSERT_NE(app, nullptr);
    EXPECT_EQ(app->name, "ghcr.io/owner/app");
    EXPECT_EQ(app->tags, std::vector<std::string>({"2"}));
    EXPECT_EQ(packageNames(*app), std::vector<std::string>({"wget"}));
}

TEST_F(EngineImageTest, TheDigestsAreWhatTheEngineListsThenTheConfiguration)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"}, {"nginx@sha256:" + std::string(64, 'd'), "other/repo@sha256:" + std::string(64, 'e')});

    scan();

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    // The id is the configuration digest here, so it is listed once, last.
    EXPECT_EQ(rows.front().digests,
              std::vector<std::string>({"sha256:" + std::string(64, 'd'), "sha256:" + std::string(64, 'e'), idOf('a')}));
}

TEST_F(EngineImageTest, AnImageWithNoNameIsStillAnImage)
{
    // A dangling image: what a container started from it has as its image.
    m_engine->add(idOf('a'), "curl", {"<none>:<none>"});

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_TRUE(rows.front().name.empty());
    EXPECT_TRUE(rows.front().tags.empty());
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"curl"}));
}

TEST_F(EngineImageTest, AnImageAlreadyStoredIsNotExportedAgain)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->add(idOf('b'), "wget", {"app:1"});

    scan();
    ASSERT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('a'), idOf('b')}));
    m_engine->exported.clear();

    EXPECT_EQ(scan(), 2U);
    EXPECT_TRUE(m_engine->exported.empty());

    // What is stored for them is what was read, packages included.
    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 2U);
    EXPECT_EQ(packageNames(*storedImage(rows, idOf('a'))), std::vector<std::string>({"curl"}));
}

TEST_F(EngineImageTest, ARetaggedImageKeepsItsRowAndGetsTheNewNames)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    scan();
    m_engine->exported.clear();

    m_engine->images.front().repoTags = {"nginx:1", "nginx:stable"};
    m_engine->images.front().repoDigests = {"nginx@sha256:" + std::string(64, 'd')};

    EXPECT_EQ(scan(), 1U);
    EXPECT_TRUE(m_engine->exported.empty());

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().tags, std::vector<std::string>({"1", "stable"}));
    EXPECT_EQ(rows.front().digests, std::vector<std::string>({"sha256:" + std::string(64, 'd'), idOf('a')}));
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"curl"}));
}

TEST_F(EngineImageTest, AnImageIdentifiedByItsManifestIsRecognisedThroughItsDigests)
{
    // An engine whose id is not the configuration digest: the row holds the id among its digests,
    // so the image is still recognised without being exported.
    const auto manifestId {idOf('f')};
    m_engine->images.push_back({manifestId, {"app:1"}, {}});
    m_engine->archives[manifestId] = dockerSave(idOf('c'), "curl");

    scan();

    auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().configDigest, idOf('c'));
    EXPECT_NE(std::find(rows.front().digests.begin(), rows.front().digests.end(), manifestId), rows.front().digests.end());
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({manifestId}));

    m_engine->exported.clear();
    scan();

    EXPECT_TRUE(m_engine->exported.empty());
    EXPECT_EQ(stored().size(), 1U);
}

TEST_F(EngineImageTest, AnImageTheEngineNoLongerHoldsIsRemoved)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->add(idOf('b'), "wget", {"app:1"});
    scan();
    ASSERT_EQ(stored().size(), 2U);

    m_engine->remove(idOf('a'));

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().source.location, "docker/" + idOf('b'));
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"wget"}));
}

TEST_F(EngineImageTest, AnEngineThatHoldsNoImageClearsWhatWasStored)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    scan();
    ASSERT_EQ(stored().size(), 1U);

    m_engine->remove(idOf('a'));

    EXPECT_EQ(scan(), 0U);
    EXPECT_TRUE(stored().empty());
}

TEST_F(EngineImageTest, AnEngineThatCannotBeReachedKeepsWhatWasStored)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->add(idOf('b'), "wget", {"app:1"});
    scan();
    ASSERT_EQ(stored().size(), 2U);

    m_engine->available = false;

    // Nothing is known about the engine this time, which is not the same as it holding nothing.
    EXPECT_EQ(scan(), 2U);
    EXPECT_EQ(stored().size(), 2U);
    EXPECT_TRUE(warned("The 'docker' engine could not be read: connection refused."));
    EXPECT_TRUE(warned("Keeping the 2 image(s) already stored for it"));

    m_engine->available = true;
    scan();
    EXPECT_EQ(stored().size(), 2U);
}

TEST_F(EngineImageTest, AnEngineThatIsDownOnTheFirstScanStoresNothing)
{
    m_engine->available = false;

    EXPECT_EQ(scan(), 0U);
    EXPECT_TRUE(stored().empty());
}

TEST_F(EngineImageTest, AnImageThatCannotBeExportedKeepsItsStoredRow)
{
    seedStaleImage(idOf('a'));
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->unexportable.insert(idOf('a'));

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"old"}));
    EXPECT_EQ(rows.front().tags, std::vector<std::string>({"1"}));
    EXPECT_TRUE(warned("Image 'docker/" + idOf('a') + "' could not be exported: no such image."));
    EXPECT_TRUE(warned("Keeping the 1 package(s) already stored for it"));
}

TEST_F(EngineImageTest, AnImageThatCannotBeExportedAndIsNotStoredHasNoRow)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->add(idOf('b'), "wget", {"app:1"});
    m_engine->unexportable.insert(idOf('b'));

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().source.location, "docker/" + idOf('a'));
}

TEST_F(EngineImageTest, AnExportThatBreaksHalfwayIsNotStoredAsAShortInventory)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->broken.insert(idOf('a'));

    EXPECT_EQ(scan(), 0U);
    EXPECT_TRUE(stored().empty());
    EXPECT_TRUE(warned("the connection to the engine was closed"));
}

TEST_F(EngineImageTest, ABrokenExportOfAStoredImageKeepsItsPackages)
{
    seedStaleImage(idOf('a'));
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->broken.insert(idOf('a'));

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"old"}));
}

TEST_F(EngineImageTest, AnIdThatIsNotADigestIsNotAnImage)
{
    m_engine->images.push_back({"../../etc/passwd", {"x:1"}, {}});
    m_engine->add(idOf('a'), "curl", {"nginx:1"});

    EXPECT_EQ(scan(), 1U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('a')}));
}

TEST_F(EngineImageTest, AnImageListedTwiceIsReadOnce)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->images.push_back(m_engine->images.front());

    EXPECT_EQ(scan(), 1U);
    EXPECT_EQ(m_engine->exported.size(), 2U);
}

TEST_F(EngineImageTest, TheExportIsBoundedByTheImageAllowanceAndTheFramingOfTheTar)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_config.limits.maxImageBytes = 1000000;

    scan();

    // A quarter and 16 MiB on top of the allowance: the export is a tar, so it is larger than the image.
    EXPECT_EQ(m_engine->lastMaxBytes, 1000000U + 250000U + 16U * 1024 * 1024);
    EXPECT_GT(m_engine->lastMaxBytes, m_config.limits.maxImageBytes);
}

TEST_F(EngineImageTest, TheExportBoundSaturatesInsteadOfOverflowing)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_config.limits.maxImageBytes = std::numeric_limits<std::uint64_t>::max();

    scan();

    EXPECT_EQ(m_engine->lastMaxBytes, std::numeric_limits<std::uint64_t>::max());
}

TEST_F(EngineImageTest, AnImageAtTheAllowanceIsExportedAndOneByteOverIsNot)
{
    m_config.limits.maxImageBytes = 1000;
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->images.back().size = 1000;
    m_engine->add(idOf('b'), "wget", {"app:1"});
    m_engine->images.back().size = 1001;

    EXPECT_EQ(scan(), 1U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('a')}));
}

TEST_F(EngineImageTest, TheImageIsChargedToTheScanOnceAndNotForEachPassOfItsExport)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_config.limits.maxScanBytes = std::numeric_limits<std::uint64_t>::max();

    std::uint64_t bytes {0};
    ReaderContext context;
    context.config = &m_config;
    context.scanBytes = &bytes;

    EngineImageReader reader {DOCKER_ENGINE, m_engine, context};

    EXPECT_EQ(reader.discover().status, ReadStatus::Success);
    EXPECT_EQ(m_engine->exported.size(), 2U);
    // One pass of the export, which is at most the export: both passes would be nearly twice that.
    EXPECT_GT(bytes, 0U);
    EXPECT_LE(bytes, m_engine->archives.at(idOf('a')).size());
}

#ifdef __linux__
namespace
{
    /// @brief A read of a Berkeley DB database that hangs, with a deadline short enough to wait for.
    PackageDb::BerkeleyDbOptions hangingRead()
    {
        PackageDb::BerkeleyDbOptions options;
        options.deadline = std::chrono::milliseconds {100};
        options.child = [](const std::string&, const std::string&) -> std::string
        {
            while (true)
            {
                pause();
            }
        };

        return options;
    }
}

TEST_F(EngineImageTest, ADatabaseThatTimedOutKeepsTheStoredRowAndTheImageIsExportedAgainAtOnce)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    seedStaleImage(idOf('a'));
    m_engine->archives[idOf('a')] = dockerSaveWithBerkeleyDb(idOf('a'));

    const auto hangs {hangingRead()};
    m_databaseOptions = &hangs;
    const auto engine {module()};

    // Scan after scan, the stored row is what it was and the export is made again: nothing holds it back.
    for (std::size_t scan = 1; scan <= 2; ++scan)
    {
        engine->scanOnce();

        const auto rows {stored()};
        const auto* image {storedImage(rows, idOf('a'))};

        ASSERT_NE(image, nullptr) << scan;
        EXPECT_EQ(packageNames(*image), std::vector<std::string>({"old"})) << scan;
        EXPECT_EQ(m_engine->exported.size(), 2 * scan) << "the image was not exported again, so a back-off was armed";
        EXPECT_TRUE(warned("It will be read again on the next scan"));
    }
}

TEST_F(EngineImageTest, AnImageNothingIsStoredForIsExportedAgainAtOnceWhenItsDatabaseTimedOut)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->archives[idOf('a')] = dockerSaveWithBerkeleyDb(idOf('a'));

    const auto hangs {hangingRead()};
    m_databaseOptions = &hangs;
    const auto engine {module()};

    engine->scanOnce();
    EXPECT_TRUE(stored().empty());
    EXPECT_EQ(m_engine->exported.size(), 2U);

    engine->scanOnce();
    EXPECT_TRUE(stored().empty());
    EXPECT_EQ(m_engine->exported.size(), 4U);

    // The database reads well once the machine allows it, and the image is stored then.
    m_databaseOptions = nullptr;
    engine->scanOnce();

    const auto rows {stored()};
    ASSERT_NE(storedImage(rows, idOf('a')), nullptr);
    EXPECT_EQ(packageNames(*storedImage(rows, idOf('a'))), std::vector<std::string>({"bash"}));
    EXPECT_EQ(m_engine->exported.size(), 6U);
}

TEST_F(EngineImageTest, TheFailuresOfAnImageTheEngineNoLongerListsAreForgotten)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->archives[idOf('a')] = dockerSaveWithBerkeleyDb(idOf('a'));

    const auto hangs {hangingRead()};
    ReadFailures failures;
    // A registry reference that reads like an image of the engine is not one of them.
    failures.entries["ref:docker/getting-started@sha256:other"].count = 1;

    ReaderContext context;
    context.config = &m_config;
    context.packageReads.failures = &failures;
    context.packageReads.options = &hangs;

    EngineImageReader first {DOCKER_ENGINE, m_engine, context};
    first.discover();
    const auto countOf = [&failures](const std::string & prefix)
    {
        return std::count_if(failures.entries.begin(), failures.entries.end(), [&prefix](const auto & entry)
        {
            return entry.first.rfind(prefix, 0) == 0;
        });
    };

    EXPECT_EQ(countOf("local:docker/" + idOf('a') + "@"), 1);

    // The image is gone from the engine, and the count with it. What belongs to another reference stays.
    m_engine->remove(idOf('a'));
    EngineImageReader second {DOCKER_ENGINE, m_engine, context};
    second.discover();

    EXPECT_EQ(countOf("local:docker/" + idOf('a') + "@"), 0);
    EXPECT_EQ(countOf("ref:docker/getting-started@"), 1);
}

TEST_F(EngineImageTest, AnImageWhoseDatabaseTimesOutThreeTimesInARowIsStoredWithoutIt)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->archives[idOf('a')] = dockerSaveWithBerkeleyDb(idOf('a'));

    const auto hangs {hangingRead()};
    m_databaseOptions = &hangs;
    const auto engine {module()};

    engine->scanOnce();
    engine->scanOnce();
    EXPECT_TRUE(stored().empty());

    engine->scanOnce();

    const auto rows {stored()};
    ASSERT_NE(storedImage(rows, idOf('a')), nullptr);
    EXPECT_TRUE(storedImage(rows, idOf('a'))->packages.empty());
    EXPECT_TRUE(warned("3 times in a row. It will not be read again until the image changes"));

    // It is the image stored now, so it is not exported again.
    engine->scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 6U);
}

TEST_F(EngineImageTest, AnImageWhoseDatabaseCannotBeReadForTheHostThreeTimesInARowIsLeftAloneUntilARestart)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    seedStaleImage(idOf('a'));
    m_engine->archives[idOf('a')] = dockerSaveWithBerkeleyDb(idOf('a'));

    // A child ended from outside, as the out-of-memory killer does.
    PackageDb::BerkeleyDbOptions killed;
    killed.child = [](const std::string&, const std::string&) -> std::string
    {
        std::signal(SIGKILL, SIG_DFL);
        std::raise(SIGKILL);
        return {};
    };

    m_databaseOptions = &killed;
    auto engine {module()};

    for (std::size_t scan = 1; scan <= MAX_TRANSIENT_READS; ++scan)
    {
        engine->scanOnce();

        const auto rows {stored()};
        ASSERT_NE(storedImage(rows, idOf('a')), nullptr) << scan;
        EXPECT_EQ(packageNames(*storedImage(rows, idOf('a'))), std::vector<std::string>({"old"})) << "what is stored stays: " << scan;
        EXPECT_EQ(m_engine->exported.size(), 2 * scan);
    }

    EXPECT_TRUE(warned("The image is not read again until the agent is restarted or its configuration changes"));

    // Left alone: not exported, though the host would read it now.
    m_databaseOptions = nullptr;
    engine->scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 2 * MAX_TRANSIENT_READS);

    // A restart builds a module with nothing remembered, and the image is read and stored.
    engine = module();
    engine->scanOnce();

    const auto rows {stored()};
    ASSERT_NE(storedImage(rows, idOf('a')), nullptr);
    EXPECT_EQ(packageNames(*storedImage(rows, idOf('a'))), std::vector<std::string>({"bash"}));
    EXPECT_EQ(m_engine->exported.size(), 2 * MAX_TRANSIENT_READS + 2);
}
#endif

TEST_F(EngineImageTest, ARowKeptBecauseTheScanAllowanceWasReachedIsReadAgainByTheNextScan)
{
    // A row that does not hold the engine's id in its digests, as one upgraded from an earlier schema.
    m_engine->add(idOf('b'), "wget", {"app:1"});
    m_engine->images.back().size = 10;
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->images.back().size = 20;
    seedStaleImage(idOf('a'));
    m_config.limits.maxScanBytes = 1;

    // The first image spends the allowance, so the stored row of the other is kept as it is.
    scan();

    {
        const auto rows {stored()};
        const auto* kept {storedImage(rows, idOf('a'))};

        ASSERT_NE(kept, nullptr);
        EXPECT_EQ(packageNames(*kept), std::vector<std::string>({"old"}));
        EXPECT_EQ(std::count(kept->digests.begin(), kept->digests.end(), idOf('a')), 0)
                << "the id of the engine in the digests makes the next scan take the row for the image";
    }

    m_engine->exported.clear();
    scan();

    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('a')}));

    const auto rows {stored()};
    ASSERT_NE(storedImage(rows, idOf('a')), nullptr);
    EXPECT_EQ(packageNames(*storedImage(rows, idOf('a'))), std::vector<std::string>({"curl"}));
}

TEST_F(EngineImageTest, TheScanAllowanceStopsTheImagesStillToExport)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->add(idOf('b'), "wget", {"app:1"});
    m_engine->add(idOf('c'), "git", {"tool:1"});
    m_config.limits.maxScanBytes = 1;

    // The first export is read twice and spends the allowance, so no other image is started.
    EXPECT_EQ(scan(), 1U);
    EXPECT_EQ(m_engine->exported.size(), 2U);
    EXPECT_TRUE(warned("this scan already reached its 1 byte allowance"));
}

TEST_F(EngineImageTest, AStopRequestEndsTheReadWithoutAResult)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    std::atomic<bool> stop {true};

    ReaderContext context;
    context.stopRequested = &stop;

    EngineImageReader reader {DOCKER_ENGINE, m_engine, context};

    EXPECT_EQ(reader.discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_engine->exported.empty());
}

TEST_F(EngineImageTest, TheReaderIsOfTheLocalType)
{
    EngineImageReader reader {DOCKER_ENGINE, m_engine, {}};

    EXPECT_EQ(reader.sourceType(), "local");
}

TEST_F(EngineImageTest, ImagesOverTheAllowanceAreNotExportedAndDoNotStarveTheOthers)
{
    // Four big images listed first, as an engine lists the newest first, would spend the whole scan
    // allowance on exports that fail and are stored nowhere.
    m_config.limits.maxImageBytes = 1000;

    for (const char letter :
            {'1', '2', '3', '4'
            })
    {
        m_engine->add(idOf(letter), "big", {"big:" + std::string(1, letter)});
        m_engine->images.back().size = 5000;
    }

    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->images.back().size = 10;
    m_engine->add(idOf('b'), "wget", {"app:1"});
    m_engine->images.back().size = 10;

    EXPECT_EQ(scan(), 2U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('a'), idOf('b')}));
    EXPECT_EQ(stored().size(), 2U);
    EXPECT_FALSE(warned("this scan already reached"));
}

TEST_F(EngineImageTest, TheOversizeWarningIsOncePerImageNotOncePerScan)
{
    m_config.limits.maxImageBytes = 1000;
    m_engine->add(idOf('1'), "big", {"big:1"});
    m_engine->images.back().size = 5000;
    m_engine->add(idOf('2'), "big", {"big:2"});
    m_engine->images.back().size = 5000;

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    const auto count = [this]
    {
        std::lock_guard<std::mutex> lock {m_logMutex};
        return std::count_if(m_warnings.begin(), m_warnings.end(), [](const std::string & line)
        {
            return line.find("was not read: the engine reports 5000 bytes") != std::string::npos;
        });
    };

    impl.scanOnce();
    EXPECT_EQ(count(), 2);
    impl.scanOnce();
    EXPECT_EQ(count(), 2);

    // An image the engine stops listing is forgotten, so it is said again if it comes back.
    m_engine->remove(idOf('1'));
    impl.scanOnce();
    m_engine->add(idOf('1'), "big", {"big:1"});
    m_engine->images.back().size = 5000;
    impl.scanOnce();
    EXPECT_EQ(count(), 3);
    EXPECT_TRUE(m_engine->exported.empty());
}

TEST_F(EngineImageTest, AnImageWhoseExportFailedIsNotExportedAgainAndKeepsItsRow)
{
    seedStaleImage(idOf('a'));
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->broken.insert(idOf('a'));
    m_engine->add(idOf('b'), "wget", {"app:1"});

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    const auto exports = [this](const std::string & id)
    {
        return std::count(m_engine->exported.begin(), m_engine->exported.end(), id);
    };

    EXPECT_EQ(impl.scanOnce(), 2U);
    EXPECT_EQ(exports(idOf('a')), 1);

    EXPECT_EQ(impl.scanOnce(), 2U);
    EXPECT_EQ(exports(idOf('a')), 1) << "the failed image is not asked of the engine again";

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 2U);
    ASSERT_NE(storedImage(rows, idOf('a')), nullptr);
    EXPECT_EQ(packageNames(*storedImage(rows, idOf('a'))), std::vector<std::string>({"old"}));

    std::lock_guard<std::mutex> lock {m_logMutex};
    EXPECT_EQ(std::count_if(m_warnings.begin(), m_warnings.end(), [](const std::string & line)
    {
        return line.find("will not be exported again") != std::string::npos;
    }), 1) << "said once per image";
}

TEST_F(EngineImageTest, AFailedExportOnlyStarvesTheImagesAfterItInTheScanItFailsIn)
{
    // The failed export is charged to the scan and spends the whole allowance, so the image after it is
    // not started. The next scan skips the failed one and reads the rest.
    m_config.limits.maxScanBytes = 1;
    m_engine->add(idOf('1'), "big", {"big:1"});
    m_engine->broken.insert(idOf('1'));
    m_engine->add(idOf('a'), "curl", {"nginx:1"});

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('1')}));

    EXPECT_EQ(impl.scanOnce(), 1U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('1'), idOf('a')}));
    EXPECT_EQ(stored().size(), 1U);
}

TEST_F(EngineImageTest, AnImageTheEngineStopsListingIsTriedAgainWhenItComesBack)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->broken.insert(idOf('a'));

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    impl.scanOnce();
    impl.scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 1U);

    const auto image {m_engine->images.front()};
    m_engine->remove(idOf('a'));
    impl.scanOnce();
    m_engine->images.push_back(image);
    impl.scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 2U);
}

TEST_F(EngineImageTest, AnExportThatNeverStartedIsTriedAgainByTheNextScan)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->unexportable.insert(idOf('a'));

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    impl.scanOnce();
    m_engine->unexportable.clear();

    EXPECT_EQ(impl.scanOnce(), 1U);
    EXPECT_EQ(m_engine->exported.size(), 3U);
}

TEST_F(EngineImageTest, AnExportThatFailedBeforeAnyDataIsTriedAgainByTheNextScan)
{
    // A refused connection or a 5xx, as while the engine restarts, says nothing about the image.
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->refused.insert(idOf('a'));

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    impl.scanOnce();
    impl.scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 2U);
    EXPECT_FALSE(warned("will not be exported again"));

    m_engine->refused.clear();
    EXPECT_EQ(impl.scanOnce(), 1U);
}

TEST_F(EngineImageTest, AnExportEndedByTheAgentsOwnBoundIsHeldBackEvenWithNoData)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->idleBound.insert(idOf('a'));

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    impl.scanOnce();
    impl.scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 1U);
    EXPECT_TRUE(warned("will not be exported again for 6 scans."));
}

TEST_F(EngineImageTest, AFailedExportIsTriedAgainAfterTheScansThatSkipIt)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->broken.insert(idOf('a'));

    std::map<std::string, unsigned> failed;
    ReaderContext context;
    context.failedExportImages = &failed;
    context.failedExportRetryScans = 2;

    const auto scanOnce = [&]
    {
        EngineImageReader {DOCKER_ENGINE, m_engine, context}.discover();
    };

    scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 1U);
    EXPECT_EQ(failed.at(idOf('a')), 0U);

    scanOnce();
    scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 1U) << "the two scans that skip it do not export";
    EXPECT_EQ(failed.at(idOf('a')), 2U);

    scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 2U) << "the next one tries again, and fails again";
    EXPECT_EQ(failed.at(idOf('a')), 0U);

    m_engine->broken.clear();
    scanOnce();
    scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 2U);
    scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 4U) << "read in both passes once it works";
    EXPECT_TRUE(failed.empty());
}

TEST_F(EngineImageTest, ByDefaultAFailedExportIsSkippedForSixScans)
{
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->broken.insert(idOf('a'));

    ContainerImagesImpl impl(m_config, [this](const ConfiguredReference & reference, const std::string&, const ReaderContext & context)
    {
        return std::unique_ptr<IImageReader>(std::make_unique<EngineImageReader>(reference.location, m_engine, context));
    }, m_db);

    for (int scan {0}; scan < 7; ++scan)
    {
        impl.scanOnce();
    }

    EXPECT_EQ(m_engine->exported.size(), 1U) << "the failing scan and the six that skip it";

    impl.scanOnce();
    EXPECT_EQ(m_engine->exported.size(), 2U);
}

TEST_F(EngineImageTest, TheSmallestImagesAreReadFirstSoALargeFailureDoesNotStarveThem)
{
    // The engine lists the large image that fails first. Read in that order its export would spend the scan
    // allowance, and the small image would wait for the next scan.
    m_config.limits.maxScanBytes = 1;
    m_engine->add(idOf('1'), "big", {"big:1"});
    m_engine->images.back().size = 5000;
    m_engine->broken.insert(idOf('1'));
    m_engine->add(idOf('a'), "curl", {"nginx:1"});
    m_engine->images.back().size = 10;

    EXPECT_EQ(scan(), 1U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('a')}));
    EXPECT_NE(storedImage(stored(), idOf('a')), nullptr);
}

TEST_F(EngineImageTest, ImagesOfEqualSizeKeepTheOrderTheEngineListedThem)
{
    m_config.limits.maxScanBytes = 1;
    m_engine->add(idOf('b'), "wget", {"app:1"});
    m_engine->add(idOf('a'), "curl", {"nginx:1"});

    // The first image spends the allowance, so which one it was shows the order.
    EXPECT_EQ(scan(), 1U);
    EXPECT_EQ(m_engine->exportedIds(), std::set<std::string>({idOf('b')}));
}

TEST_F(EngineImageTest, AnExportOfSeveralPlatformsIsReadAsTheAgentsPlatform)
{
    const auto target {detectTargetPlatform()};

    if (target.architecture.empty())
    {
        GTEST_SKIP() << "no architecture is detected on this platform";
    }

    m_engine->images.push_back({idOf('a'), {"app:1"}, {}});
    m_engine->archives[idOf('a')] = dockerSaveTwoPlatforms("not-this-architecture", target.architecture);

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"second"}));
    EXPECT_EQ(rows.front().architecture, target.architecture);
    EXPECT_EQ(rows.front().configDigest, "sha256:" + std::string(64, '2'));
}

TEST_F(EngineImageTest, AnExportWithNoPlatformOfTheAgentsIsReadAsItsFirst)
{
    m_engine->images.push_back({idOf('a'), {"app:1"}, {}});
    m_engine->archives[idOf('a')] = dockerSaveTwoPlatforms("not-this-architecture", "nor-this-one");

    EXPECT_EQ(scan(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"first"}));
}

TEST_F(EngineImageTest, AnImagePulledByDigestIsNamedByItsRepository)
{
    // `docker pull nginx@sha256:...` leaves no tag, only the repository in the digest name.
    m_engine->add(idOf('a'), "curl", {}, {"nginx@sha256:" + std::string(64, 'd')});

    scan();

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows.front().name, "docker.io/library/nginx");
    EXPECT_TRUE(rows.front().tags.empty());
}

TEST_F(EngineImageTest, ATagStillNamesTheImageBeforeItsDigest)
{
    m_engine->add(idOf('a'), "curl", {"ghcr.io/owner/app:2"}, {"other/repo@sha256:" + std::string(64, 'd')});

    scan();

    ASSERT_EQ(stored().size(), 1U);
    EXPECT_EQ(stored().front().name, "ghcr.io/owner/app");
}

TEST(EngineDigestTest, AnImageIdIsAFullLowerCaseHexDigest)
{
    EXPECT_TRUE(oci::isHexDigest("sha256:" + std::string(64, 'a')));
    EXPECT_TRUE(oci::isHexDigest("sha512:" + std::string(128, '0')));
    EXPECT_FALSE(oci::isHexDigest("sha256:" + std::string(63, 'a')));
    EXPECT_FALSE(oci::isHexDigest("sha256:" + std::string(64, 'A')));
    EXPECT_FALSE(oci::isHexDigest("sha256:" + std::string(63, 'a') + "="));
    EXPECT_FALSE(oci::isHexDigest("md5:" + std::string(32, 'a')));
    EXPECT_FALSE(oci::isHexDigest("sha256:" + std::string(60, 'a') + "/get"));
    EXPECT_FALSE(oci::isHexDigest(std::string(64, 'a')));
}

// ---------------------------------------------------------------------------
// The reader the module builds for a `<local>` reference.
// ---------------------------------------------------------------------------

TEST_F(EngineImageTest, AnEngineNameTheModuleDoesNotKnowBuildsNoReader)
{
    ContainerImagesConfig config;
    config.dockerSocket = "/var/run/docker.sock";
    const ReaderContext context {&config, nullptr, nullptr};

    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "podman"}, {}, context), nullptr);
    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "kubernetes"}, {}, context), nullptr);
    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "alpine:latest"}, {}, context), nullptr);
}

#if defined(__linux__)
TEST_F(EngineImageTest, TheDockerEngineBuildsAReaderOnlyWithItsSocket)
{
    ContainerImagesConfig withSocket;
    withSocket.dockerSocket = "/var/run/docker.sock";
    const ReaderContext context {&withSocket, nullptr, nullptr};

    const auto reader {makeReader({ReferenceType::EngineStore, "docker"}, {}, context)};
    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(reader->sourceType(), "local");

    ContainerImagesConfig withoutSocket;
    const ReaderContext bare {&withoutSocket, nullptr, nullptr};

    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "docker"}, {}, bare), nullptr);
    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "docker"}, {}, {}), nullptr);
    EXPECT_TRUE(warned("has no Docker socket to read from"));
}
#else
TEST_F(EngineImageTest, ThereIsNoEngineReaderOutsideLinux)
{
    ContainerImagesConfig config;
    config.dockerSocket = "/var/run/docker.sock";
    const ReaderContext context {&config, nullptr, nullptr};

    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "docker"}, {}, context), nullptr);
}
#endif

#if defined(__linux__)
// ---------------------------------------------------------------------------
// The Docker Engine API client, with a transport that answers from memory.
// ---------------------------------------------------------------------------

namespace
{
    class ScriptedTransport final : public IRegistryTransport
    {
        public:
            bool get(const std::string& url, const std::vector<std::string>& headers, HttpResponse& response, std::string& error) override
            {
                urls.push_back(url);
                requestHeaders = headers;

                if (!answers)
                {
                    error = "Couldn't connect to server";
                    return false;
                }

                response = reply;
                return true;
            }

            bool getWithBasicAuth(const std::string&, const std::vector<std::string>&, const std::string&, const Secret&, HttpResponse&, std::string&) override
            {
                return false;
            }

            bool answers {true};
            HttpResponse reply;
            std::vector<std::string> urls;
            std::vector<std::string> requestHeaders;
    };

    /// @brief A path that exists and is a socket on the host, whatever answers behind it: the transport is scripted.
    class SocketPath
    {
        public:
            SocketPath()
                : m_path {std::filesystem::temp_directory_path() / (uniqueName() + ".sock")}
            {
                m_descriptor = ::socket(AF_UNIX, SOCK_STREAM, 0);
                sockaddr_un address {};
                address.sun_family = AF_UNIX;
                std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", m_path.c_str());

                if (::bind(m_descriptor, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
                        ::listen(m_descriptor, 8) != 0)
                {
                    throw std::runtime_error("the test socket could not be created");
                }
            }

            ~SocketPath()
            {
                ::close(m_descriptor);
                std::filesystem::remove(m_path);
            }

            SocketPath(const SocketPath&) = delete;
            SocketPath& operator=(const SocketPath&) = delete;

            std::string path() const
            {
                return m_path.string();
            }

            int descriptor() const
            {
                return m_descriptor;
            }

        private:
            std::filesystem::path m_path;
            int m_descriptor {-1};
    };
} // namespace

class DockerImageSourceTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            LoggingHelper::setLogCallback([](const modules_log_level_t, const char*) {});
        }

        DockerImageSource make(ScriptedTransport*& transport, std::string& exportUrl, std::vector<std::string>& exportHeaders)
        {
            auto scripted {std::make_unique<ScriptedTransport>()};
            transport = scripted.get();

            return DockerImageSource {m_socket.path(), std::move(scripted),
                                      [&exportUrl, &exportHeaders](const TransportConfig&, const std::string & url,
                                                                   const std::vector<std::string>& headers, std::uint64_t,
                                                                   const std::atomic<bool>*) -> std::unique_ptr<IBlobStream>
            {
                exportUrl = url;
                exportHeaders = headers;
                return std::make_unique<MemoryExport>("tar", false);
            }, TransportConfig {}};
        }

        SocketPath m_socket;
};

TEST_F(DockerImageSourceTest, ImagesAreListedFromTheEngineApi)
{
    ScriptedTransport* transport {nullptr};
    std::string exportUrl;
    std::vector<std::string> exportHeaders;
    auto source {make(transport, exportUrl, exportHeaders)};

    transport->reply.status = 200;
    transport->reply.body = R"([
        {"Id":"sha256:aaa","RepoTags":["nginx:1","nginx:latest"],"RepoDigests":["nginx@sha256:bbb"],"Size":1},
        {"Id":"sha256:ccc","RepoTags":null,"RepoDigests":null},
        {"RepoTags":["no-id:1"]},
        "not an object"])";

    std::vector<EngineImage> images;
    std::string error;

    ASSERT_TRUE(source.listImages(images, error)) << error;
    ASSERT_EQ(images.size(), 2U);
    EXPECT_EQ(images[0].id, "sha256:aaa");
    EXPECT_EQ(images[0].repoTags, std::vector<std::string>({"nginx:1", "nginx:latest"}));
    EXPECT_EQ(images[0].repoDigests, std::vector<std::string>({"nginx@sha256:bbb"}));
    EXPECT_EQ(images[0].size, 1U);
    EXPECT_EQ(images[1].size, 0U);
    EXPECT_EQ(images[1].id, "sha256:ccc");
    EXPECT_TRUE(images[1].repoTags.empty());
    EXPECT_TRUE(images[1].repoDigests.empty());
    EXPECT_EQ(transport->urls, std::vector<std::string>({"http://localhost/images/json"}));
}

TEST_F(DockerImageSourceTest, AnEmptyEngineIsASuccess)
{
    ScriptedTransport* transport {nullptr};
    std::string exportUrl;
    std::vector<std::string> exportHeaders;
    auto source {make(transport, exportUrl, exportHeaders)};

    transport->reply.status = 200;
    transport->reply.body = "[]";

    std::vector<EngineImage> images {{"stale", {}, {}}};
    std::string error;

    EXPECT_TRUE(source.listImages(images, error));
    EXPECT_TRUE(images.empty());
}

TEST_F(DockerImageSourceTest, AnAnswerThatIsNotAListOfImagesFails)
{
    ScriptedTransport* transport {nullptr};
    std::string exportUrl;
    std::vector<std::string> exportHeaders;
    auto source {make(transport, exportUrl, exportHeaders)};
    std::vector<EngineImage> images;
    std::string error;

    transport->reply.status = 500;
    transport->reply.body = R"({"message":"boom"})";
    EXPECT_FALSE(source.listImages(images, error));
    EXPECT_EQ(error, "the engine answered 500 to the list of images");

    transport->reply.status = 200;
    transport->reply.body = R"({"message":"not a list"})";
    EXPECT_FALSE(source.listImages(images, error));
    EXPECT_EQ(error, "the engine's list of images is not a JSON list");

    transport->answers = false;
    EXPECT_FALSE(source.listImages(images, error));
    EXPECT_EQ(error, "the list of images could not be requested: Couldn't connect to server");
}

TEST_F(DockerImageSourceTest, AnImageIsExportedFromItsOwnPath)
{
    ScriptedTransport* transport {nullptr};
    std::string exportUrl;
    std::vector<std::string> exportHeaders;
    auto source {make(transport, exportUrl, exportHeaders)};
    std::string error;

    const auto stream {source.exportImage(idOf('a'), 1000, error)};

    ASSERT_NE(stream, nullptr) << error;
    EXPECT_EQ(exportUrl, "http://localhost/images/" + idOf('a') + "/get");
    EXPECT_EQ(exportHeaders, std::vector<std::string>({"Accept: application/x-tar"}));
}

TEST_F(DockerImageSourceTest, OnlyADigestIsPutIntoTheExportPath)
{
    ScriptedTransport* transport {nullptr};
    std::string exportUrl;
    std::vector<std::string> exportHeaders;
    auto source {make(transport, exportUrl, exportHeaders)};
    std::string error;

    EXPECT_EQ(source.exportImage("../../containers/json", 1000, error), nullptr);
    EXPECT_NE(error.find("is not an image id"), std::string::npos);
    EXPECT_EQ(source.exportImage("sha256:abc/get?x=1", 1000, error), nullptr);
    EXPECT_TRUE(exportUrl.empty());
}

TEST(DockerSocketTest, ASocketThatIsNotThereNamesWhatIsMissing)
{
    ContainerImagesConfig config;
    DockerImageSource source {(std::filesystem::temp_directory_path() / (uniqueName() + ".sock")).string(), config};
    std::vector<EngineImage> images;
    std::string error;

    EXPECT_FALSE(source.listImages(images, error));
    EXPECT_NE(error.find("does not exist, so the engine is not running or is configured elsewhere"), std::string::npos) << error;

    EXPECT_EQ(source.exportImage(idOf('a'), 1000, error), nullptr);
    EXPECT_NE(error.find("does not exist"), std::string::npos);
}

TEST(DockerSocketTest, ASocketBehindADirectoryTheAgentCannotReachIsReportedAsPermissionDenied)
{
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "root can reach any directory";
    }

    const auto directory {std::filesystem::temp_directory_path() / uniqueName()};
    std::filesystem::create_directories(directory);
    ::chmod(directory.c_str(), 0);

    ContainerImagesConfig config;
    DockerImageSource source {(directory / "docker.sock").string(), config};
    std::vector<EngineImage> images;
    std::string error;

    EXPECT_FALSE(source.listImages(images, error));
    EXPECT_NE(error.find("permission denied on the Docker socket"), std::string::npos) << error;

    ::chmod(directory.c_str(), 0700);
    std::filesystem::remove_all(directory);
}

TEST(DockerSocketTest, APathThatIsNotASocketIsRefused)
{
    const auto file {std::filesystem::temp_directory_path() / (uniqueName() + ".txt")};
    std::ofstream {file} << "not a socket";

    ContainerImagesConfig config;
    DockerImageSource source {file.string(), config};
    std::vector<EngineImage> images;
    std::string error;

    EXPECT_FALSE(source.listImages(images, error));
    EXPECT_NE(error.find("is not a Unix socket"), std::string::npos) << error;

    std::filesystem::remove(file);
}

// ---------------------------------------------------------------------------
// The real transport against a stand-in daemon on a Unix socket: no engine is involved, but the
// socket, the plain http request and the streamed export are the real ones.
// ---------------------------------------------------------------------------

namespace
{
    /// @brief Answers the two Docker Engine API calls the module makes, one connection at a time.
    class FakeDockerDaemon
    {
        public:
            FakeDockerDaemon(const int listener, std::string list, std::map<std::string, std::string> archives)
                : m_listener {listener}
                , m_list {std::move(list)}
                , m_archives {std::move(archives)}
                , m_thread {[this] { serve(); }}
            {
            }

            ~FakeDockerDaemon()
            {
                m_stop = true;
                m_thread.join();
            }

            std::vector<std::string> requests()
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                return m_requests;
            }

            /// @brief Hold every export back before its first byte, as an engine does while it builds the archive.
            void delayExports(const int milliseconds)
            {
                m_exportDelayMs = milliseconds;
            }

            /// @brief Send only the first bytes of every export, then go quiet for a while before closing it.
            void stallExports(const int bytes, const int milliseconds)
            {
                m_stallAfterBytes = bytes;
                m_stallMs = milliseconds;
            }

        private:
            void serve()
            {
                while (!m_stop)
                {
                    pollfd waiting {m_listener, POLLIN, 0};

                    if (::poll(&waiting, 1, 50) <= 0)
                    {
                        continue;
                    }

                    const int connection {::accept(m_listener, nullptr, nullptr)};

                    if (connection < 0)
                    {
                        continue;
                    }

                    answer(connection);
                    ::close(connection);
                }
            }

            void answer(const int connection)
            {
                std::string request;
                char buffer[1024];

                while (request.find("\r\n\r\n") == std::string::npos)
                {
                    const auto count {::read(connection, buffer, sizeof(buffer))};

                    if (count <= 0)
                    {
                        return;
                    }

                    request.append(buffer, static_cast<std::size_t>(count));
                }

                const auto line {request.substr(0, request.find("\r\n"))};

                {
                    std::lock_guard<std::mutex> lock {m_mutex};
                    m_requests.push_back(line);
                }

                std::string body;
                std::string status {"200 OK"};
                bool isExport {false};

                if (line == "GET /images/json HTTP/1.1")
                {
                    body = m_list;
                }
                else
                {
                    status = "404 Not Found";
                    body = R"({"message":"no such image"})";

                    for (const auto& archive : m_archives)
                    {
                        if (line == "GET /images/" + archive.first + "/get HTTP/1.1")
                        {
                            status = "200 OK";
                            body = archive.second;
                            isExport = true;

                            for (int waited {0}; waited < m_exportDelayMs && !m_stop; waited += 50)
                            {
                                std::this_thread::sleep_for(std::chrono::milliseconds {50});
                            }
                        }
                    }
                }

                const auto response {"HTTP/1.1 " + status + "\r\nContent-Length: " + std::to_string(body.size()) +
                                     "\r\nConnection: close\r\n\r\n" + body};

                const bool stalls = isExport && m_stallAfterBytes >= 0;
                const auto end {stalls ? std::min(response.size(), response.size() - body.size() + static_cast<std::size_t>(m_stallAfterBytes))
                                : response.size()};
                std::size_t sent {0};

                while (sent < end)
                {
                    const auto count {::send(connection, response.data() + sent, end - sent, MSG_NOSIGNAL)};

                    if (count <= 0)
                    {
                        return;
                    }

                    sent += static_cast<std::size_t>(count);
                }

                for (int waited {0}; stalls && waited < m_stallMs && !m_stop; waited += 50)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds {50});
                }
            }

            int m_listener;
            std::string m_list;
            std::map<std::string, std::string> m_archives;
            std::atomic<bool> m_stop {false};
            std::atomic<int> m_exportDelayMs {0};
            std::atomic<int> m_stallAfterBytes {-1};
            std::atomic<int> m_stallMs {0};
            std::mutex m_mutex;
            std::vector<std::string> m_requests;
            std::thread m_thread;
    };
} // namespace

TEST_F(EngineImageTest, TheRealTransportReadsImagesFromAUnixSocket)
{
    SocketPath socket;
    const auto list {R"([{"Id":")" + idOf('a') + R"(","RepoTags":["nginx:1"],"RepoDigests":["nginx@sha256:)" + std::string(64, 'd') +
                     R"("]},{"Id":")" + idOf('b') + R"(","RepoTags":null,"RepoDigests":null}])"};
    FakeDockerDaemon daemon {socket.descriptor(), list, {{idOf('a'), dockerSave(idOf('a'), "curl")}, {idOf('b'), dockerSave(idOf('b'), "wget")}}};

    ContainerImagesConfig config;
    config.references = {{ReferenceType::EngineStore, DOCKER_ENGINE}};
    config.dockerSocket = socket.path();

    ContainerImagesImpl impl(config, makeReader, m_db);

    EXPECT_EQ(impl.scanOnce(), 2U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 2U);

    const auto* nginx {storedImage(rows, idOf('a'))};
    ASSERT_NE(nginx, nullptr);
    EXPECT_EQ(nginx->name, "docker.io/library/nginx");
    EXPECT_EQ(nginx->tags, std::vector<std::string>({"1"}));
    EXPECT_EQ(packageNames(*nginx), std::vector<std::string>({"curl"}));
    EXPECT_EQ(nginx->os, "linux");

    const auto requests {daemon.requests()};
    EXPECT_EQ(requests.front(), "GET /images/json HTTP/1.1");
    // The export is read twice, for the metadata and for the layers.
    EXPECT_EQ(std::count(requests.begin(), requests.end(), "GET /images/" + idOf('a') + "/get HTTP/1.1"), 2);

    // The second scan lists, and exports nothing: the ids are the ones stored.
    const auto before {requests.size()};
    EXPECT_EQ(impl.scanOnce(), 2U);
    EXPECT_EQ(daemon.requests().size(), before + 1);
}

TEST_F(EngineImageTest, AnExportThatTakesLongerThanTheRequestTimeoutToStartIsStillRead)
{
    // A large image takes the engine far longer than the request timeout to build, and it sends nothing
    // until it has. The request timeout only ends a transfer that stalls once data flows.
    SocketPath socket;
    const auto list {R"([{"Id":")" + idOf('a') + R"(","RepoTags":["nginx:1"],"RepoDigests":null}])"};
    FakeDockerDaemon daemon {socket.descriptor(), list, {{idOf('a'), dockerSave(idOf('a'), "curl")}}};
    daemon.delayExports(2500);

    ContainerImagesConfig config;
    config.references = {{ReferenceType::EngineStore, DOCKER_ENGINE}};
    config.dockerSocket = socket.path();
    config.limits.requestTimeoutMs = 1000;

    ContainerImagesImpl impl(config, makeReader, m_db);

    EXPECT_EQ(impl.scanOnce(), 1U);

    const auto rows {stored()};
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(packageNames(rows.front()), std::vector<std::string>({"curl"}));
    EXPECT_FALSE(warned("could not be read"));
}

TEST_F(EngineImageTest, AnExportThatStallsOnceDataFlowsIsEndedByTheRequestTimeout)
{
    // Only the first-byte wait is exempt from the stall detector: after that a transfer under 1 KiB/s
    // for the request timeout ends, well before the idle bound.
    SocketPath socket;
    const auto list {R"([{"Id":")" + idOf('a') + R"(","RepoTags":["nginx:1"],"RepoDigests":null}])"};
    FakeDockerDaemon daemon {socket.descriptor(), list, {{idOf('a'), dockerSave(idOf('a'), "curl")}}};
    daemon.stallExports(100, 8000);

    ContainerImagesConfig config;
    config.references = {{ReferenceType::EngineStore, DOCKER_ENGINE}};
    config.dockerSocket = socket.path();
    config.limits.requestTimeoutMs = 1000;

    ContainerImagesImpl impl(config, makeReader, m_db);

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_TRUE(stored().empty());
    EXPECT_TRUE(warned("Timeout was reached"));
}

TEST_F(EngineImageTest, AnExportThatSendsNothingForLongerThanTheIdleBoundIsEnded)
{
    // The wait for the first byte is bounded by the idle window instead of the request timeout.
    SocketPath socket;
    const auto list {R"([{"Id":")" + idOf('a') + R"(","RepoTags":["nginx:1"],"RepoDigests":null}])"};
    FakeDockerDaemon daemon {socket.descriptor(), list, {{idOf('a'), dockerSave(idOf('a'), "curl")}}};
    daemon.delayExports(3000);

    ContainerImagesConfig config;
    config.references = {{ReferenceType::EngineStore, DOCKER_ENGINE}};
    config.dockerSocket = socket.path();
    config.limits.blobIdleTimeoutMs = 1000;

    ContainerImagesImpl impl(config, makeReader, m_db);

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_TRUE(stored().empty());
    EXPECT_TRUE(warned("the transfer received no data for 1000 milliseconds"));
}

TEST_F(EngineImageTest, AnExportTheEngineRefusesIsNotStoredAsAnImage)
{
    SocketPath socket;
    const auto list {R"([{"Id":")" + idOf('a') + R"(","RepoTags":["nginx:1"],"RepoDigests":null}])"};
    FakeDockerDaemon daemon {socket.descriptor(), list, {}};

    ContainerImagesConfig config;
    config.references = {{ReferenceType::EngineStore, DOCKER_ENGINE}};
    config.dockerSocket = socket.path();

    ContainerImagesImpl impl(config, makeReader, m_db);

    EXPECT_EQ(impl.scanOnce(), 0U);
    EXPECT_TRUE(stored().empty());
    EXPECT_TRUE(warned("the server answered 404"));
}
#endif
