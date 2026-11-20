/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "archive_image_reader.hpp"
#include "byte_stream.hpp"
#include "ci_logging_helper.hpp"
#include "container_images_config.hpp"
#include "container_images_impl.hpp"
#include "image_fixtures.hpp"
#include "layer_composer.hpp"
#include "layer_reader.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace containerimages;
using namespace imagefixtures;

namespace
{
    const std::string DPKG_STATUS_PATH {"var/lib/dpkg/status"};
    const std::string APK_DB_PATH {"lib/apk/db/installed"};
    const std::string APK_USR_DB_PATH {"usr/lib/apk/db/installed"};
    const std::string RPM_SQLITE_PATH {"var/lib/rpm/rpmdb.sqlite"};
    const std::string RPM_SQLITE_USR_PATH {"usr/lib/sysimage/rpm/rpmdb.sqlite"};
    const std::string RPM_NDB_PATH {"var/lib/rpm/Packages.db"};
    const std::string RPM_NDB_USR_PATH {"usr/lib/sysimage/rpm/Packages.db"};
    const std::string RPM_BDB_PATH {"var/lib/rpm/Packages"};
    const std::string RPM_BDB_USR_PATH {"usr/lib/sysimage/rpm/Packages"};
    const std::string DPKG_STATUS_D_PATH {"var/lib/dpkg/status.d/"};
    const std::string PACMAN_PATH {"var/lib/pacman/local/desc"};
    /// What the module reports for a Berkeley DB database on a platform that cannot read it.
    const std::string RPM_BDB_UNSUPPORTED_FORMAT {"rpm Berkeley DB (not supported on this platform)"};
    constexpr char TYPE_HARDLINK {'1'};
    constexpr char TYPE_SYMLINK {'2'};
    const std::string OS_RELEASE_PATH {"etc/os-release"};
    const std::string OS_RELEASE_USR_PATH {"usr/lib/os-release"};

    std::string osRelease(const std::string& id, const std::string& version = "1")
    {
        return "NAME=\"" + id + " Linux\"\nID=" + id + "\nVERSION_ID=\"" + version + "\"\n";
    }

    /// @brief Unique name for a temporary directory, so concurrent runs never collide.
    std::string uniqueName()
    {
        static std::atomic<unsigned> counter {0};
        const auto now {std::chrono::steady_clock::now().time_since_epoch().count()};
        return "container_images_extraction_" + std::to_string(now) + "_" + std::to_string(counter++);
    }

    void setNullLogger()
    {
        LoggingHelper::setLogCallback([](const modules_log_level_t, const char*) {});
    }

    /// @brief Read every entry of a tar held in memory, keeping the content of each one.
    struct ReadEntry
    {
        LayerEntry entry;
        std::string content;
    };

    std::vector<ReadEntry> readAll(const std::string& tar, bool& complete)
    {
        std::vector<ReadEntry> entries;
        MemoryByteStream stream {tar};

        complete = LayerReader::read(stream, [&entries](const LayerEntry & entry, IByteStream & content)
        {
            ReadEntry read;
            read.entry = entry;
            read.content.resize(static_cast<std::size_t>(entry.size));
            read.content.resize(readExact(content, read.content.data(), read.content.size()));
            entries.push_back(std::move(read));
            return true;
        });

        return entries;
    }

    /// @brief The package names of a record list, sorted, so tests compare sets.
    std::vector<std::string> packageNames(const std::vector<ImagePackageRecord>& packages)
    {
        std::vector<std::string> names;

        for (const auto& package : packages)
        {
            names.push_back(package.name);
        }

        std::sort(names.begin(), names.end());
        return names;
    }

    /// @brief Snapshot of a layer built from a tar in memory.
    LayerSnapshot snapshotOf(const std::string& tar)
    {
        MemoryByteStream stream {tar};
        return readLayerSnapshot(stream);
    }

    /// @brief Builds an image on disk, as an OCI layout directory or as a saved archive.
    ///
    /// The layers are given as tar buffers in manifest order, so a test states the layer
    /// order it exercises and nothing else.
    class ImageBuilder
    {
        public:
            ImageBuilder()
                : m_root {std::filesystem::temp_directory_path() / uniqueName()}
            {
                std::filesystem::remove_all(m_root);
                std::filesystem::create_directories(m_root);
            }

            ~ImageBuilder()
            {
                std::filesystem::remove_all(m_root);
            }

            ImageBuilder(const ImageBuilder&) = delete;
            ImageBuilder& operator=(const ImageBuilder&) = delete;

            /// @brief Add one layer, compressed or not, in manifest order.
            void addLayer(const std::string& tar, const bool compressed = true)
            {
                m_layers.push_back(compressed ? gzip(tar) : tar);
            }

            /// @brief Write an OCI image layout directory and return its path.
            /// @param annotations Raw annotations object of the index entry.
            std::string writeOciLayout(const std::string& annotations =
                                           R"({"org.opencontainers.image.ref.name":"example:latest"})")
            {
                const auto layout {m_root / "layout"};
                std::filesystem::create_directories(layout / "blobs" / "sha256");

                write(layout / "oci-layout", R"({"imageLayoutVersion":"1.0.0"})");

                std::string layerDescriptors;

                for (std::size_t index = 0; index < m_layers.size(); ++index)
                {
                    const auto digest {layerDigest(index)};
                    write(layout / "blobs" / "sha256" / digest, m_layers[index]);
                    layerDescriptors += (layerDescriptors.empty() ? "" : ",");
                    layerDescriptors += R"({"digest":"sha256:)" + digest + R"("})";
                }

                write(layout / "blobs" / "sha256" / CONFIG_DIGEST, CONFIG_BLOB);
                write(layout / "blobs" / "sha256" / MANIFEST_DIGEST,
                      R"({"config":{"digest":"sha256:)" + CONFIG_DIGEST + R"("},"layers":[)" + layerDescriptors + "]}");
                write(layout / "index.json",
                      R"({"manifests":[{"digest":"sha256:)" + MANIFEST_DIGEST + R"(","annotations":)" +
                      annotations + "}]}");

                return layout.string();
            }

            /// @brief Write a saved image archive with the `docker save` layout.
            /// @param repoTags Raw `RepoTags` list of the manifest entry.
            std::string writeDockerArchive(const std::string& repoTags = R"(["example:latest"])")
            {
                std::string archive;
                std::string layerNames;

                for (std::size_t index = 0; index < m_layers.size(); ++index)
                {
                    const auto name {"layer" + std::to_string(index) + "/layer.tar"};
                    archive += tarMember(name, m_layers[index]);
                    layerNames += (layerNames.empty() ? "" : ",");
                    layerNames += "\"" + name + "\"";
                }

                archive += tarMember(CONFIG_DIGEST + ".json", CONFIG_BLOB);
                archive += tarMember("manifest.json",
                                     R"([{"Config":")" + CONFIG_DIGEST + R"(.json","RepoTags":)" + repoTags + R"(,"Layers":[)" +
                                     layerNames + "]}]");
                archive += tarEnd();

                const auto path {m_root / "image.tar"};
                write(path, archive);

                return path.string();
            }

            /// @brief Write a saved image archive holding an OCI layout.
            std::string writeOciArchive()
            {
                std::string archive;
                std::string layerDescriptors;

                for (std::size_t index = 0; index < m_layers.size(); ++index)
                {
                    const auto name {"blobs/sha256/" + layerDigest(index)};
                    archive += tarMember(name, m_layers[index]);
                    layerDescriptors += (layerDescriptors.empty() ? "" : ",");
                    layerDescriptors += R"({"digest":"sha256:)" + layerDigest(index) + R"("})";
                }

                archive += tarMember("oci-layout", R"({"imageLayoutVersion":"1.0.0"})");
                archive += tarMember("blobs/sha256/" + CONFIG_DIGEST, CONFIG_BLOB);
                archive += tarMember("blobs/sha256/" + MANIFEST_DIGEST,
                                     R"({"config":{"digest":"sha256:)" + CONFIG_DIGEST + R"("},"layers":[)" +
                                     layerDescriptors + "]}");
                archive += tarMember("index.json",
                                     R"({"manifests":[{"digest":"sha256:)" + MANIFEST_DIGEST +
                                     R"(","annotations":{"org.opencontainers.image.ref.name":"example:latest"}}]})");
                archive += tarEnd();

                const auto path {m_root / "image-oci.tar"};
                write(path, archive);

                return path.string();
            }

            static const std::string CONFIG_DIGEST;
            static const std::string MANIFEST_DIGEST;
            static const std::string CONFIG_BLOB;

        private:
            static std::string layerDigest(const std::size_t index)
            {
                // A digest-shaped name; the reader resolves blobs by name, it does not verify
                // digests, which is the job of the source that produced the image.
                return "layer" + std::string(59, '0') + std::to_string(index);
            }

            static void write(const std::filesystem::path& path, const std::string& content)
            {
                std::ofstream stream {path, std::ios::binary};
                stream.write(content.data(), static_cast<std::streamsize>(content.size()));
            }

            std::filesystem::path m_root;
            std::vector<std::string> m_layers;
    };

    const std::string ImageBuilder::CONFIG_DIGEST {"config" + std::string(58, '0')};
    const std::string ImageBuilder::MANIFEST_DIGEST {"manifest" + std::string(56, '0')};
    const std::string ImageBuilder::CONFIG_BLOB {R"({"os":"linux","architecture":"amd64"})"};
} // namespace

class PackageExtractionTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            setNullLogger();
        }
};

// ---------------------------------------------------------------------------
// Byte streams.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, MemoryStreamReadsEverythingAndThenReportsEnd)
{
    MemoryByteStream stream {"abcdef"};

    std::string buffer;
    buffer.resize(6);
    EXPECT_EQ(readExact(stream, buffer.data(), buffer.size()), 6U);
    EXPECT_EQ(buffer, "abcdef");
    EXPECT_EQ(stream.read(buffer.data(), buffer.size()), 0U);
}

TEST_F(PackageExtractionTest, BoundedStreamNeverReadsPastItsLimit)
{
    MemoryByteStream source {"abcdef"};
    BoundedByteStream bounded {source, 3};

    std::string buffer;
    buffer.resize(6);
    EXPECT_EQ(readExact(bounded, buffer.data(), buffer.size()), 3U);
    EXPECT_EQ(buffer.substr(0, 3), "abc");
    EXPECT_EQ(bounded.remaining(), 0U);

    // The bytes the bounded stream did not expose are still there for the next reader.
    EXPECT_EQ(readExact(source, buffer.data(), 3), 3U);
    EXPECT_EQ(buffer.substr(0, 3), "def");
}

TEST_F(PackageExtractionTest, LayerStreamDecompressesAGzipMember)
{
    // A payload larger than the internal buffer, so more than one inflate round is needed.
    std::string payload;

    for (int i = 0; i < 20000; ++i)
    {
        payload += "package data ";
    }

    const auto compressed {gzip(payload)};
    ASSERT_LT(compressed.size(), payload.size());

    MemoryByteStream source {compressed};
    LayerByteStream stream {source};

    std::string output;
    std::string chunk;
    chunk.resize(4096);

    while (true)
    {
        const auto got {stream.read(chunk.data(), chunk.size())};

        if (got == 0)
        {
            break;
        }

        output.append(chunk.data(), got);
    }

    EXPECT_EQ(output, payload);
}

TEST_F(PackageExtractionTest, LayerStreamPassesUncompressedBytesThrough)
{
    // An OCI layer may be stored uncompressed, so the format is decided from the bytes.
    MemoryByteStream source {"plain tar bytes"};
    LayerByteStream stream {source};

    std::string buffer;
    buffer.resize(32);
    const auto got {readExact(stream, buffer.data(), buffer.size())};

    EXPECT_EQ(std::string(buffer.data(), got), "plain tar bytes");
}

TEST_F(PackageExtractionTest, LayerStreamStopsOnATruncatedMember)
{
    auto compressed {gzip(std::string(4096, 'x'))};
    compressed.resize(compressed.size() / 2);

    MemoryByteStream source {compressed};
    LayerByteStream stream {source};

    std::string buffer;
    buffer.resize(8192);

    // Truncated input ends the stream instead of throwing or looping.
    EXPECT_NO_THROW(readExact(stream, buffer.data(), buffer.size()));
    EXPECT_EQ(stream.read(buffer.data(), buffer.size()), 0U);
}

TEST_F(PackageExtractionTest, LayerStreamDecompressesAZstdFrame)
{
    // zstd is the second compression the OCI image specification defines for a layer.
    std::string payload;

    for (int i = 0; i < 20000; ++i)
    {
        payload += "package data ";
    }

    const auto compressed {zstd(payload)};
    ASSERT_LT(compressed.size(), payload.size());

    MemoryByteStream source {compressed};
    LayerByteStream stream {source};

    EXPECT_EQ(stream.compression(), LayerCompression::Zstd);

    std::string output;
    std::string chunk;
    chunk.resize(4096);

    while (true)
    {
        const auto got {stream.read(chunk.data(), chunk.size())};

        if (got == 0)
        {
            break;
        }

        output.append(chunk.data(), got);
    }

    EXPECT_EQ(output, payload);
}

TEST_F(PackageExtractionTest, LayerStreamStopsOnATruncatedZstdFrame)
{
    auto compressed {zstd(std::string(4096, 'x'))};
    compressed.resize(compressed.size() / 2);

    MemoryByteStream source {compressed};
    LayerByteStream stream {source};

    std::string buffer;
    buffer.resize(8192);

    EXPECT_NO_THROW(readExact(stream, buffer.data(), buffer.size()));
    EXPECT_EQ(stream.read(buffer.data(), buffer.size()), 0U);
}

TEST_F(PackageExtractionTest, LayerStreamReportsTheCompressionItFound)
{
    const std::vector<std::pair<std::string, LayerCompression>> cases
    {
        {gzip("payload"), LayerCompression::Gzip},
        {zstd("payload"), LayerCompression::Zstd},
        {std::string("\xfd\x37\x7a\x58\x5a\x00", 6) + "payload", LayerCompression::Xz},
        {std::string("BZh9") + "payload", LayerCompression::Bzip2},
        {std::string("\x04\x22\x4d\x18", 4) + "payload", LayerCompression::Lz4},
        {std::string("plain tar bytes"), LayerCompression::None},
    };

    for (const auto& [content, expected] : cases)
    {
        MemoryByteStream source {content};
        LayerByteStream stream {source};

        EXPECT_EQ(stream.compression(), expected) << "for " << compressionName(expected);
    }
}

TEST_F(PackageExtractionTest, LayerStreamYieldsNothingForACompressionItCannotRead)
{
    // A recognized compression that cannot be decompressed must yield no bytes, so the
    // compressed bytes are never handed to the tar reader as if they were tar data. That
    // is what lets the caller report the layer instead of calling it malformed.
    for (const auto& content :
            {
                std::string("\xfd\x37\x7a\x58\x5a\x00", 6) + std::string(4096, 'x'),
                std::string("BZh9") + std::string(4096, 'x'),
                std::string("\x04\x22\x4d\x18", 4) + std::string(4096, 'x'),
            })
    {
        MemoryByteStream source {content};
        LayerByteStream stream {source};

        EXPECT_FALSE(isCompressionSupported(stream.compression()));

        std::string buffer;
        buffer.resize(512);
        EXPECT_EQ(stream.read(buffer.data(), buffer.size()), 0U);
    }
}

TEST_F(PackageExtractionTest, LayerReaderReadsAZstdCompressedLayer)
{
    // End to end over a layer: compressed with zstd, composed, and parsed.
    const auto tar {tarMember("var/lib/dpkg/status", dpkgStanza("bash", "5.2.15-2+b13"))};

    MemoryByteStream source {zstd(tar)};
    LayerByteStream stream {source};
    const auto snapshot {readLayerSnapshot(stream)};

    EXPECT_TRUE(snapshot.complete);

    LayerComposer composer;
    composer.apply(snapshot);

    const auto packages {composer.packages()};
    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "bash");
    EXPECT_EQ(packages.front().version, "5.2.15-2+b13");
}

// ---------------------------------------------------------------------------
// Layer reader: tar variants and deletion markers.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, LayerReaderReportsEntriesAndContent)
{
    const auto tar {tarMember("etc/hostname", "example\n") + tarMember("var/", "", TYPE_DIRECTORY) + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_TRUE(complete);
    ASSERT_EQ(entries.size(), 2U);
    EXPECT_EQ(entries[0].entry.path, "etc/hostname");
    EXPECT_TRUE(entries[0].entry.isRegularFile);
    EXPECT_EQ(entries[0].content, "example\n");
    EXPECT_EQ(entries[1].entry.path, "var/");
    EXPECT_FALSE(entries[1].entry.isRegularFile);
}

TEST_F(PackageExtractionTest, LayerReaderNormalizesLeadingPathMarkers)
{
    const auto tar {tarMember("./var/lib/dpkg/status", "data") + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].entry.path, DPKG_STATUS_PATH);
}

TEST_F(PackageExtractionTest, LayerReaderNormalizesInterleavedPathMarkers)
{
    // "/./var/..." strips one leading slash to "./var/...", which needs a second "./"
    // pass to finish normalizing: the two prefixes must be stripped until neither
    // applies, not just once each.
    const auto tar {tarMember("/./var/lib/dpkg/status", "data") + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].entry.path, DPKG_STATUS_PATH);
}

TEST_F(PackageExtractionTest, LayerReaderJoinsTheUstarPrefixField)
{
    const auto tar {tarMember("status", "data", TYPE_REGULAR, "var/lib/dpkg") + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].entry.path, DPKG_STATUS_PATH);
}

TEST_F(PackageExtractionTest, LayerReaderAppliesAGnuLongName)
{
    const std::string longPath {"var/lib/" + std::string(120, 'a') + "/dpkg/status"};
    const auto tar {gnuLongName(longPath) + tarMember("truncated", "data") + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].entry.path, longPath);
    EXPECT_EQ(entries[0].content, "data");
}

TEST_F(PackageExtractionTest, LayerReaderAppliesAPaxLongName)
{
    const std::string longPath {"usr/lib/" + std::string(130, 'b') + "/apk/db/installed"};
    const auto tar {paxLongName(longPath) + tarMember("truncated", "data") + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].entry.path, longPath);
    EXPECT_EQ(entries[0].content, "data");
}

TEST_F(PackageExtractionTest, LayerReaderAppliesAPaxSizeOverride)
{
    // A pax writer may leave the ustar size field at zero and encode the real size out
    // of band in a pax "size" record instead. Not honouring it would read the entry as
    // zero bytes and desync onto its real content, which the next iteration would
    // misread as the following header.
    const std::string content(600, 'x');

    // Built by hand rather than through tarMember(): the header must claim a size of
    // zero while real content bytes still follow it, which tarMember cannot express
    // since it always sizes the header from the content it is given.
    auto entry {tarMember(DPKG_STATUS_PATH, "", TYPE_REGULAR)};
    entry += content;
    entry.append((TAR_BLOCK - (content.size() % TAR_BLOCK)) % TAR_BLOCK, '\0');

    const auto tar {paxRecord("size", std::to_string(content.size())) + entry + tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].entry.path, DPKG_STATUS_PATH);
    EXPECT_EQ(entries[0].content, content);
    EXPECT_TRUE(complete);
}

TEST_F(PackageExtractionTest, LayerReaderRejectsAHeaderWithABadChecksum)
{
    // The checksum is what lets the reader tell a genuine header apart from an
    // arbitrary 512-byte block; a mismatch must stop the layer rather than parse
    // whatever the corrupt fields happen to decode to.
    auto tar {tarMember(DPKG_STATUS_PATH, "data") + tarEnd()};
    tar[148] = '9'; // Corrupt one digit of the checksum field.

    bool complete {true};
    const auto entries {readAll(tar, complete)};

    EXPECT_TRUE(entries.empty());
    EXPECT_FALSE(complete);
}

TEST_F(PackageExtractionTest, LayerReaderRecognizesDeletionMarkers)
{
    const auto tar {tarMember("var/lib/.wh.dpkg", "") +
                    tarMember("var/lib/dpkg/.wh..wh..opq", "") +
                    tarEnd()};

    bool complete {false};
    const auto entries {readAll(tar, complete)};

    ASSERT_EQ(entries.size(), 2U);
    EXPECT_TRUE(entries[0].entry.isWhiteout);
    EXPECT_FALSE(entries[0].entry.isOpaqueDirectory);
    EXPECT_EQ(entries[0].entry.whiteoutTarget, "var/lib/dpkg");
    EXPECT_TRUE(entries[1].entry.isOpaqueDirectory);
    EXPECT_FALSE(entries[1].entry.isWhiteout);
    EXPECT_EQ(entries[1].entry.whiteoutTarget, "var/lib/dpkg");
}

TEST_F(PackageExtractionTest, LayerReaderSkipsTheContentTheCallbackIgnores)
{
    // The reader must resynchronize on the next header even when nothing read the entry,
    // which is what keeps an image cheap to scan.
    const auto tar {tarMember("big/file", std::string(5000, 'x')) + tarMember("etc/hostname", "example\n") + tarEnd()};

    std::vector<std::string> paths;
    MemoryByteStream stream {tar};

    const auto complete {LayerReader::read(stream, [&paths](const LayerEntry & entry, IByteStream&)
    {
        paths.push_back(entry.path);
        return true;
    })};

    EXPECT_TRUE(complete);
    EXPECT_EQ(paths, std::vector<std::string>({"big/file", "etc/hostname"}));
}

TEST_F(PackageExtractionTest, LayerReaderStopsWhenTheCallbackAsksIt)
{
    const auto tar {tarMember("first", "a") + tarMember("second", "b") + tarEnd()};

    int seen {0};
    MemoryByteStream stream {tar};

    const auto complete {LayerReader::read(stream, [&seen](const LayerEntry&, IByteStream&)
    {
        ++seen;
        return false;
    })};

    EXPECT_TRUE(complete);
    EXPECT_EQ(seen, 1);
}

TEST_F(PackageExtractionTest, LayerReaderReportsATruncatedArchive)
{
    auto tar {tarMember("var/lib/dpkg/status", std::string(2000, 'x'))};
    tar.resize(tar.size() - 700);

    bool complete {true};
    const auto entries {readAll(tar, complete)};

    EXPECT_FALSE(complete);
    // The entry was still reported, so a truncated layer costs the layer, not the scan.
    EXPECT_EQ(entries.size(), 1U);
}

TEST_F(PackageExtractionTest, LayerReaderHandlesGarbageWithoutThrowing)
{
    MemoryByteStream stream {std::string(1024, '\x7f')};

    EXPECT_NO_THROW(LayerReader::read(stream, [](const LayerEntry&, IByteStream&) { return true; }));
}

// ---------------------------------------------------------------------------
// Layer composition.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, ComposerKeepsOnlyTheTrackedDatabases)
{
    const auto snapshot {snapshotOf(tarMember(DPKG_STATUS_PATH, "status data") +
                                    tarMember("etc/hostname", "example") +
                                    tarEnd())};

    ASSERT_EQ(snapshot.databases.size(), 1U);
    EXPECT_EQ(snapshot.databases.at(DPKG_STATUS_PATH), "status data");
}

TEST_F(PackageExtractionTest, ComposerLetsTheLastLayerWin)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "8.0")) + tarEnd()));

    const auto packages {composer.packages()};

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "curl");
    EXPECT_EQ(packages.front().version, "8.0");
}

TEST_F(PackageExtractionTest, ComposerAppliesAFileDeletionMarker)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("var/lib/dpkg/.wh.status", "") + tarEnd()));

    EXPECT_TRUE(composer.databases().empty());
    EXPECT_TRUE(composer.packages().empty());
}

TEST_F(PackageExtractionTest, ComposerAppliesADeletionMarkerOnAParentDirectory)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("var/lib/.wh.dpkg", "") + tarEnd()));

    EXPECT_TRUE(composer.databases().empty());
}

TEST_F(PackageExtractionTest, ComposerAppliesAnOpaqueDirectoryMarker)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("var/lib/dpkg/.wh..wh..opq", "") + tarEnd()));

    EXPECT_TRUE(composer.databases().empty());
}

TEST_F(PackageExtractionTest, ComposerAppliesTheOwnFilesOfALayerAfterItsMarkers)
{
    // A layer that both hides its directory and provides a new database keeps the new one:
    // the marker applies to what the earlier layers left, not to the layer itself.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("var/lib/dpkg/.wh..wh..opq", "") +
                              tarMember(DPKG_STATUS_PATH, dpkgStanza("wget", "1.0")) +
                              tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"wget"}));
}

TEST_F(PackageExtractionTest, ComposerRecordsTheFormatsThatAreNotImplementedYet)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember("var/db/pkg/app-1.0/CONTENTS", "not parsed") +
                              tarMember(PACMAN_PATH, "not parsed") +
                              tarEnd()));

    EXPECT_TRUE(composer.packages().empty());
    EXPECT_EQ(composer.unsupportedFormats(), std::set<std::string>({"portage", "pacman"}));
}

TEST_F(PackageExtractionTest, ComposerReportsBothDatabasesOfAMixedImage)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) +
                              tarMember(APK_DB_PATH, apkStanza("busybox", "1.36")) +
                              tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"busybox", "curl"}));
}

TEST_F(PackageExtractionTest, ComposerDoesNotReportBothApkLocationsOfTheSameImage)
{
    // An image that happens to carry a real file at both apk database locations must not
    // report the same packages twice: they are alternate locations of one conceptual
    // database, not two, and duplicate rows collide on the packages table's primary key.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(APK_DB_PATH, apkStanza("busybox", "1.36")) +
                              tarMember(APK_USR_DB_PATH, apkStanza("musl", "1.2.4")) +
                              tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"busybox"}));
}

TEST_F(PackageExtractionTest, ComposerIgnoresABareWhiteoutEntry)
{
    // ".wh." with nothing after the prefix names no target. Treating it as a whiteout of
    // "" would delete every tracked database instead of nothing.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("var/lib/dpkg/.wh.", "") + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"curl"}));
}

TEST_F(PackageExtractionTest, ComposerRetractsAnUnsupportedFormatWarningOnceItsPathIsRemoved)
{
    // The unsupported-format warning is tied to the path it was seen at, so it is
    // retracted the same way a tracked database is: an image whose pacman directory is
    // removed in a later layer should not keep reporting pacman once nothing pacman-shaped
    // survives composition.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(PACMAN_PATH, "not parsed") + tarEnd()));
    EXPECT_EQ(composer.unsupportedFormats(), std::set<std::string>({"pacman"}));

    composer.apply(snapshotOf(tarMember("var/lib/.wh.pacman", "") + tarEnd()));

    EXPECT_TRUE(composer.unsupportedFormats().empty());
}

TEST_F(PackageExtractionTest, ComposerKeepsTheOsReleaseApartFromTheDatabases)
{
    const auto snapshot {snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "12")) +
                                    tarMember(OS_RELEASE_USR_PATH, osRelease("debian", "12")) +
                                    tarEnd())};

    EXPECT_TRUE(snapshot.databases.empty());
    EXPECT_EQ(snapshot.osReleases.size(), 2U);
}

TEST_F(PackageExtractionTest, ComposerReadsTheOperatingSystemOfTheEtcFile)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "12")) + tarEnd()));

    const auto os {composer.operatingSystem()};

    EXPECT_EQ(os.id, "debian");
    EXPECT_EQ(os.version, "12");
    EXPECT_EQ(os.name, "debian Linux");
}

TEST_F(PackageExtractionTest, ComposerFallsBackToTheUsrLibOsRelease)
{
    // Most images keep the file under /usr/lib and link /etc/os-release to it, and a link
    // is not a regular file, so the real one is the only one the layer carries.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_USR_PATH, osRelease("alpine", "3.19")) + tarEnd()));

    EXPECT_EQ(composer.operatingSystem().id, "alpine");
}

TEST_F(PackageExtractionTest, ComposerPrefersTheEtcOsReleaseOverTheFallback)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_USR_PATH, osRelease("alpine")) +
                              tarMember(OS_RELEASE_PATH, osRelease("debian")) +
                              tarEnd()));

    EXPECT_EQ(composer.operatingSystem().id, "debian");
}

TEST_F(PackageExtractionTest, ComposerTakesTheOsReleaseFromTheLastLayerThatProvidesIt)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "11")) + tarEnd()));
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "12")) + tarEnd()));

    EXPECT_EQ(composer.operatingSystem().version, "12");
}

TEST_F(PackageExtractionTest, ComposerFallsBackWhenALaterLayerDeletesTheEtcOsRelease)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_USR_PATH, osRelease("alpine")) +
                              tarMember(OS_RELEASE_PATH, osRelease("debian")) +
                              tarEnd()));
    composer.apply(snapshotOf(tarMember("etc/.wh.os-release", "") + tarEnd()));

    EXPECT_EQ(composer.operatingSystem().id, "alpine");
}

TEST_F(PackageExtractionTest, ComposerReportsNoOperatingSystemWhenEveryOsReleaseIsDeleted)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian")) +
                              tarMember(OS_RELEASE_USR_PATH, osRelease("debian")) +
                              tarEnd()));
    composer.apply(snapshotOf(tarMember("etc/.wh.os-release", "") + tarMember("usr/lib/.wh.os-release", "") + tarEnd()));

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerDropsTheOsReleaseOfADeletedParentDirectory)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian")) + tarEnd()));
    composer.apply(snapshotOf(tarMember(".wh.etc", "") + tarEnd()));

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerDropsTheOsReleaseHiddenByAnOpaqueDirectory)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("etc/.wh..wh..opq", "") + tarEnd()));

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerKeepsTheOsReleaseTheDeletingLayerProvidesAgain)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "11")) + tarEnd()));
    composer.apply(snapshotOf(tarMember("etc/.wh.os-release", "") +
                              tarMember(OS_RELEASE_PATH, osRelease("debian", "12")) +
                              tarEnd()));

    EXPECT_EQ(composer.operatingSystem().version, "12");
}

TEST_F(PackageExtractionTest, ComposerDoesNotFollowASymlinkedOsRelease)
{
    // /etc/os-release linked to the /usr/lib file: the link has no content of its own, and
    // the file it names is read at its own path.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, "", TYPE_SYMLINK) +
                              tarMember(OS_RELEASE_USR_PATH, osRelease("alpine", "3.19")) +
                              tarEnd()));

    const auto os {composer.operatingSystem()};

    EXPECT_EQ(os.id, "alpine");
    EXPECT_EQ(os.version, "3.19");
}

TEST_F(PackageExtractionTest, ComposerReportsNoOperatingSystemForALoneSymlink)
{
    const auto snapshot {snapshotOf(tarMember(OS_RELEASE_PATH, "", TYPE_SYMLINK) + tarEnd())};

    EXPECT_TRUE(snapshot.osReleases.empty());
    EXPECT_EQ(snapshot.osReleasesReplaced, std::set<std::string>({OS_RELEASE_PATH}));

    LayerComposer composer;
    composer.apply(snapshot);

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerDropsTheEarlierOsReleaseWhenALaterLayerReplacesItWithASymlink)
{
    // A package moved the file: the later layer links /etc/os-release to the new /usr/lib
    // one. A tar replacement carries no deletion marker, and the old file must not win.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "11")) + tarEnd()));
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, "", TYPE_SYMLINK) +
                              tarMember(OS_RELEASE_USR_PATH, osRelease("debian", "12")) +
                              tarEnd()));

    EXPECT_EQ(composer.operatingSystem().version, "12");
}

TEST_F(PackageExtractionTest, ComposerDropsTheEarlierOsReleaseWhenALaterLayerReplacesItWithAHardlink)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "11")) + tarEnd()));
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, "", TYPE_HARDLINK) + tarEnd()));

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerDropsTheEarlierOsReleaseWhenALaterLayerReplacesItWithAnOversizedFile)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, osRelease("debian", "11")) + tarEnd()));
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, std::string(128 * 1024, 'a')) + tarEnd()));

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerFallsBackToTheUsrLibFileWhenALaterLayerLinksTheEtcOne)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_USR_PATH, osRelease("alpine", "3.18")) +
                              tarMember(OS_RELEASE_PATH, osRelease("debian", "11")) +
                              tarEnd()));
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, "", TYPE_SYMLINK) + tarEnd()));

    EXPECT_EQ(composer.operatingSystem().id, "alpine");
}

TEST_F(PackageExtractionTest, ComposerReportsNoOperatingSystemForAnImageWithNoOsRelease)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember("bin/app", "a static binary") + tarEnd()));

    EXPECT_TRUE(composer.operatingSystem().empty());
}

TEST_F(PackageExtractionTest, ComposerTriesTheFallbackWhenTheEtcFileStatesNothing)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(OS_RELEASE_PATH, "# empty\n") +
                              tarMember(OS_RELEASE_USR_PATH, osRelease("alpine")) +
                              tarEnd()));

    EXPECT_EQ(composer.operatingSystem().id, "alpine");
}

TEST_F(PackageExtractionTest, ComposerDoesNotReadAnOversizedOsRelease)
{
    // The size comes from the image: a file far past what an os-release can be is skipped.
    const auto snapshot {snapshotOf(tarMember(OS_RELEASE_PATH, std::string(128 * 1024, 'a')) + tarEnd())};

    EXPECT_TRUE(snapshot.osReleases.empty());
}

// ---------------------------------------------------------------------------
// Package databases through the composer. The formats themselves are read by the parser
// shared with container runtime security, which has its own tests in data_provider.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, WolfiStyleApkDatabaseIsInventoried)
{
    const auto snapshot {snapshotOf(tarMember(APK_USR_DB_PATH, apkStanza("wolfi-base", "1.0")) + tarEnd())};

    LayerComposer composer;
    composer.apply(snapshot);

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"wolfi-base"}));
}

TEST_F(PackageExtractionTest, RpmDatabaseIsNotReportedAsAnUnsupportedFormat)
{
    // The Berkeley DB file sits in the same directory as the databases that are read, so
    // a database this module parses must never be claimed by the unsupported list.
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_SQLITE_PATH, rpmSqliteDatabase({rpmHeaderBlob(bash)})) +
                              tarMember("var/lib/rpm/.rpm.lock", "") + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"bash"}));
    EXPECT_TRUE(composer.unsupportedFormats().empty());
}

TEST_F(PackageExtractionTest, ComposerDoesNotReportBothRpmLocationsOfTheSameImage)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    RpmPackage glibc;
    glibc.name = "glibc";
    glibc.version = "2.34";

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_SQLITE_PATH, rpmSqliteDatabase({rpmHeaderBlob(bash)})) +
                              tarMember(RPM_NDB_USR_PATH, rpmNdbDatabase({rpmHeaderBlob(glibc)})) + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"bash"}));
}

TEST_F(PackageExtractionTest, SysimageRpmDatabaseIsInventoried)
{
    RpmPackage vim;
    vim.name = "vim-data";
    vim.version = "9.1.785";
    vim.release = "1.fc39";
    vim.hasEpoch = true;
    vim.epoch = 2;

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_SQLITE_USR_PATH, rpmSqliteDatabase({rpmHeaderBlob(vim)})) + tarEnd()));

    const auto packages {composer.packages()};
    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().version, "2:9.1.785-1.fc39");
    EXPECT_EQ(packages.front().packageDbPath, RPM_SQLITE_USR_PATH);
}

TEST_F(PackageExtractionTest, ComposerReadsTheDpkgStatusDirectoryOfADistrolessImage)
{
    // A distroless image has no `status`: each package is its own file, usually with no
    // Status line, and the checksum files next to them are not packages.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\nVersion: 12.4\nArchitecture: amd64\n") +
                              tarMember(DPKG_STATUS_D_PATH + "base-files.md5sums", "d41d8cd98f00b204e9800998ecf8427e  etc/issue\n") +
                              tarMember(DPKG_STATUS_D_PATH + "tzdata", "Package: tzdata\nVersion: 2024a\nArchitecture: all\n") +
                              tarEnd()));

    const auto packages {composer.packages()};

    EXPECT_EQ(packageNames(packages), std::vector<std::string>({"base-files", "tzdata"}));
    EXPECT_EQ(packages.front().type, "deb");
    EXPECT_TRUE(composer.unsupportedFormats().empty());
}

TEST_F(PackageExtractionTest, ComposerAppliesAWhiteoutToOneFileOfTheDpkgStatusDirectory)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\nVersion: 12.4\n") +
                              tarMember(DPKG_STATUS_D_PATH + "tzdata", "Package: tzdata\nVersion: 2024a\n") +
                              tarEnd()));
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_D_PATH + ".wh.tzdata", "") + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"base-files"}));
}

TEST_F(PackageExtractionTest, ComposerAppliesAWhiteoutToTheDpkgStatusDirectory)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\nVersion: 12.4\n") + tarEnd()));
    composer.apply(snapshotOf(tarMember("var/lib/dpkg/.wh.status.d", "") + tarEnd()));

    EXPECT_TRUE(composer.packages().empty());
}

TEST_F(PackageExtractionTest, ComposerReplacesAFileOfTheDpkgStatusDirectoryWithALaterLayer)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\nVersion: 12.4\n") + tarEnd()));
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\nVersion: 12.5\n") + tarEnd()));

    const auto packages {composer.packages()};

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().version, "12.5");
}

TEST_F(PackageExtractionTest, ComposerReadsTheDpkgStatusDirectoryOnlyWhenThereIsNoStatusFile)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) +
                              tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\nVersion: 12.4\n") +
                              tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"curl"}));

    // The same directory is read once the status file is gone.
    composer.apply(snapshotOf(tarMember("var/lib/dpkg/.wh.status", "") + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"base-files"}));
}

TEST_F(PackageExtractionTest, TheDpkgStatusDirectoryIsKeptOnlyForItsDirectChildren)
{
    const auto snapshot {snapshotOf(tarMember(DPKG_STATUS_D_PATH + "base-files", "Package: base-files\n") +
                                    tarMember(DPKG_STATUS_D_PATH + "base-files.md5sums", "sums") +
                                    tarMember(DPKG_STATUS_D_PATH + "nested/other", "Package: other\n") +
                                    tarEnd())};

    EXPECT_EQ(snapshot.databases.size(), 1U);
    EXPECT_EQ(snapshot.databases.count(DPKG_STATUS_D_PATH + "base-files"), 1U);
}

#if defined(__linux__)
TEST_F(PackageExtractionTest, RpmBerkeleyDbImageIsInventoried)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "4.2.46";
    bash.release = "35.el7_9";

    RpmPackage glibc;
    glibc.name = "glibc";
    glibc.version = "2.17";
    glibc.hasEpoch = true;
    glibc.epoch = 0;

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, rpmBerkeleyDatabase({rpmHeaderBlob(bash), rpmHeaderBlob(glibc)})) +
                              tarMember("var/lib/rpm/__db.001", "") + tarEnd()));

    const auto packages {composer.packages()};

    ASSERT_EQ(packageNames(packages), std::vector<std::string>({"bash", "glibc"}));

    for (const auto& package : packages)
    {
        EXPECT_EQ(package.version, package.name == "bash" ? "4.2.46-35.el7_9" : "0:2.17-1.el9");
        EXPECT_EQ(package.packageDbPath, RPM_BDB_PATH);
    }

    EXPECT_TRUE(composer.unsupportedFormats().empty());
}

TEST_F(PackageExtractionTest, RpmBerkeleyDbUnderUsrIsInventoried)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "4.2.46";

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_USR_PATH, rpmBerkeleyDatabase({rpmHeaderBlob(bash)})) + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"bash"}));
}

TEST_F(PackageExtractionTest, AStaleRpmBerkeleyDbNextToASqliteOneIsNotReported)
{
    // rpm 4.16 and later can leave the old file behind when it converts the database.
    RpmPackage stale;
    stale.name = "stale";
    stale.version = "1";

    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, rpmBerkeleyDatabase({rpmHeaderBlob(stale)})) +
                              tarMember(RPM_SQLITE_PATH, rpmSqliteDatabase({rpmHeaderBlob(bash)})) + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"bash"}));
}

TEST_F(PackageExtractionTest, AFileThatIsNoBerkeleyDbIsReportedAndCostsNoOtherDatabase)
{
    std::vector<std::string> warnings;
    LoggingHelper::setLogCallback([&warnings](const modules_log_level_t level, const char* message)
    {
        if (level == LOG_WARNING)
        {
            warnings.push_back(message);
        }
    });

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, "a Berkeley DB hash file") +
                              tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()));

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"curl"}));
    ASSERT_EQ(warnings.size(), 1U);
    EXPECT_NE(warnings.front().find("'" + RPM_BDB_PATH + "' could not be read"), std::string::npos);

    LoggingHelper::setLogCallback({});
}

TEST_F(PackageExtractionTest, ATruncatedRpmBerkeleyDbDoesNotStopTheScan)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "4.2.46";

    const auto database {rpmBerkeleyDatabase({rpmHeaderBlob(bash)})};

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, database.substr(0, database.size() / 2)) + tarEnd()));

    EXPECT_NO_THROW(composer.packages());
}

TEST_F(PackageExtractionTest, ARunningBerkeleyDbReadIsCancelledByAStopRequest)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "4.2.46";

    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, rpmBerkeleyDatabase({rpmHeaderBlob(bash)})) + tarEnd()));

    std::vector<std::string> debug;
    LoggingHelper::setLogCallback([&debug](const modules_log_level_t level, const char* message)
    {
        if (level == LOG_DEBUG || level == LOG_WARNING)
        {
            debug.push_back(std::to_string(level) + message);
        }
    });

    const std::atomic<bool> stop {true};

    EXPECT_TRUE(composer.packages("image", &stop).empty());
    EXPECT_TRUE(std::any_of(debug.begin(), debug.end(), [](const std::string & line)
    {
        return line.find("cancelled by a stop request") != std::string::npos;
    }));

    // A read cut short by a shutdown is not reported as a fault of the database.
    EXPECT_FALSE(std::any_of(debug.begin(), debug.end(), [](const std::string & line)
    {
        return line.rfind(std::to_string(LOG_WARNING), 0) == 0;
    }));

    LoggingHelper::setLogCallback({});
}

TEST_F(PackageExtractionTest, RpmBerkeleyDbImageIsStoredWithItsPackages)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "4.2.46";

    ImageBuilder builder;
    builder.addLayer(tarMember(RPM_BDB_PATH, rpmBerkeleyDatabase({rpmHeaderBlob(bash)})) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(packageNames(references.front().packages), std::vector<std::string>({"bash"}));
}
#else
TEST_F(PackageExtractionTest, RpmBerkeleyDbImageIsReportedAsNotSupportedOnThisPlatform)
{
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, "a Berkeley DB hash file") +
                              tarMember("var/lib/rpm/__db.001", "") + tarEnd()));

    EXPECT_TRUE(composer.packages().empty());
    EXPECT_EQ(composer.unsupportedFormats(), std::set<std::string>({RPM_BDB_UNSUPPORTED_FORMAT}));
}
#endif

// ---------------------------------------------------------------------------
// Reader: end to end over the supported inputs.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, OciLayoutDirectoryIsInventoried)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0") + dpkgStanza("tar", "1.34")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().source.sourceType, "archive");
    EXPECT_EQ(references.front().name, "docker.io/library/example");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"latest"}));
    EXPECT_EQ(references.front().os, "linux");
    EXPECT_EQ(packageNames(references.front().packages), std::vector<std::string>({"curl", "tar"}));
}

TEST_F(PackageExtractionTest, UncompressedLayerIsInventoried)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(APK_DB_PATH, apkStanza("busybox", "1.36")) + tarEnd(), false);

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(packageNames(references.front().packages), std::vector<std::string>({"busybox"}));
}

TEST_F(PackageExtractionTest, SavedArchiveIsInventoried)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeDockerArchive()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().name, "docker.io/library/example");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"latest"}));
    EXPECT_EQ(packageNames(references.front().packages), std::vector<std::string>({"curl"}));
}

TEST_F(PackageExtractionTest, SavedArchiveHoldingAnOciLayoutIsInventoried)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(APK_DB_PATH, apkStanza("musl", "1.2.4")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciArchive()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(packageNames(references.front().packages), std::vector<std::string>({"musl"}));
}

TEST_F(PackageExtractionTest, LayerOrderIsTheManifestOrderInASavedArchive)
{
    // The archive is read from start to end while the order comes from the manifest, so a
    // package replaced in a later layer must still be reported with the later version.
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0") + dpkgStanza("tar", "1.34")) + tarEnd());
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "8.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeDockerArchive()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    ASSERT_EQ(references.front().packages.size(), 1U);
    EXPECT_EQ(references.front().packages.front().name, "curl");
    EXPECT_EQ(references.front().packages.front().version, "8.0");
}

TEST_F(PackageExtractionTest, PackageRemovedInALaterLayerIsNotReported)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());
    builder.addLayer(tarMember("var/lib/dpkg/.wh.status", "") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().packages.empty());
}

TEST_F(PackageExtractionTest, ImageWithNoSupportedDatabaseIsInventoriedWithZeroPackages)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(PACMAN_PATH, "a package format this module does not read") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    // The reference is still inventoried, so the scan reports the image it found.
    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().packages.empty());
}

TEST_F(PackageExtractionTest, TheOperatingSystemOfAnImageIsRead)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) +
                     tarMember(OS_RELEASE_USR_PATH, osRelease("debian", "12")) +
                     tarEnd());

    const std::vector<std::string> locations {builder.writeOciLayout(), builder.writeDockerArchive(), builder.writeOciArchive()};

    for (const auto& location : locations)
    {
        ArchiveImageReader reader {location};
        const auto references {reader.discover().records};

        ASSERT_EQ(references.size(), 1U) << location;
        EXPECT_EQ(references.front().operatingSystem.id, "debian") << location;
        EXPECT_EQ(references.front().operatingSystem.version, "12") << location;
        EXPECT_EQ(references.front().operatingSystem.name, "debian Linux") << location;
    }
}

TEST_F(PackageExtractionTest, AnImageWithNoOsReleaseIsStoredWithNoOperatingSystem)
{
    // A scratch or static distroless image: not an error, the reference is still reported.
    ImageBuilder builder;
    builder.addLayer(tarMember("bin/app", "a static binary") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto result {reader.discover()};

    ASSERT_EQ(result.status, ReadStatus::Success);
    ASSERT_EQ(result.records.size(), 1U);
    EXPECT_TRUE(result.records.front().operatingSystem.empty());
}

TEST_F(PackageExtractionTest, AnImageWithNoOsReleaseIsReportedOnceAtInfoLevel)
{
    std::vector<std::string> infos;
    LoggingHelper::setLogCallback([&infos](const modules_log_level_t level, const char* message)
    {
        if (level == LOG_INFO)
        {
            infos.push_back(message);
        }
    });

    ImageBuilder builder;
    builder.addLayer(tarMember("bin/app", "a static binary") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    reader.discover();

    ASSERT_EQ(infos.size(), 1U);
    EXPECT_NE(infos.front().find("no operating system"), std::string::npos);

    LoggingHelper::setLogCallback({});
}

TEST_F(PackageExtractionTest, AnOsReleaseDeletedByALaterLayerIsNotReported)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(OS_RELEASE_PATH, osRelease("debian", "12")) + tarEnd());
    builder.addLayer(tarMember("etc/.wh.os-release", "") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().operatingSystem.empty());
}

TEST_F(PackageExtractionTest, SavedArchiveKeepsTheDigestsItsMetadataStates)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    // The `docker save` layout names the configuration file and nothing else, so the
    // configuration digest is the only one it can offer.
    {
        ArchiveImageReader reader {builder.writeDockerArchive()};
        const auto references {reader.discover().records};

        ASSERT_EQ(references.size(), 1U);
        EXPECT_EQ(references.front().digests, std::vector<std::string>({"sha256:" + ImageBuilder::CONFIG_DIGEST}));
    }

    // An OCI layout names the manifest as well.
    const std::vector<std::string> ociLocations {builder.writeOciArchive(), builder.writeOciLayout()};

    for (const auto& location : ociLocations)
    {
        ArchiveImageReader reader {location};
        const auto references {reader.discover().records};

        ASSERT_EQ(references.size(), 1U) << location;
        EXPECT_EQ(references.front().digests,
                  std::vector<std::string>({"sha256:" + ImageBuilder::MANIFEST_DIGEST,
                                            "sha256:" + ImageBuilder::CONFIG_DIGEST})) << location;
    }
}

TEST_F(PackageExtractionTest, AnUnchangedSavedArchiveReportsTheDigestsItsMetadataStates)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    const auto known {"sha256:" + ImageBuilder::CONFIG_DIGEST};

    const auto docker {ArchiveImageReader(builder.writeDockerArchive(), known).discover()};
    EXPECT_EQ(docker.status, ReadStatus::Unchanged);
    EXPECT_EQ(docker.digests, std::vector<std::string>({known}));

    const auto oci {ArchiveImageReader(builder.writeOciArchive(), known).discover()};
    EXPECT_EQ(oci.status, ReadStatus::Unchanged);
    EXPECT_EQ(oci.digests, std::vector<std::string>({"sha256:" + ImageBuilder::MANIFEST_DIGEST, known}));
}

TEST_F(PackageExtractionTest, AnUnchangedArchiveReportsTheNameAndTagsItHasNow)
{
    // Saved again under other tags, the image keeps its configuration digest, so nothing is read
    // again, but the names it carries now are handed back with the unchanged result.
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    const auto known {"sha256:" + ImageBuilder::CONFIG_DIGEST};

    const auto docker {ArchiveImageReader(builder.writeDockerArchive(R"(["a:1","a:2"])"), known).discover()};
    ASSERT_EQ(docker.status, ReadStatus::Unchanged);
    ASSERT_TRUE(docker.names.has_value());
    EXPECT_EQ(docker.names->name, "docker.io/library/a");
    EXPECT_EQ(docker.names->tags, std::vector<std::string>({"1", "2"}));

    const auto oci {ArchiveImageReader(builder.writeOciLayout(R"({"org.opencontainers.image.ref.name":"b:3"})"),
                                       known).discover()};
    ASSERT_EQ(oci.status, ReadStatus::Unchanged);
    ASSERT_TRUE(oci.names.has_value());
    EXPECT_EQ(oci.names->name, "docker.io/library/b");
    EXPECT_EQ(oci.names->tags, std::vector<std::string>({"3"}));
}

TEST_F(PackageExtractionTest, AnImageListingMoreNamesThanTheLimitKeepsTheFirstOnes)
{
    // The manifest is bounded by its size, not by what it lists, and every tag is compared to
    // the ones already kept.
    std::string repoTags {"["};

    for (int tag = 0; tag < 500; ++tag)
    {
        repoTags += std::string {tag == 0 ? "" : ","} + "\"x:" + std::to_string(tag) + "\"";
    }

    repoTags += "]";

    int capLines {0};
    LoggingHelper::setLogCallback([&capLines](const modules_log_level_t, const char* message)
    {
        if (std::string {message}.find("names, the ones past that are not reported") != std::string::npos)
        {
            ++capLines;
        }
    });

    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeDockerArchive(repoTags)};
    const auto references {reader.discover().records};

    LoggingHelper::setLogCallback([](const modules_log_level_t, const char*) {});

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().name, "docker.io/library/x");
    ASSERT_EQ(references.front().tags.size(), 64U);
    EXPECT_EQ(references.front().tags.front(), "0");
    EXPECT_EQ(references.front().tags.back(), "63");
    EXPECT_EQ(capLines, 1) << "the dropped names are reported once";
}

TEST_F(PackageExtractionTest, RpmImageIsInventoried)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";
    bash.release = "9.el9";

    ImageBuilder builder;
    builder.addLayer(tarMember(RPM_SQLITE_PATH, rpmSqliteDatabase({rpmHeaderBlob(bash)})) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    ASSERT_EQ(references.front().packages.size(), 1U);
    EXPECT_EQ(references.front().packages.front().name, "bash");
    EXPECT_EQ(references.front().packages.front().version, "5.1.8-9.el9");
    EXPECT_EQ(references.front().packages.front().type, "rpm");
}

TEST_F(PackageExtractionTest, RpmDatabaseRemovedInALaterLayerIsNotReported)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    ImageBuilder builder;
    builder.addLayer(tarMember(RPM_SQLITE_PATH, rpmSqliteDatabase({rpmHeaderBlob(bash)})) + tarEnd());
    builder.addLayer(tarMember("var/lib/.wh.rpm", "") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().packages.empty());
}

TEST_F(PackageExtractionTest, TruncatedLayerCostsOneReferenceOnly)
{
    ImageBuilder builder;
    auto layer {tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd()};
    layer.resize(layer.size() / 3);
    builder.addLayer(layer);

    ArchiveImageReader reader {builder.writeOciLayout()};

    std::vector<ImageReferenceRecord> references;
    ASSERT_NO_THROW(references = reader.discover().records);
    EXPECT_EQ(references.size(), 1U);
}

TEST_F(PackageExtractionTest, SavedArchiveWithoutAManifestIsSkipped)
{
    const auto directory {std::filesystem::temp_directory_path() / uniqueName()};
    std::filesystem::create_directories(directory);
    const auto path {directory / "not-an-image.tar"};

    {
        std::ofstream stream {path, std::ios::binary};
        const auto archive {tarMember("etc/hostname", "example\n") + tarEnd()};
        stream.write(archive.data(), static_cast<std::streamsize>(archive.size()));
    }

    ArchiveImageReader reader {path.string()};
    EXPECT_TRUE(reader.discover().records.empty());

    std::filesystem::remove_all(directory);
}

TEST_F(PackageExtractionTest, ArchiveKeysThatEscapeTheLayoutAreRejected)
{
    // A saved manifest names its members directly, so a member name is the one place a
    // reference could point outside the image.
    const auto directory {std::filesystem::temp_directory_path() / uniqueName()};
    std::filesystem::create_directories(directory);
    const auto path {directory / "traversal.tar"};

    {
        std::ofstream stream {path, std::ios::binary};
        const auto archive {tarMember("manifest.json",
                                      R"([{"Config":"../../etc/passwd","Layers":["../../../etc/shadow"]}])") + tarEnd()};
        stream.write(archive.data(), static_cast<std::streamsize>(archive.size()));
    }

    ArchiveImageReader reader {path.string()};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().packages.empty());
    EXPECT_TRUE(references.front().configDigest.empty());

    std::filesystem::remove_all(directory);
}

// ---------------------------------------------------------------------------
// Reference types.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, ReferenceTypeNamesMatchTheConfigurationGrammar)
{
    EXPECT_EQ(referenceTypeName(ReferenceType::Registry), "ref");
    EXPECT_EQ(referenceTypeName(ReferenceType::Archive), "archive");
    EXPECT_EQ(referenceTypeName(ReferenceType::EngineStore), "local");

    ReferenceType type {ReferenceType::Registry};
    EXPECT_TRUE(parseReferenceType("archive", type));
    EXPECT_EQ(type, ReferenceType::Archive);
    EXPECT_TRUE(parseReferenceType("local", type));
    EXPECT_EQ(type, ReferenceType::EngineStore);
    EXPECT_TRUE(parseReferenceType("ref", type));
    EXPECT_EQ(type, ReferenceType::Registry);
    EXPECT_FALSE(parseReferenceType("registry", type));
}

TEST_F(PackageExtractionTest, ArchiveAndRegistryReferenceTypesBuildAReader)
{
    EXPECT_NE(makeReader({ReferenceType::Archive, "/some/image.tar"}, {}, {}), nullptr);

    // A registry reference now builds a reader. Whether the reference itself is usable is
    // decided by the reader, not by the factory: an unsupported registry is reported with
    // its own reason at read time rather than being indistinguishable here from a type
    // the module cannot handle at all.
    EXPECT_NE(makeReader({ReferenceType::Registry, "ghcr.io/owner/app:1.0"}, {}, {}), nullptr);
    EXPECT_NE(makeReader({ReferenceType::Registry, "docker.io/library/alpine:latest"}, {}, {}), nullptr);

    // `<local>` names an engine; anything but the ones the module supports builds no reader.
    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "alpine:latest"}, {}, {}), nullptr);
}

TEST_F(PackageExtractionTest, ARegistryReaderWithNoConfigurationFailsItsRead)
{
    // Built with an empty context, which is what a caller that forgot the configuration
    // hands it. The read fails rather than dereferencing nothing.
    const auto reader {makeReader({ReferenceType::Registry, "ghcr.io/owner/app:1.0"}, {}, {})};

    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(reader->sourceType(), "ref");

    const auto result {reader->discover()};

    EXPECT_EQ(result.status, ReadStatus::Failed);
    EXPECT_TRUE(result.records.empty());
}

TEST_F(PackageExtractionTest, ARegistryReaderRejectsAnUnsupportedRegistryWithoutNetwork)
{
    // Rejected while parsing the reference, so no request is attempted and the outcome
    // does not depend on anything being reachable.
    ContainerImagesConfig config;
    const ReaderContext context {&config, nullptr, nullptr};

    const auto reader {makeReader({ReferenceType::Registry, "docker.io/library/alpine:latest"}, {}, context)};

    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(reader->discover().status, ReadStatus::Failed);
}

TEST_F(PackageExtractionTest, TheContainerdAnnotationNamesTheImageAndTheTagOnlyOneAddsNothingNew)
{
    // A saved image carries the whole reference in the containerd annotation and only the tag
    // in the OCI one: one name, and the tag once.
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout(
        R"({"io.containerd.image.name":"docker.io/library/debian:12","org.opencontainers.image.ref.name":"12"})")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().name, "docker.io/library/debian");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"12"}));
}

TEST_F(PackageExtractionTest, AWholeReferenceInTheOciAnnotationIsNormalised)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout(R"({"org.opencontainers.image.ref.name":"example:latest"})")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().name, "docker.io/library/example");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"latest"}));
}

TEST_F(PackageExtractionTest, ABareTagInTheOciAnnotationIsATagWithNoName)
{
    // Layout writers record only the tag there; guessing a repository from it would invent a name.
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout(R"({"org.opencontainers.image.ref.name":"1.4"})")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().name.empty());
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"1.4"}));
}

TEST_F(PackageExtractionTest, AnOciEntryWithNoAnnotationsHasNoNameAndNoTags)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout("{}")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().name.empty());
    EXPECT_TRUE(references.front().tags.empty());
}

TEST_F(PackageExtractionTest, SavedArchiveTagsOfOneRepositoryAreListedUnderOneNormalisedName)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeDockerArchive(R"(["nginx:1","library/nginx:latest","nginx:1"])")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().name, "docker.io/library/nginx");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"1", "latest"}));
}

TEST_F(PackageExtractionTest, SavedArchiveNamesOnAnotherRepositoryAreNotReportedAsTags)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    const auto archive {builder.writeDockerArchive(R"(["ghcr.io/o/r:2","ghcr.io/o/other:3","localhost:5000/r:4"])")};

    ArchiveImageReader reader {archive};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().name, "ghcr.io/o/r");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"2"}));
}

TEST_F(PackageExtractionTest, SavedArchiveWithNoUsableRepoTagHasNoNameAndNoTags)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeDockerArchive(R"(["<none>:<none>"])")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().name.empty());
    EXPECT_TRUE(references.front().tags.empty());
}
