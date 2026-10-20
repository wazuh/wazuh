/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
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
#include "package_db_parser.hpp"

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
            std::string writeDockerArchive()
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
                                     R"([{"Config":")" + CONFIG_DIGEST + R"(.json","RepoTags":["example:latest"],"Layers":[)" +
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
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, "not parsed") +
                              tarMember("var/lib/pacman/local/desc", "not parsed") +
                              tarEnd()));

    EXPECT_TRUE(composer.packages().empty());
    EXPECT_EQ(composer.unsupportedFormats(), std::set<std::string>({"rpm", "pacman"}));
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
    // retracted the same way a tracked database is: an image whose rpm directory is
    // removed in a later layer should not keep reporting rpm once nothing rpm-shaped
    // survives composition.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, "not parsed") + tarEnd()));
    EXPECT_EQ(composer.unsupportedFormats(), std::set<std::string>({"rpm"}));

    composer.apply(snapshotOf(tarMember("var/lib/.wh.rpm", "") + tarEnd()));

    EXPECT_TRUE(composer.unsupportedFormats().empty());
}

// ---------------------------------------------------------------------------
// Package database parsers.
// ---------------------------------------------------------------------------

TEST_F(PackageExtractionTest, DpkgParserMapsEveryField)
{
    const DpkgParser parser;
    const auto packages {parser.parse(dpkgStanza("curl", "7.88.1-10"), DPKG_STATUS_PATH)};

    ASSERT_EQ(packages.size(), 1U);

    const auto& package {packages.front()};
    EXPECT_EQ(package.name, "curl");
    EXPECT_EQ(package.version, "7.88.1-10");
    EXPECT_EQ(package.architecture, "amd64");
    EXPECT_EQ(package.type, "deb");
    EXPECT_EQ(package.vendor, "Debian curl Maintainers <team@debian.org>");
    EXPECT_EQ(package.category, "utils");
    EXPECT_EQ(package.priority, "optional");
    EXPECT_EQ(package.multiarch, "same");
    EXPECT_EQ(package.source, "curl-source");
    EXPECT_EQ(package.packageDbPath, DPKG_STATUS_PATH);
    // dpkg reports kibibytes, the inventory stores bytes.
    EXPECT_EQ(package.size, 100 * 1024);
    // Only the short description, not the continuation lines.
    EXPECT_EQ(package.description, "short description of curl");
}

TEST_F(PackageExtractionTest, DpkgParserReportsInstalledPackagesOnly)
{
    const DpkgParser parser;
    const auto content {dpkgStanza("curl", "7.0") +
                        dpkgStanza("wget", "1.0", "amd64", "deinstall ok config-files") +
                        dpkgStanza("nano", "5.0", "amd64", "install ok half-configured") +
                        dpkgStanza("tar", "1.34")};

    EXPECT_EQ(packageNames(parser.parse(content, DPKG_STATUS_PATH)), std::vector<std::string>({"curl", "tar"}));
}

TEST_F(PackageExtractionTest, DpkgParserSkipsStanzasWithoutAName)
{
    const DpkgParser parser;
    EXPECT_TRUE(parser.parse("Status: install ok installed\nVersion: 1.0\n", DPKG_STATUS_PATH).empty());
}

TEST_F(PackageExtractionTest, DpkgParserSurvivesMalformedContent)
{
    const DpkgParser parser;
    EXPECT_NO_THROW(parser.parse("Installed-Size: not-a-number\nPackage: curl\nStatus: install ok installed\n",
                                 DPKG_STATUS_PATH));
    EXPECT_EQ(parser.parse("Installed-Size: not-a-number\nPackage: curl\nStatus: install ok installed\n",
                           DPKG_STATUS_PATH).front().size, 0);
}

TEST_F(PackageExtractionTest, ApkParserMapsEveryField)
{
    const ApkParser parser;
    const auto packages {parser.parse(apkStanza("busybox", "1.36.1-r5"), APK_DB_PATH)};

    ASSERT_EQ(packages.size(), 1U);

    const auto& package {packages.front()};
    EXPECT_EQ(package.name, "busybox");
    EXPECT_EQ(package.version, "1.36.1-r5");
    EXPECT_EQ(package.architecture, "x86_64");
    EXPECT_EQ(package.type, "apk");
    EXPECT_EQ(package.vendor, "Alpine busybox Maintainers <team@alpinelinux.org>");
    EXPECT_EQ(package.source, "busybox-origin");
    EXPECT_EQ(package.description, "short description of busybox");
    EXPECT_EQ(package.packageDbPath, APK_DB_PATH);
    // The apk database reports bytes already.
    EXPECT_EQ(package.size, 2048);
}

TEST_F(PackageExtractionTest, ApkParserReadsSeveralStanzas)
{
    const ApkParser parser;
    const auto content {apkStanza("busybox", "1.36") + apkStanza("musl", "1.2.4") + apkStanza("apk-tools", "2.14")};

    EXPECT_EQ(packageNames(parser.parse(content, APK_DB_PATH)),
              std::vector<std::string>({"apk-tools", "busybox", "musl"}));
}

TEST_F(PackageExtractionTest, ApkParserSkipsStanzasWithoutAName)
{
    const ApkParser parser;
    EXPECT_TRUE(parser.parse("V:1.0\nA:x86_64\n", APK_DB_PATH).empty());
}

TEST_F(PackageExtractionTest, BothApkDatabaseLocationsAreTracked)
{
    const auto& databases {knownPackageDatabases()};

    const auto tracked = [&databases](const std::string & path)
    {
        return std::any_of(databases.begin(), databases.end(), [&path](const PackageDbLocation & location)
        {
            return location.path == path && location.parser != nullptr;
        });
    };

    EXPECT_TRUE(tracked(APK_DB_PATH));
    // Wolfi and Chainguard images keep the database under /usr.
    EXPECT_TRUE(tracked(APK_USR_DB_PATH));
}

TEST_F(PackageExtractionTest, WolfiStyleApkDatabaseIsInventoried)
{
    const auto snapshot {snapshotOf(tarMember(APK_USR_DB_PATH, apkStanza("wolfi-base", "1.0")) + tarEnd())};

    LayerComposer composer;
    composer.apply(snapshot);

    EXPECT_EQ(packageNames(composer.packages()), std::vector<std::string>({"wolfi-base"}));
}

TEST_F(PackageExtractionTest, RpmParserMapsEveryFieldOfASqliteDatabase)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";
    bash.release = "9.el9";
    bash.architecture = "x86_64";
    bash.summary = "The GNU Bourne Again shell";
    bash.vendor = "Rocky Enterprise Software Foundation";
    bash.group = "Unspecified";
    bash.sourceRpm = "bash-5.1.8-9.el9.src.rpm";
    bash.size = 7802001;
    bash.installTime = 1700000000;

    const RpmParser parser;
    const auto packages {parser.parse(rpmSqliteDatabase({rpmHeaderBlob(bash)}), RPM_SQLITE_PATH)};

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "bash");
    EXPECT_EQ(packages.front().version, "5.1.8-9.el9");
    EXPECT_EQ(packages.front().architecture, "x86_64");
    EXPECT_EQ(packages.front().type, "rpm");
    EXPECT_EQ(packages.front().vendor, "Rocky Enterprise Software Foundation");
    EXPECT_EQ(packages.front().category, "Unspecified");
    EXPECT_EQ(packages.front().description, "The GNU Bourne Again shell");
    EXPECT_EQ(packages.front().source, "bash-5.1.8-9.el9.src.rpm");
    EXPECT_EQ(packages.front().size, 7802001);
    EXPECT_EQ(packages.front().packageDbPath, RPM_SQLITE_PATH);
    EXPECT_FALSE(packages.front().installed.empty());
}

TEST_F(PackageExtractionTest, RpmParserReadsADatabaseInWriteAheadLogMode)
{
    // The rpmdb.sqlite an image layer carries is in write-ahead log mode. Reading it from
    // the layer bytes has to account for that, or every current Red Hat and Fedora image
    // is inventoried with no packages.
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    auto database {rpmSqliteDatabase({rpmHeaderBlob(bash)})};
    database[18] = 2;
    database[19] = 2;

    const RpmParser parser;
    EXPECT_EQ(packageNames(parser.parse(database, RPM_SQLITE_PATH)), std::vector<std::string>({"bash"}));
}

TEST_F(PackageExtractionTest, RpmParserMapsEveryFieldOfAnNdbDatabase)
{
    RpmPackage aaaBase;
    aaaBase.name = "aaa_base";
    aaaBase.version = "84.87";
    aaaBase.release = "150300.10.20.1";
    aaaBase.vendor = "SUSE LLC";

    const RpmParser parser;
    const auto packages {parser.parse(rpmNdbDatabase({rpmHeaderBlob(aaaBase)}), RPM_NDB_PATH)};

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().name, "aaa_base");
    EXPECT_EQ(packages.front().version, "84.87-150300.10.20.1");
    EXPECT_EQ(packages.front().type, "rpm");
    EXPECT_EQ(packages.front().vendor, "SUSE LLC");
    EXPECT_EQ(packages.front().packageDbPath, RPM_NDB_PATH);
}

TEST_F(PackageExtractionTest, RpmParserReadsEveryPackageOfADatabase)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    RpmPackage glibc;
    glibc.name = "glibc";
    glibc.version = "2.34";

    const RpmParser parser;

    EXPECT_EQ(packageNames(parser.parse(rpmSqliteDatabase({rpmHeaderBlob(bash), rpmHeaderBlob(glibc)}), RPM_SQLITE_PATH)),
              std::vector<std::string>({"bash", "glibc"}));
    EXPECT_EQ(packageNames(parser.parse(rpmNdbDatabase({rpmHeaderBlob(bash), rpmHeaderBlob(glibc)}), RPM_NDB_PATH)),
              std::vector<std::string>({"bash", "glibc"}));
}

TEST_F(PackageExtractionTest, RpmParserKeepsTheEpochInTheVersion)
{
    // rpm orders versions by epoch first, so a version that carries one is only correct
    // with the epoch kept, exactly as the package manager prints it.
    RpmPackage gdbm;
    gdbm.name = "gdbm-libs";
    gdbm.version = "1.19";
    gdbm.release = "4.el9";
    gdbm.hasEpoch = true;
    gdbm.epoch = 1;

    const RpmParser parser;
    const auto packages {parser.parse(rpmSqliteDatabase({rpmHeaderBlob(gdbm)}), RPM_SQLITE_PATH)};

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().version, "1:1.19-4.el9");
}

TEST_F(PackageExtractionTest, RpmParserReportsAPackageWithNoEpochWithoutAPrefix)
{
    RpmPackage basesystem;
    basesystem.name = "basesystem";
    basesystem.version = "11";
    basesystem.release = "13.el9";

    const RpmParser parser;
    const auto packages {parser.parse(rpmSqliteDatabase({rpmHeaderBlob(basesystem)}), RPM_SQLITE_PATH)};

    ASSERT_EQ(packages.size(), 1U);
    EXPECT_EQ(packages.front().version, "11-13.el9");
}

TEST_F(PackageExtractionTest, RpmParserSkipsTheSigningKeys)
{
    // rpm keeps its trusted keys as packages in the same database. They are not installed
    // software and the host package inventory drops them the same way.
    RpmPackage key;
    key.name = "gpg-pubkey";
    key.version = "3228467c";

    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    const RpmParser parser;
    const auto packages {parser.parse(rpmSqliteDatabase({rpmHeaderBlob(key), rpmHeaderBlob(bash)}), RPM_SQLITE_PATH)};

    EXPECT_EQ(packageNames(packages), std::vector<std::string>({"bash"}));
}

TEST_F(PackageExtractionTest, RpmParserReportsNothingForContentThatIsNoDatabase)
{
    const RpmParser parser;

    EXPECT_TRUE(parser.parse("", RPM_SQLITE_PATH).empty());
    EXPECT_TRUE(parser.parse("not a database at all", RPM_SQLITE_PATH).empty());
    EXPECT_TRUE(parser.parse(std::string("SQLite format 3\0 truncated", 26), RPM_SQLITE_PATH).empty());
    EXPECT_TRUE(parser.parse(std::string("RpmP", 4) + std::string(60, '\0'), RPM_NDB_PATH).empty());
}

TEST_F(PackageExtractionTest, RpmParserSurvivesATruncatedDatabase)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    const RpmParser parser;
    const auto sqlite {rpmSqliteDatabase({rpmHeaderBlob(bash)})};
    const auto ndb {rpmNdbDatabase({rpmHeaderBlob(bash)})};

    // Half a database is not a database. Nothing is reported and nothing throws.
    EXPECT_NO_THROW(parser.parse(sqlite.substr(0, sqlite.size() / 2), RPM_SQLITE_PATH));
    EXPECT_TRUE(parser.parse(ndb.substr(0, ndb.size() - 16), RPM_NDB_PATH).empty());
}

TEST_F(PackageExtractionTest, RpmParserSkipsABlobItCannotRead)
{
    RpmPackage bash;
    bash.name = "bash";
    bash.version = "5.1.8";

    const RpmParser parser;
    const auto packages
    {
        parser.parse(rpmSqliteDatabase({std::string("\xff\xff\xff\xff\x00\x00\x00\x10", 8), rpmHeaderBlob(bash)}),
                     RPM_SQLITE_PATH)
    };

    // A blob declaring more index entries than it carries costs its own package only.
    EXPECT_EQ(packageNames(packages), std::vector<std::string>({"bash"}));
}

TEST_F(PackageExtractionTest, EveryRpmDatabaseLocationIsTracked)
{
    const auto& databases {knownPackageDatabases()};

    const auto tracked = [&databases](const std::string & path)
    {
        return std::any_of(databases.begin(), databases.end(), [&path](const PackageDbLocation & location)
        {
            return location.path == path && location.parser != nullptr && location.parser->format() == "rpm";
        });
    };

    // The Red Hat family keeps the database under /var, Fedora and the SUSE family under
    // /usr, and both formats occur at both locations.
    EXPECT_TRUE(tracked(RPM_SQLITE_PATH));
    EXPECT_TRUE(tracked(RPM_SQLITE_USR_PATH));
    EXPECT_TRUE(tracked(RPM_NDB_PATH));
    EXPECT_TRUE(tracked(RPM_NDB_USR_PATH));
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

TEST_F(PackageExtractionTest, BerkeleyDbImageIsReportedAsAnUnsupportedFormat)
{
    // Reading it needs libdb pointed at the whole directory, so an image still carrying
    // the pre-4.16 format is reported rather than parsed.
    LayerComposer composer;
    composer.apply(snapshotOf(tarMember(RPM_BDB_PATH, "a Berkeley DB hash file") +
                              tarMember("var/lib/rpm/__db.001", "") + tarEnd()));

    EXPECT_TRUE(composer.packages().empty());
    EXPECT_EQ(composer.unsupportedFormats(), std::set<std::string>({"rpm"}));
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
    EXPECT_EQ(references.front().tag, "example:latest");
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
    EXPECT_EQ(references.front().tag, "example:latest");
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
    builder.addLayer(tarMember(RPM_BDB_PATH, "a Berkeley DB this module does not read") + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout()};
    const auto references {reader.discover().records};

    // The reference is still inventoried, so the scan reports the image it found.
    ASSERT_EQ(references.size(), 1U);
    EXPECT_TRUE(references.front().packages.empty());
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

TEST_F(PackageExtractionTest, OnlyTheArchiveReferenceTypeBuildsAReader)
{
    EXPECT_NE(makeReader({ReferenceType::Archive, "/some/image.tar"}, {}), nullptr);
    // Accepted by the configuration, reported as unimplemented here.
    EXPECT_EQ(makeReader({ReferenceType::Registry, "docker.io/library/alpine:latest"}, {}), nullptr);
    EXPECT_EQ(makeReader({ReferenceType::EngineStore, "alpine:latest"}, {}), nullptr);
}

TEST_F(PackageExtractionTest, WholeImageNameIsPreferredOverTheTagOnlyAnnotation)
{
    // A saved image carries the whole reference in the containerd annotation and only the tag
    // in the OCI one, so the display name comes from the first and both are reported.
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout(
        R"({"io.containerd.image.name":"docker.io/library/debian:12","org.opencontainers.image.ref.name":"12"})")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().tag, "docker.io/library/debian:12");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"docker.io/library/debian:12", "12"}));
}

TEST_F(PackageExtractionTest, TagOnlyAnnotationIsUsedWhenItIsTheOnlyOne)
{
    ImageBuilder builder;
    builder.addLayer(tarMember(DPKG_STATUS_PATH, dpkgStanza("curl", "7.0")) + tarEnd());

    ArchiveImageReader reader {builder.writeOciLayout(R"({"org.opencontainers.image.ref.name":"example:latest"})")};
    const auto references {reader.discover().records};

    ASSERT_EQ(references.size(), 1U);
    EXPECT_EQ(references.front().tag, "example:latest");
    EXPECT_EQ(references.front().tags, std::vector<std::string>({"example:latest"}));
}
