/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engine_image_reader.hpp"

#include "archive_image_reader.hpp"
#include "ci_logging_helper.hpp"
#include "oci_metadata.hpp"
#include "registry_reference.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace
{
    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    /// @brief An export stream that adds the bytes it delivered to the scan's count when it is closed.
    ///
    /// The count is what the per-scan allowance is checked against. An export is read twice, once for
    /// the metadata and once for the layers, and the image is charged once: the engine rebuilds the
    /// export for each pass, but the second one is not more of the image. A stream given no count is
    /// not charged. It also tells whether the export got going: it delivered bytes or ended on this
    /// side's own bound.
    class MeteredStream final : public containerimages::IBlobStream
    {
        public:
            MeteredStream(std::unique_ptr<containerimages::IBlobStream> stream, std::uint64_t* scanBytes, bool* engaged)
                : m_stream {std::move(stream)}
                , m_scanBytes {scanBytes}
                , m_engaged {engaged}
            {
            }

            ~MeteredStream() override
            {
                if (m_scanBytes != nullptr)
                {
                    *m_scanBytes += m_stream->bytesDelivered();
                }

                if (m_stream->bytesDelivered() > 0 || m_stream->abortedLocally())
                {
                    *m_engaged = true;
                }
            }

            std::size_t read(char* buffer, const std::size_t size) override
            {
                return m_stream->read(buffer, size);
            }

            bool failed() const override
            {
                return m_stream->failed();
            }

            const std::string& error() const override
            {
                return m_stream->error();
            }

            long status() const override
            {
                return m_stream->status();
            }

            std::uint64_t bytesDelivered() const override
            {
                return m_stream->bytesDelivered();
            }

            bool abortedLocally() const override
            {
                return m_stream->abortedLocally();
            }

            const std::string& retryAfter() const override
            {
                return m_stream->retryAfter();
            }

        private:
            std::unique_ptr<containerimages::IBlobStream> m_stream;
            std::uint64_t* m_scanBytes;
            bool* m_engaged;
    };

    /// An export is a tar, so it carries more than the image size the engine reports: a 512-byte header
    /// and padding to a block for every file, and the configuration and manifest. That is about 768 bytes
    /// a file, so a quarter on top covers images whose files average 3 KiB, and a fixed margin covers the
    /// small ones. The size check before the export stays at the allowance itself.
    constexpr std::uint64_t EXPORT_FRAMING_MARGIN {16ULL * 1024 * 1024};

    /// @brief The most an export may deliver for an image of at most @p maxImageBytes.
    std::uint64_t exportCeiling(const std::uint64_t maxImageBytes)
    {
        const auto headroom {maxImageBytes / 4 + EXPORT_FRAMING_MARGIN};
        return maxImageBytes > std::numeric_limits<std::uint64_t>::max() - headroom
               ? std::numeric_limits<std::uint64_t>::max()
               : maxImageBytes + headroom;
    }

    /// @brief Every digest the image is known by: what its names pin it to, then its configuration,
    /// then the engine's own id when that is neither (an engine that identifies an image by its manifest).
    std::vector<std::string> digestsOf(const containerimages::EngineImage& image, const std::string& configDigest)
    {
        std::vector<std::string> pinned;

        for (const auto& repoDigest : image.repoDigests)
        {
            const auto at {repoDigest.find('@')};

            if (at != std::string::npos && containerimages::oci::isHexDigest(repoDigest.substr(at + 1)))
            {
                pinned.push_back(repoDigest.substr(at + 1));
            }
        }

        auto digests {containerimages::oci::collectDigests(pinned, "", configDigest)};

        if (std::find(digests.begin(), digests.end(), image.id) == digests.end())
        {
            digests.push_back(image.id);
        }

        return digests;
    }

    /// @brief The name and tags of an image: those of its tags, and for an image pulled by digest, which has
    /// none, the repository its digest names. The tags of that case are empty, since the digest says none.
    containerimages::ImageNames namesOf(const containerimages::EngineImage& image)
    {
        auto names {containerimages::imageNamesOf(image.repoTags)};

        for (const auto& repoDigest : image.repoDigests)
        {
            if (!names.name.empty())
            {
                break;
            }

            containerimages::NormalizedImageName normalized;

            if (containerimages::normalizeImageName(repoDigest.substr(0, repoDigest.find('@')), normalized))
            {
                names.name = normalized.name;
            }
        }

        return names;
    }

    const std::string& idOf(const std::string& id)
    {
        return id;
    }

    const std::string& idOf(const std::pair<const std::string, unsigned>& entry)
    {
        return entry.first;
    }

    /// @brief Drop the ids the engine no longer lists, so a set of image ids follows the engine.
    template<typename Ids>
    void forgetUnlisted(Ids* ids, const std::vector<containerimages::EngineImage>& images)
    {
        if (ids == nullptr)
        {
            return;
        }

        for (auto entry = ids->begin(); entry != ids->end();)
        {
            entry = std::any_of(images.begin(), images.end(), [&entry](const containerimages::EngineImage & image)
            {
                return image.id == idOf(*entry);
            }) ? std::next(entry) : ids->erase(entry);
        }
    }

    /// @brief Drop the timeouts counted for images of @p engine that it no longer lists.
    void forgetUnlistedTimeouts(containerimages::ReadTimeouts* timeouts,
                                const std::string& engine,
                                const std::vector<containerimages::EngineImage>& images)
    {
        if (timeouts == nullptr)
        {
            return;
        }

        for (auto entry = timeouts->entries.begin(); entry != timeouts->entries.end();)
        {
            const auto ofEngine {entry->first.rfind(engine + "/", 0) == 0};
            const auto listed {std::any_of(images.begin(), images.end(), [&](const containerimages::EngineImage & image)
            {
                return engine + "/" + image.id == entry->first;
            })};

            entry = ofEngine && !listed ? timeouts->entries.erase(entry) : std::next(entry);
        }
    }

    /// @brief True when the stored record is of this image: its configuration, or any digest it was known by, is the engine's id.
    bool holdsImage(const containerimages::ImageReferenceRecord& stored, const std::string& id)
    {
        return stored.configDigest == id || std::find(stored.digests.begin(), stored.digests.end(), id) != stored.digests.end();
    }
} // namespace

namespace containerimages
{
    EngineImageReader::EngineImageReader(std::string engine, std::shared_ptr<IEngineImageSource> source, ReaderContext context)
        : m_engine {std::move(engine)}
        , m_source {std::move(source)}
        , m_context {context}
    {
    }

    std::string EngineImageReader::sourceType() const
    {
        return referenceTypeName(ReferenceType::EngineStore);
    }

    ImageReadResult EngineImageReader::discover()
    {
        // Same rule as the other readers: nothing escapes to the scan loop, which runs on the module thread.
        try
        {
            std::vector<EngineImage> images;
            std::string error;

            if (!m_source->listImages(images, error))
            {
                logWarn("The '" + m_engine + "' engine could not be read: " + error + ". The images stored for it are kept.");
                return ImageReadResult::failed();
            }

            // Smallest first, so a large export that fails cannot use up the scan allowance before the small
            // images after it are read. Equal sizes keep the engine's order.
            std::stable_sort(images.begin(), images.end(), [](const EngineImage & left, const EngineImage & right)
            {
                return left.size < right.size;
            });

            std::map<std::string, const ImageReferenceRecord*> stored;

            if (m_context.storedEngineImages != nullptr)
            {
                for (const auto& record : *m_context.storedEngineImages)
                {
                    stored.emplace(record.source.location, &record);
                }
            }

            std::vector<ImageReferenceRecord> records;
            std::set<std::string> seen;

            for (const auto& image : images)
            {
                if (m_context.stopRequested != nullptr && m_context.stopRequested->load())
                {
                    logDebug("Stop requested, leaving the images of the '" + m_engine + "' engine.");
                    return ImageReadResult::failed();
                }

                // The id is a key, a path of the export request and the identity of the row: a value that
                // is not a digest is not an image this module can name.
                if (!oci::isHexDigest(image.id))
                {
                    logDebug("Ignoring an image of the '" + m_engine + "' engine with the id '" + image.id.substr(0, 80) +
                             "': it is not a digest.");
                    continue;
                }

                const auto key {m_engine + "/" + image.id};

                if (!seen.insert(key).second)
                {
                    continue;
                }

                const auto known {stored.find(key)};
                auto record {readImage(image, key, known != stored.end() ? known->second : nullptr)};

                if (record)
                {
                    records.push_back(std::move(*record));
                }
            }

            forgetUnlisted(m_context.reportedOversizeImages, images);
            forgetUnlisted(m_context.failedExportImages, images);
            forgetUnlistedTimeouts(m_context.packageReads.timeouts, m_engine, images);

            return ImageReadResult::success(std::move(records));
        }
        catch (const std::exception& ex)
        {
            logWarn("Could not read the '" + m_engine + "' engine: " + ex.what());
        }
        catch (...)
        {
            logWarn("Could not read the '" + m_engine + "' engine: unknown error.");
        }

        return ImageReadResult::failed();
    }

    std::optional<ImageReferenceRecord> EngineImageReader::readImage(const EngineImage& image,
                                                                     const std::string& key,
                                                                     const ImageReferenceRecord* stored)
    {
        const auto names {namesOf(image)};

        // What the engine says about an image now, which holds for a record read this time and for one
        // carried over: its names and digests can change while its contents do not.
        const auto describe = [&](ImageReferenceRecord record)
        {
            record.source = {referenceTypeName(ReferenceType::EngineStore), key};
            record.name = names.name;
            record.tags = names.tags;
            record.digests = digestsOf(image, record.configDigest);
            return record;
        };

        // A row kept because the image could not be read now. It keeps the digests it has: the engine's id
        // among them would make the next scan take the row for this image and never read it, which a row
        // that does not hold the id yet (one upgraded from an earlier schema) must not get.
        const auto keep = [&]() -> std::optional<ImageReferenceRecord>
        {
            if (stored == nullptr)
            {
                return std::nullopt;
            }

            auto kept {describe(*stored)};
            kept.digests = stored->digests;
            return kept;
        };

        if (stored != nullptr && holdsImage(*stored, image.id))
        {
            logDebug("Image '" + key + "' is the one already stored, so it was not exported again.");
            return describe(*stored);
        }

        const auto carry = [&]() -> std::optional<ImageReferenceRecord>
        {
            if (stored == nullptr)
            {
                return std::nullopt;
            }

            logWarn("Image '" + key + "' could not be read. Keeping the " + std::to_string(stored->packages.size()) +
                    " package(s) already stored for it, which are left as they were.");
            return keep();
        };

        const RegistryLimits limits {m_context.config != nullptr ? m_context.config->limits : RegistryLimits {}};

        // The engine says how big an image is, so one over the allowance is not exported at all: reading it
        // would end at the stream's ceiling, after spending up to that much of the scan allowance on an image
        // that is stored nowhere, and the next scan would do the same. The ceiling on the stream stays for a
        // listing that under-reports. Said once per image, not once per scan.
        if (image.size > limits.maxImageBytes)
        {
            if (m_context.reportedOversizeImages == nullptr || m_context.reportedOversizeImages->insert(image.id).second)
            {
                logWarn("Image '" + key + "' was not read: the engine reports " + std::to_string(image.size) +
                        " bytes, over the " + std::to_string(limits.maxImageBytes) + " byte allowance of an image.");
            }

            return keep();
        }

        // An export that failed is skipped for the next few scans: the engine rebuilds it every time, the
        // attempt is charged to the scan, and the images after it would never be read.
        if (m_context.failedExportImages != nullptr)
        {
            const auto failed {m_context.failedExportImages->find(image.id)};

            if (failed != m_context.failedExportImages->end())
            {
                if (failed->second < m_context.failedExportRetryScans)
                {
                    ++failed->second;
                    return keep();
                }

                m_context.failedExportImages->erase(failed);
            }
        }

        if (m_context.scanBytes != nullptr && *m_context.scanBytes >= limits.maxScanBytes)
        {
            // Checked before an image is started, like a registry reference, so the scan stops taking on
            // new work instead of abandoning an image halfway.
            if (!m_scanAllowanceLogged)
            {
                logWarn("The remaining images of the '" + m_engine + "' engine were not read: this scan already reached its " +
                        std::to_string(limits.maxScanBytes) + " byte allowance.");
                m_scanAllowanceLogged = true;
            }

            return carry();
        }

        bool exportEngaged {false};
        bool charged {false};

        const ArchiveOpener open = [&]() -> std::unique_ptr<IByteStream>
        {
            std::string error;
            auto stream {m_source->exportImage(image.id, exportCeiling(limits.maxImageBytes), error)};

            if (!stream)
            {
                logWarn("Image '" + key + "' could not be exported: " + error + ".");
                return nullptr;
            }

            // Only the first pass is charged to the scan.
            const auto scanBytes {charged ? nullptr : m_context.scanBytes};
            charged = true;

            return std::make_unique<MeteredStream>(std::move(stream), scanBytes, &exportEngaged);
        };

        // The archive reader skips the layers when the configuration it finds is the stored one, which
        // covers an engine whose id is not the configuration digest.
        ArchiveImageReader reader {key, stored != nullptr ? stored->configDigest : std::string {}, m_context.stopRequested, open};
        reader.setPackageReadControls(m_context.packageReads);

        auto result {reader.discover()};

        if (result.status == ReadStatus::Unchanged && stored != nullptr)
        {
            return describe(*stored);
        }

        // The image was exported well and a database of it could not be read: it is not held back, the next
        // scan reads it again.
        if (result.transient)
        {
            return keep();
        }

        if (result.status != ReadStatus::Success || result.records.empty())
        {
            const bool stopping = m_context.stopRequested != nullptr && m_context.stopRequested->load();

            // Only an export that got going is held back. One the engine refused, or that was reset before
            // any data, such as when the engine restarts, is simply tried again by the next scan.
            if (exportEngaged && !stopping && m_context.failedExportImages != nullptr &&
                    m_context.failedExportImages->emplace(image.id, 0U).second)
            {
                logWarn("Image '" + key + "' will not be exported again for " + std::to_string(m_context.failedExportRetryScans) +
                        " scans.");
            }

            return carry();
        }

        return describe(std::move(result.records.front()));
    }
} // namespace containerimages
