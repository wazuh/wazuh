/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_images_impl.hpp"
#include "archive_image_reader.hpp"
#include "ci_logging_helper.hpp"

#include <chrono>
#include <exception>
#include <utility>

namespace
{
    void logInfo(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_INFO, message);
    }

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    void logError(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, message);
    }

    std::string operationName(ReturnTypeCallback operation)
    {
        switch (operation)
        {
            case INSERTED: return "created";
            case MODIFIED: return "modified";
            case DELETED: return "deleted";
            default: return "unknown";
        }
    }
} // namespace

namespace containerimages
{
    std::unique_ptr<IImageReader> makeReader(const ConfiguredReference& reference,
                                            const std::string& knownConfigDigest)
    {
        switch (reference.type)
        {
            case ReferenceType::Archive:
                return std::make_unique<ArchiveImageReader>(reference.location, knownConfigDigest);

            case ReferenceType::Registry:
                logWarn("NOT IMPLEMENTED: the '<ref>' reference '" + reference.location +
                        "' needs remote registry support, which is not available yet. Skipping it.");
                return nullptr;

            case ReferenceType::EngineStore:
                logWarn("NOT IMPLEMENTED: the '<local>' reference '" + reference.location +
                        "' needs container engine support, which is not available yet. Skipping it.");
                return nullptr;

            default:
                logWarn("Unknown reference type for '" + reference.location + "', skipping it.");
                return nullptr;
        }
    }

    ContainerImagesImpl::ContainerImagesImpl(ContainerImagesConfig config,
                                             std::function<std::unique_ptr<IImageReader>(const ConfiguredReference&, const std::string&)> readerFactory,
                                             std::shared_ptr<ContainerImagesDB> db)
        : m_config {std::move(config)}
        , m_readerFactory {std::move(readerFactory)}
        , m_db {db ? std::move(db) : std::make_shared<ContainerImagesDB>(m_config.dbPath)}
    {
    }

    void ContainerImagesImpl::onDelta(ReturnTypeCallback operation,
                                      const std::string& table,
                                      const std::string& id,
                                      const std::string& data,
                                      std::uint64_t version)
    {
        // The delta payload and version are already extracted here so the synchronization
        // layer can be attached at this point without reshaping the storage code.
        (void)data;
        (void)version;

        logDebug("Inventory " + operationName(operation) + " in " + table + ": " + id + ".");
    }

    void ContainerImagesImpl::clearInventory()
    {
        m_db->dropTables();
    }

    std::size_t ContainerImagesImpl::scanOnce()
    {
        if (m_config.references.empty())
        {
            logInfo("No references configured, nothing to scan.");
            return 0;
        }

        logInfo("Scan started.");

        std::vector<ImageReferenceRecord> references;

        std::size_t unreadable {0};
        std::size_t unchanged {0};

        for (const auto& configured : m_config.references)
        {
            {
                // Checked once per reference rather than continuously inside a reader: a
                // reader already in progress runs to completion (bounded work is the
                // reader's own job, see the caps in ArchiveImageReader), but a stop that
                // lands mid-scan stops the scan from starting any reference it has not
                // reached yet, instead of reading every configured source regardless.
                std::lock_guard<std::mutex> lock {m_mutex};

                if (m_stopRequested)
                {
                    // Abandoned, not finished. What was collected so far describes only the
                    // references the scan reached, and storing it would report every
                    // reference it never got to as deleted.
                    logDebug("Stop requested, abandoning the scan without storing its partial result.");
                    return 0;
                }
            }

            auto stored {m_db->loadStored(referenceTypeName(configured.type), configured.location)};
            const auto reader {m_readerFactory(configured, stored ? stored->configDigest : std::string {})};

            if (!reader)
            {
                continue;
            }

            auto result {reader->discover()};

            if (result.status == ReadStatus::Unchanged)
            {
                // The image still reports the digest already stored, so its layers were not
                // read. What is stored is its current inventory, and it is handed back so
                // the storage layer sees it as present rather than gone.
                ++unchanged;

                if (stored)
                {
                    references.push_back(std::move(*stored));
                }

                continue;
            }

            if (result.status == ReadStatus::Failed)
            {
                // A reference that could not be read says nothing about what it holds, so
                // its stored inventory is carried into this scan unchanged. Leaving it out
                // would hand the storage layer an empty set for that reference, and every
                // record it owns would be reported as deleted on a scan that never saw it.
                ++unreadable;

                if (stored)
                {
                    logWarn("Reference '" + configured.location + "' could not be read. Keeping the " +
                            std::to_string(stored->packages.size()) +
                            " package(s) already stored for it, which are left as they were.");
                    references.push_back(std::move(*stored));
                }
                else
                {
                    logWarn("Reference '" + configured.location + "' could not be read, and nothing is stored for it.");
                }

                continue;
            }

            for (auto& reference : result.records)
            {
                logDebug("Discovered image reference " + reference.source.location + " (" + reference.source.sourceType +
                         ") digest=" + reference.configDigest + ".");
                references.push_back(std::move(reference));
            }
        }

        const auto deltaCallback = [this](ReturnTypeCallback operation,
                                          const std::string & table,
                                          const std::string & id,
                                          const std::string & data,
                                          std::uint64_t version)
        {
            onDelta(operation, table, id, data, version);
        };

        // Every configured source is synced as one set, so a reference that disappeared
        // since the last scan is reported as deleted instead of surviving as stale state.
        m_db->syncReferences(references, deltaCallback);
        m_db->syncPackages(references, deltaCallback);

        std::size_t packageCount {0};

        for (const auto& reference : references)
        {
            packageCount += reference.packages.size();
        }

        if (unreadable > 0)
        {
            logWarn("Scan ended with " + std::to_string(unreadable) +
                    " reference(s) that could not be read. Their inventory is the one stored by an earlier scan.");
        }

        if (unchanged > 0)
        {
            logDebug(std::to_string(unchanged) +
                     " reference(s) still hold the image already stored, so their layers were not read.");
        }

        logInfo("Scan ended. " + std::to_string(references.size()) + " references, " +
                std::to_string(packageCount) + " packages.");

        return references.size();
    }

    void ContainerImagesImpl::scanSafely()
    {
        try
        {
            scanOnce();
        }
        catch (const std::exception& ex)
        {
            logError(std::string {"Scan failed: "} + ex.what());
        }
    }

    void ContainerImagesImpl::run()
    {
        if (!m_config.enabled)
        {
            logInfo("Module is disabled.");
            return;
        }

        {
            std::lock_guard<std::mutex> lock {m_mutex};

            if (m_stopRequested)
            {
                logDebug("Stop requested before the module started, not scanning.");
                return;
            }

            m_running = true;
        }

        if (m_config.scanOnStart)
        {
            logDebug("Scan on start.");
            scanSafely();
        }

        std::unique_lock<std::mutex> lock {m_mutex};

        while (m_running)
        {
            if (m_condition.wait_for(lock, std::chrono::seconds(m_config.interval), [this] { return !m_running; }))
            {
                break;
            }

            lock.unlock();
            scanSafely();
            lock.lock();
        }

        logDebug("Module loop finished.");
    }

    void ContainerImagesImpl::stop()
    {
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_stopRequested = true;
            m_running = false;
        }

        m_condition.notify_all();
    }
} // namespace containerimages
