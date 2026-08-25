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
#include "local_image_reader.hpp"
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
    std::unique_ptr<IImageReader> makeReader(const std::string& path)
    {
        return std::make_unique<LocalImageReader>(path);
    }

    ContainerImagesImpl::ContainerImagesImpl(ContainerImagesConfig config,
                                             std::function<std::unique_ptr<IImageReader>(const std::string&)> readerFactory,
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
        if (m_config.localPaths.empty())
        {
            logInfo("No local sources configured, nothing to scan.");
            return 0;
        }

        logInfo("Scan started.");

        std::vector<ImageReferenceRecord> references;

        for (const auto& path : m_config.localPaths)
        {
            const auto reader {m_readerFactory(path)};

            if (!reader)
            {
                continue;
            }

            for (auto& reference : reader->discover())
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
