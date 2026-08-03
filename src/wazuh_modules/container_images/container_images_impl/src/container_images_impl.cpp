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
#include "stub_image_reader.hpp"
#include "ci_logging_helper.hpp"

#include <chrono>
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
    std::unique_ptr<IImageReader> makeReader(const std::string& /*path*/)
    {
        // Real source selection (local OCI, registry, socket) lands in a later stage.
        // Until then the stub reader feeds a fixed inventory through the storage and
        // sync path so it can be validated end to end.
        return std::make_unique<StubImageReader>();
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
        const auto reader {m_readerFactory("")};

        if (!reader)
        {
            return 0;
        }

        logInfo("Scan started.");

        const auto references {reader->discover()};

        const auto deltaCallback = [this](ReturnTypeCallback operation,
                                          const std::string & table,
                                          const std::string & id,
                                          const std::string & data,
                                          std::uint64_t version)
        {
            onDelta(operation, table, id, data, version);
        };

        m_db->syncReferences(references, deltaCallback);
        m_db->syncPackages(references, deltaCallback);

        std::size_t packageCount {0};

        for (const auto& reference : references)
        {
            packageCount += reference.packages.size();
        }

        logInfo("Scan ended. " + std::to_string(references.size()) + " references, " +
                std::to_string(packageCount) + " packages.");

        return packageCount;
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
            m_running = true;
        }

        if (m_config.scanOnStart)
        {
            logDebug("Scan on start.");
            scanOnce();
        }

        std::unique_lock<std::mutex> lock {m_mutex};

        while (m_running)
        {
            if (m_condition.wait_for(lock, std::chrono::seconds(m_config.interval), [this] { return !m_running; }))
            {
                break;
            }

            lock.unlock();
            scanOnce();
            lock.lock();
        }

        logDebug("Module loop finished.");
    }

    void ContainerImagesImpl::stop()
    {
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_running = false;
        }

        m_condition.notify_all();
    }
} // namespace containerimages
