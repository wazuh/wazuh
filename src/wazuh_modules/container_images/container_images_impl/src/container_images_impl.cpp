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
} // namespace

namespace containerimages
{
    std::unique_ptr<IImageReader> makeReader(const std::string& path)
    {
        return std::make_unique<LocalImageReader>(path);
    }

    ContainerImagesImpl::ContainerImagesImpl(ContainerImagesConfig config,
                                             std::function<std::unique_ptr<IImageReader>(const std::string&)> readerFactory)
        : m_config {std::move(config)}
        , m_readerFactory {std::move(readerFactory)}
    {
    }

    std::size_t ContainerImagesImpl::scanOnce()
    {
        if (m_config.localPaths.empty())
        {
            logInfo("No local sources configured, nothing to scan.");
            return 0;
        }

        logInfo("Scan started.");

        std::size_t total = 0;

        for (const auto& path : m_config.localPaths)
        {
            const auto reader = m_readerFactory(path);

            if (!reader)
            {
                continue;
            }

            const auto references = reader->discover();

            for (const auto& reference : references)
            {
                logDebug("Discovered image reference " + reference.source.location + " (" + reference.source.sourceType +
                         ") digest=" + reference.configDigest + ".");
            }

            total += references.size();
        }

        logInfo("Scan ended. Discovered " + std::to_string(total) + " image references.");
        return total;
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
