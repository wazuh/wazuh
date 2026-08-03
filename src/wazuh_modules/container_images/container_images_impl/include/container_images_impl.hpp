/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_IMPL_HPP
#define _CONTAINER_IMAGES_IMPL_HPP

#include "container_images_config.hpp"
#include "container_images_db.hpp"
#include "iimage_reader.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

namespace containerimages
{
    /// @brief Builds the reader used to gather the inventory for a scan.
    ///
    /// Single seam through which future source types are selected. At this stage it
    /// returns the temporary in-memory stub reader, so the persistence and sync path
    /// can be exercised before real package extraction lands.
    std::unique_ptr<IImageReader> makeReader(const std::string& path);

    /// @brief Orchestrates the module: owns the configuration, the scan loop and the local
    /// database.
    class ContainerImagesImpl final
    {
        public:
            /// @param config Module configuration.
            /// @param readerFactory Factory used to build a reader (overridable for tests).
            /// @param db Optional database layer (overridable for tests).
            ContainerImagesImpl(ContainerImagesConfig config,
                                std::function<std::unique_ptr<IImageReader>(const std::string&)> readerFactory = makeReader,
                                std::shared_ptr<ContainerImagesDB> db = nullptr);

            /// @brief Run the scan loop until stop() is called. Blocks the caller.
            ///
            /// Returns without scanning when stop() was already called: the shutdown loop
            /// signals every module before joining any of them, so a stop can arrive
            /// before the module thread ever gets here.
            void run();

            /// @brief Signal the scan loop to finish and wake it up.
            ///
            /// Latches the request, so a stop that arrives before run() is not lost.
            void stop();

            /// @brief Run a single discovery + persistence pass. Returns the package count.
            std::size_t scanOnce();

            /// @brief Remove the persisted inventory, keeping the schema.
            void clearInventory();

        private:
            /// @brief Report one already-extracted delta.
            ///
            /// Logging only at this stage. Handing deltas to the manager is the job of the
            /// synchronization layer, which plugs in here.
            void onDelta(ReturnTypeCallback operation,
                         const std::string& table,
                         const std::string& id,
                         const std::string& data,
                         std::uint64_t version);

            ContainerImagesConfig m_config;
            std::function<std::unique_ptr<IImageReader>(const std::string&)> m_readerFactory;
            std::shared_ptr<ContainerImagesDB> m_db;
            bool m_running {false};
            bool m_stopRequested {false};
            std::mutex m_mutex;
            std::condition_variable m_condition;
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_IMPL_HPP
