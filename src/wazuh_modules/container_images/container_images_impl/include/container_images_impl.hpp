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
#include "registry_image_reader.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>

namespace containerimages
{
    /// @brief Builds the reader for one configured reference.
    ///
    /// Single seam through which source types are selected. `<archive>` is served by the
    /// archive reader; the reference types that are accepted but not implemented yet
    /// report themselves here and yield no reader, so the configuration grammar does not
    /// change when one of them is implemented.
    std::unique_ptr<IImageReader> makeReader(const ConfiguredReference& reference,
                                            const std::string& knownConfigDigest,
                                            const ReaderContext& context);

    /// @brief Orchestrates the module: owns the configuration, the scan loop and the local
    /// database.
    class ContainerImagesImpl final
    {
        public:
            /// @param config Module configuration.
            /// @param readerFactory Factory used to build a reader (overridable for tests).
            /// @param db Optional database layer (overridable for tests).
            ContainerImagesImpl(ContainerImagesConfig config,
                                std::function<std::unique_ptr<IImageReader>(const ConfiguredReference&, const std::string&, const ReaderContext&)> readerFactory = makeReader,
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

            /// @brief Run a single discovery + persistence pass over the configured sources.
            /// @return Number of image references discovered across every configured source.
            std::size_t scanOnce();

            /// @brief Remove the persisted inventory, keeping the schema.
            ///
            /// Provided for the module disable / uninstall work, which is a follow-up issue:
            /// nothing in the module lifecycle calls it yet.
            void clearInventory();

        private:
            /// @brief Run a scan, absorbing and logging any failure.
            ///
            /// An exception escaping a scan would unwind out of the module thread, which then
            /// exits for the lifetime of the agent. A failing scan must cost one scan only.
            void scanSafely();

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
            std::function<std::unique_ptr<IImageReader>(const ConfiguredReference&, const std::string&, const ReaderContext&)> m_readerFactory;
            std::shared_ptr<ContainerImagesDB> m_db;
            std::shared_ptr<ICredentialProvider> m_credentials;
            std::uint64_t m_scanBytes {0};
            bool m_running {false};
            bool m_stopRequested {false};
            std::mutex m_mutex;

            /// @brief The same request as @ref m_stopRequested, readable without the lock.
            ///
            /// A reader streaming a layer has to be able to notice a stop between two
            /// reads, and it cannot take the scan mutex to do it. Both are set in stop();
            /// the flag is what a long-running read polls.
            std::atomic<bool> m_stopFlag {false};
            std::condition_variable m_condition;
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_IMPL_HPP
