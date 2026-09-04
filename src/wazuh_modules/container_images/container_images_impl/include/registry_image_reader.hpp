/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_IMAGE_READER_HPP
#define _REGISTRY_IMAGE_READER_HPP

#include "container_images_config.hpp"
#include "credential_provider.hpp"
#include "iimage_reader.hpp"
#include "platform_selection.hpp"
#include "registry_reference.hpp"
#include "registry_transport.hpp"
#include "retry_policy.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace containerimages
{
    /// @brief What a reader needs that is not part of the reference itself.
    ///
    /// Passed to the factory rather than reached for globally, so a reader is
    /// constructible in a test with a stub credential provider and no configuration
    /// file anywhere.
    struct ReaderContext
    {
        const ContainerImagesConfig* config {nullptr};
        const ICredentialProvider* credentials {nullptr};

        /// @brief Bytes already retrieved by this scan, shared across its references so
        /// the per-scan ceiling means something. Not owned.
        std::uint64_t* scanBytes {nullptr};

        /// @brief Set when the module has been asked to stop. Not owned.
        ///
        /// Polled between reads and between retries. Without it a reference being read
        /// from a slow registry keeps the module thread alive past the shutdown budget
        /// that every module shares, which starves the others.
        const std::atomic<bool>* stopRequested {nullptr};
    };

    /// @brief Reads an image, and the packages it contains, from a remote registry.
    ///
    /// The sequence is the one the registry advertises rather than one assumed of it:
    /// an unauthenticated request is answered with a challenge, the challenge names
    /// where to obtain a token, and the token authorizes the manifest and the layers.
    ///
    /// Only the metadata is ever held in memory. Layers are streamed through the same
    /// chain the archive reader uses, so a remote image and a saved one produce the
    /// same inventory from the same bytes.
    class RegistryImageReader final : public IImageReader
    {
        public:
            /// @param location           The reference as written in the configuration.
            /// @param knownConfigDigest  Configuration digest already stored for it, empty
            ///                           when there is none. When the registry still
            ///                           reports that digest no layer is retrieved.
            /// @param context            Configuration and credentials.
            RegistryImageReader(std::string location, std::string knownConfigDigest, ReaderContext context);

            /// @brief Replace the transport, for tests.
            ///
            /// The registry conversation is the part of this class worth testing and the
            /// part that cannot reach a real registry from a unit test. Injecting the
            /// transport is what makes the authentication, the 401 retry and the
            /// unchanged-digest short circuit coverable.
            void setTransport(std::unique_ptr<IRegistryTransport> transport);

            ImageReadResult discover() override;
            std::string sourceType() const override;

        private:
            /// @brief Sleep @p delay in slices, returning false if a stop was requested.
            bool waitOrStop(std::chrono::milliseconds delay) const;

            /// @brief One metadata request, with the retry and back-off policy applied.
            ///
            /// @param authorized When true the bearer token is sent, when there is one.
            bool request(const std::string& url, bool authorized, HttpResponse& response, std::string& error);

            /// @brief Obtain a bearer token for @p challenge, with a credential when the
            /// registry has one configured and anonymously when it does not.
            bool authenticate(const std::string& challengeHeader, std::string& error);

            /// @brief Fetch the manifest or index the reference points at.
            bool fetchManifest(const std::string& identifier, nlohmann::json& document, std::string& error);

            /// @brief Read every layer of @p manifest and compose the package inventory.
            bool readLayers(const nlohmann::json& manifest, ImageReferenceRecord& record, std::string& error);

            std::string m_location;
            std::string m_knownConfigDigest;
            ReaderContext m_context;

            RegistryReference m_reference;
            bool m_transportInjected {false};
            TransportConfig m_transportConfig;
            RetryPolicy m_retryPolicy;
            std::unique_ptr<IRegistryTransport> m_transport;
            std::string m_token;
            bool m_tokenRefreshed {false};
            std::uint64_t m_imageBytes {0};
    };
} // namespace containerimages

#endif // _REGISTRY_IMAGE_READER_HPP
