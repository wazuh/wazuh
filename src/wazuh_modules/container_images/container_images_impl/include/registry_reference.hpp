/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_REFERENCE_HPP
#define _REGISTRY_REFERENCE_HPP

#include <string>

namespace containerimages
{
    /// @brief The registry this module supports. Other registries are a follow-up issue,
    /// so a reference naming one is rejected rather than attempted.
    constexpr auto SUPPORTED_REGISTRY {"ghcr.io"};

    /// @brief Tag assumed when a reference names none, matching every registry client.
    constexpr auto DEFAULT_TAG {"latest"};

    /// @brief A registry reference broken into the parts a pull needs.
    ///
    /// Exactly one of @ref tag and @ref digest is set. A digest-pinned reference names
    /// its content directly; a tag-pinned one names something the registry may repoint
    /// at different content later, which is why the two are kept apart rather than
    /// collapsed into one "identifier" string at parse time.
    struct RegistryReference
    {
        std::string registry;   ///< Registry host, e.g. "ghcr.io".
        std::string repository; ///< Repository path, e.g. "owner/app".
        std::string tag;        ///< Tag, when the reference is pinned by tag.
        std::string digest;     ///< Digest, when the reference is pinned by content.

        /// @brief True when the reference names its content directly.
        bool pinnedByDigest() const
        {
            return !digest.empty();
        }

        /// @brief What goes in the manifest request path: the digest, or the tag.
        const std::string& identifier() const
        {
            return pinnedByDigest() ? digest : tag;
        }

        /// @brief The scope a token is requested for.
        std::string pullScope() const
        {
            return "repository:" + repository + ":pull";
        }
    };

    /// @brief Parse a configured `<ref>` value.
    ///
    /// Accepts `host/repository:tag` and `host/repository@algorithm:digest`. A reference
    /// with neither a tag nor a digest takes @ref DEFAULT_TAG.
    ///
    /// @param text      The reference as written in the configuration.
    /// @param reference Filled in when parsing succeeds.
    /// @param error     Filled in when parsing fails, with a reason safe to log.
    /// @return True when @p text is a reference this module can pull.
    bool parseRegistryReference(const std::string& text, RegistryReference& reference, std::string& error);
} // namespace containerimages

#endif // _REGISTRY_REFERENCE_HPP
