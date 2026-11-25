/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_REFERENCE_HPP
#define _REGISTRY_REFERENCE_HPP

#include "registry_profile.hpp"

#include <string>

namespace containerimages
{
    /// @brief Tag assumed when a reference names none, matching every registry client.
    constexpr auto DEFAULT_TAG {"latest"};

    /// @brief A registry reference broken into the parts a pull needs.
    ///
    /// At least one of @ref tag and @ref digest is set. A digest-pinned reference names
    /// its content directly; a tag-pinned one names something the registry may repoint
    /// at different content later, which is why the two are kept apart rather than
    /// collapsed into one "identifier" string at parse time. When both were written,
    /// the digest is what is pulled and the tag is only kept.
    struct RegistryReference
    {
        std::string registry;   ///< Registry host, e.g. "ghcr.io".
        RegistryProfile profile; ///< How that registry is authenticated and read.
        std::string repository; ///< Repository path, e.g. "owner/app".
        std::string tag;        ///< Tag, when the reference carries one.
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

        /// @brief The name the image is stored under: `registry/repository[:tag][@digest]`.
        ///
        /// The repository is part of it, since the same tag names different images in
        /// different repositories, and the tag stays when a digest follows it.
        std::string fullName() const
        {
            auto name {taggedName()};

            if (name.empty())
            {
                name = registry + "/" + repository;
            }

            return pinnedByDigest() ? name + "@" + digest : name;
        }

        /// @brief `registry/repository`: the image's name, with neither tag nor digest.
        std::string name() const
        {
            return registry + "/" + repository;
        }

        /// @brief `registry/repository:tag`, empty when the reference carries no tag.
        std::string taggedName() const
        {
            if (tag.empty())
            {
                return {};
            }

            return registry + "/" + repository + ":" + tag;
        }

        /// @brief The scope a token is requested for.
        std::string pullScope() const
        {
            return "repository:" + repository + ":pull";
        }

        /// @brief `registry/organization`: the registry and the first path segment of the repository.
        ///
        /// What a refusal of the credential at the token endpoint is remembered under for the
        /// rest of a scan. A registry such as GHCR can answer per organization, so one
        /// organization's refusal says nothing about another's on the same host.
        ///
        /// A private Amazon ECR registry answers per repository, since access is granted
        /// per repository and an account has no organizations, so its scope is the host and
        /// the whole repository.
        std::string refusalScope() const
        {
            if (profile.kind == RegistryKind::EcrPrivate)
            {
                return registry + "/" + repository;
            }

            return registry + "/" + repository.substr(0, repository.find('/'));
        }
    };

    /// @brief True if @p tag matches the OCI character set `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
    bool isSafeTag(const std::string& tag);

    /// @brief An image reference written the way any container client accepts it, split into the
    ///        parts the shared container block reports.
    struct NormalizedImageName
    {
        std::string name;   ///< `registry/repository`, with the registry and `library/` made explicit.
        std::string tag;    ///< Tag, or @ref DEFAULT_TAG when the text names neither tag nor digest.
        std::string digest; ///< Digest, when the text is pinned by content.
    };

    /// @brief Normalise an image reference to its full name, as a container engine does.
    ///
    /// A first component with no '.' or ':' that is not `localhost` is a repository path, not a
    /// registry, so `nginx` and `library/nginx:1` both live on `docker.io`, and a single-component
    /// Docker Hub repository sits under `library/`: `nginx` is `docker.io/library/nginx`. Unlike
    /// @ref parseRegistryReference this accepts any registry, since it only names an image and
    /// pulls nothing.
    ///
    /// @param text       A reference such as a saved image's `RepoTags` entry.
    /// @param normalized Filled in when @p text is a well-formed reference.
    /// @return False when @p text is not a reference (for example `<none>:<none>`).
    bool normalizeImageName(const std::string& text, NormalizedImageName& normalized);

    /// @brief Parse a configured `<ref>` value.
    ///
    /// Accepts `host/repository:tag`, `host/repository@algorithm:digest` and
    /// `host/repository:tag@algorithm:digest`, where the digest wins. A reference with
    /// neither a tag nor a digest takes @ref DEFAULT_TAG. The host must be one the module
    /// has a registry profile for, and the profile decides how many path components the
    /// repository needs.
    ///
    /// @param text      The reference as written in the configuration.
    /// @param reference Filled in when parsing succeeds.
    /// @param error     Filled in when parsing fails, with a reason safe to log.
    /// @return True when @p text is a reference this module can pull.
    bool parseRegistryReference(const std::string& text, RegistryReference& reference, std::string& error);
} // namespace containerimages

#endif // _REGISTRY_REFERENCE_HPP
