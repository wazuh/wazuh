/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_reference.hpp"

#include "oci_metadata.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace
{
    /// @brief Split a path on '/', keeping empty components so they can be rejected.
    std::vector<std::string> splitPath(const std::string& path)
    {
        std::vector<std::string> components;
        std::string::size_type start {0};

        while (true)
        {
            const auto separator {path.find('/', start)};

            if (separator == std::string::npos)
            {
                components.push_back(path.substr(start));
                break;
            }

            components.push_back(path.substr(start, separator - start));
            start = separator + 1;
        }

        return components;
    }

    /// @brief True if a repository path component matches the OCI character set.
    ///
    /// The specification allows lower-case alphanumerics with '.', '_' and '-' as
    /// separators between them. Enforcing it here means a reference can never introduce a
    /// path traversal, an authority, or a query string into a request URL built from it,
    /// so the transport does not have to escape anything.
    bool isSafePathComponent(const std::string& component)
    {
        if (component.empty())
        {
            return false;
        }

        const auto isAlphanumeric = [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9');
        };

        if (!isAlphanumeric(component.front()) || !isAlphanumeric(component.back()))
        {
            return false;
        }

        return std::all_of(component.begin(),
                           component.end(),
                           [&isAlphanumeric](const char character)
                           {
                               return isAlphanumeric(character) || character == '.' || character == '_' ||
                                      character == '-';
                           });
    }
} // namespace

namespace containerimages
{
    bool isSafeTag(const std::string& tag)
    {
        if (tag.empty() || tag.size() > 128)
        {
            return false;
        }

        const auto first {tag.front()};

        const auto isWordCharacter = [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '_';
        };

        if (!isWordCharacter(first))
        {
            return false;
        }

        return std::all_of(tag.begin(),
                           tag.end(),
                           [&isWordCharacter](const char character)
                           {
                               return isWordCharacter(character) || character == '.' || character == '-';
                           });
    }

    bool normalizeImageName(const std::string& text, NormalizedImageName& normalized)
    {
        normalized = {};

        std::string remainder {text};
        const auto digestSeparator {remainder.find('@')};

        if (digestSeparator != std::string::npos)
        {
            normalized.digest = remainder.substr(digestSeparator + 1);
            remainder = remainder.substr(0, digestSeparator);

            if (!oci::isSafeDigest(normalized.digest))
            {
                return false;
            }
        }

        // A ':' only introduces a tag after the last '/'; before it, it is a registry port.
        const auto lastSlash {remainder.rfind('/')};
        const auto tagSeparator {remainder.rfind(':')};

        if (tagSeparator != std::string::npos && (lastSlash == std::string::npos || tagSeparator > lastSlash))
        {
            normalized.tag = remainder.substr(tagSeparator + 1);
            remainder = remainder.substr(0, tagSeparator);

            if (!isSafeTag(normalized.tag))
            {
                return false;
            }
        }
        else if (normalized.digest.empty())
        {
            normalized.tag = DEFAULT_TAG;
        }

        auto components {splitPath(remainder)};
        std::string registry {"docker.io"};

        // Same rule as every container client: the first component is a registry only when it
        // looks like a host, otherwise the whole text is a repository on Docker Hub.
        const auto& first {components.front()};

        if (components.size() > 1 && (first.find_first_of(".:") != std::string::npos || first == "localhost"))
        {
            registry = first;
            std::transform(registry.begin(), registry.end(), registry.begin(),
                           [](const unsigned char character)
            {
                return static_cast<char>(std::tolower(character));
            });
            components.erase(components.begin());
        }

        const auto isHostCharacter = [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
                   character == '.' || character == '-' || character == ':';
        };

        if (registry == "index.docker.io")
        {
            registry = "docker.io";
        }

        if (!std::all_of(registry.begin(), registry.end(), isHostCharacter))
        {
            return false;
        }

        if (registry == "docker.io" && components.size() == 1)
        {
            components.insert(components.begin(), "library");
        }

        normalized.name = registry;

        for (const auto& component : components)
        {
            if (!isSafePathComponent(component))
            {
                normalized = {};
                return false;
            }

            normalized.name += "/" + component;
        }

        return true;
    }

    bool parseRegistryReference(const std::string& text, RegistryReference& reference, std::string& error)
    {
        reference = {};
        error.clear();

        if (text.empty())
        {
            error = "the reference is empty";
            return false;
        }

        std::string remainder {text};

        // The digest separator is looked for first: a digest contains a ':', so splitting
        // on ':' first would cut a digest-pinned reference in the wrong place.
        const auto digestSeparator {remainder.find('@')};

        if (digestSeparator != std::string::npos)
        {
            reference.digest = remainder.substr(digestSeparator + 1);
            remainder = remainder.substr(0, digestSeparator);

            if (!oci::isSafeDigest(reference.digest))
            {
                error = "the digest is not a well-formed OCI digest";
                return false;
            }
        }

        // A ':' only introduces a tag when it comes after the last '/'. Before it, it is
        // the port of a registry host, which this module does not accept but must not
        // mistake for a tag. Looked for with a digest present too: "app:1.4@sha256:..." is
        // what dependency update tools write, and the tag in it is left for the digest to
        // override.
        const auto lastSlash {remainder.rfind('/')};
        const auto tagSeparator {remainder.rfind(':')};

        if (tagSeparator != std::string::npos && (lastSlash == std::string::npos || tagSeparator > lastSlash))
        {
            reference.tag = remainder.substr(tagSeparator + 1);
            remainder = remainder.substr(0, tagSeparator);

            if (!isSafeTag(reference.tag))
            {
                error = "the tag is not a well-formed OCI tag";
                return false;
            }
        }
        else if (reference.digest.empty())
        {
            reference.tag = DEFAULT_TAG;
        }

        const auto components {splitPath(remainder)};

        // A bare "app:1.4" names an implicit registry, which is Docker Hub for every
        // client that accepts it, and this module supports only a fixed set of registries,
        // so it is rejected rather than silently redirected.
        if (components.size() < 2)
        {
            error = "the reference must name a registry and a repository";
            return false;
        }

        reference.registry = components.front();

        if (!profileForHost(reference.registry, reference.profile, error))
        {
            return false;
        }

        if (components.size() - 1 < reference.profile.minRepositoryComponents())
        {
            error = reference.profile.minRepositoryComponents() > 1
                    ? "the reference must name a registry, an owner and a repository"
                    : "the reference must name a registry and a repository";
            return false;
        }

        for (auto component = components.begin() + 1; component != components.end(); ++component)
        {
            if (!isSafePathComponent(*component))
            {
                error = "the repository path is not a well-formed OCI repository name";
                return false;
            }

            if (!reference.repository.empty())
            {
                reference.repository += "/";
            }

            reference.repository += *component;
        }

        return true;
    }
} // namespace containerimages
