/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "imageReference.hpp"

#include <stdexcept>
#include <sys/utsname.h>

namespace container_image_inventory
{
    RemoteImageRef parse_image_ref(const std::string& ref)
    {
        if (ref.empty())
        {
            throw std::invalid_argument("image reference is empty");
        }
        RemoteImageRef out;
        out.original = ref;

        const auto digest_sep = ref.rfind('@');
        const auto last_slash = ref.rfind('/');
        const auto tag_sep = ref.rfind(':');

        std::string name;
        if (digest_sep != std::string::npos)
        {
            name = ref.substr(0, digest_sep);
            out.reference = ref.substr(digest_sep + 1);
        }
        else if (tag_sep != std::string::npos &&
                 (last_slash == std::string::npos || tag_sep > last_slash))
        {
            name = ref.substr(0, tag_sep);
            out.reference = ref.substr(tag_sep + 1);
        }
        else
        {
            name = ref;
            out.reference = "latest";
        }

        // Split name into registry + repository.
        const auto first_slash = name.find('/');
        std::string first = (first_slash == std::string::npos) ? name : name.substr(0, first_slash);
        const bool first_is_registry =
            first == "localhost" ||
            first.find('.') != std::string::npos ||
            first.find(':') != std::string::npos;

        if (first_is_registry)
        {
            out.registry = first;
            out.repository = (first_slash == std::string::npos)
                                 ? std::string()
                                 : name.substr(first_slash + 1);
        }
        else
        {
            out.registry = "registry-1.docker.io";
            out.repository = name;
        }

        if (out.registry == "registry-1.docker.io" &&
            out.repository.find('/') == std::string::npos &&
            !out.repository.empty())
        {
            out.repository = "library/" + out.repository;
        }
        if (out.registry == "docker.io")
        {
            out.registry = "registry-1.docker.io";
        }

        if (out.repository.empty())
        {
            throw std::invalid_argument("image reference missing repository: " + ref);
        }
        return out;
    }

    std::string default_platform()
    {
        struct utsname u{};
        if (uname(&u) != 0)
        {
            return "linux/amd64";
        }
        std::string m = u.machine ? u.machine : "";
        std::string arch;
        if (m == "x86_64" || m == "amd64")
        {
            arch = "amd64";
        }
        else if (m == "aarch64" || m == "arm64")
        {
            arch = "arm64";
        }
        else
        {
            arch = m.empty() ? "amd64" : m;
        }
        return "linux/" + arch;
    }

    PlatformParts parse_platform(const std::string& platform)
    {
        PlatformParts p;
        const auto first = platform.find('/');
        if (first == std::string::npos)
        {
            throw std::invalid_argument("invalid platform: " + platform);
        }
        p.os = platform.substr(0, first);
        const auto rest = platform.substr(first + 1);
        const auto second = rest.find('/');
        if (second == std::string::npos)
        {
            p.arch = rest;
        }
        else
        {
            p.arch = rest.substr(0, second);
            p.variant = rest.substr(second + 1);
        }
        if (p.os.empty() || p.arch.empty())
        {
            throw std::invalid_argument("invalid platform: " + platform);
        }
        return p;
    }
} // namespace container_image_inventory
