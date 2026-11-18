/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_PROFILE_HPP
#define _REGISTRY_PROFILE_HPP

#include <cstddef>
#include <string>

namespace containerimages
{
    /// @brief The registries this module reads.
    enum class RegistryKind
    {
        Ghcr,       ///< `ghcr.io`: Bearer token, optionally exchanged for a stored credential.
        EcrPublic,  ///< `public.ecr.aws`: Bearer token, always anonymous.
        EcrPrivate  ///< `<account>.dkr.ecr.<region>.amazonaws.com`: Basic, token from a signed AWS call.
    };

    /// @brief What differs between the supported registries, chosen by the reference's host.
    ///
    /// Only the three kinds above exist. The host is matched exactly, never by substring,
    /// because what it selects decides where a credential-derived value is sent.
    struct RegistryProfile
    {
        RegistryKind kind {RegistryKind::Ghcr};
        std::string region;    ///< Region named by an ECR private host, empty otherwise.
        std::string dnsSuffix; ///< "amazonaws.com" or "amazonaws.com.cn" for an ECR private host.

        /// @brief Path components a reference needs after the host.
        ///
        /// GHCR names an owner and a repository, public ECR an alias and a repository,
        /// and a private ECR repository may be a single name.
        std::size_t minRepositoryComponents() const
        {
            return kind == RegistryKind::EcrPrivate ? 1 : 2;
        }

        /// @brief True when requests carry `Basic <token>` rather than `Bearer <token>`.
        bool usesBasicToken() const
        {
            return kind == RegistryKind::EcrPrivate;
        }

        /// @brief True when a credential the registry refused may be replaced by an anonymous request.
        ///
        /// GHCR serves public repositories to anyone, so a refused credential is retried without
        /// it. Private ECR has no anonymous access, and public ECR takes no credential to refuse.
        bool allowsAnonymousFallback() const
        {
            return kind == RegistryKind::Ghcr;
        }

        /// @brief True when a response status means the credential was refused.
        ///
        /// A Bearer registry answers 401. ECR answered a refused Basic token with 400 and
        /// a `DENIED` body, so 400 and 403 count there as well.
        bool rejectsAuthorization(const long status) const
        {
            return status == 401 || (usesBasicToken() && (status == 400 || status == 403));
        }
    };

    /// @brief Select the profile for a registry host.
    ///
    /// @param host    The host as written in the reference, without a port.
    /// @param profile Filled in on success.
    /// @param error   Why the host is not supported, when it is not.
    /// @return True when @p host is a registry this module can read.
    bool profileForHost(const std::string& host, RegistryProfile& profile, std::string& error);

    /// @brief True when @p region is shaped like an AWS region name, such as "eu-west-1".
    ///
    /// The region is placed into a host name that signed requests are sent to, so it is
    /// whitelisted rather than filtered.
    bool isValidAwsRegion(const std::string& region);

    /// @brief True when @p suffix is one of the AWS DNS suffixes this module sends signed
    /// requests under: "amazonaws.com" and "amazonaws.com.cn".
    bool isSupportedAwsDnsSuffix(const std::string& suffix);
} // namespace containerimages

#endif // _REGISTRY_PROFILE_HPP
