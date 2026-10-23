/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CA_BUNDLE_HPP
#define _CA_BUNDLE_HPP

#include <functional>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Where a certificate bundle was found, so the caller can say so once.
    enum class CaBundleOrigin
    {
        Configured, ///< Named in the configuration.
        Detected,   ///< Found at one of the well-known locations.
        None        ///< Not found; the reference cannot be verified.
    };

    /// @brief The outcome of looking for a certificate bundle.
    struct CaBundle
    {
        CaBundleOrigin origin {CaBundleOrigin::None};
        std::string path;   ///< The bundle to verify against, when one was found.
        std::string reason; ///< Why none was found, when that is the outcome.

        bool found() const
        {
            return origin != CaBundleOrigin::None;
        }
    };

    /// @brief The locations probed, in order, when none is configured.
    ///
    /// The vendored cURL has a bundle path compiled in at build time, and that path is
    /// whichever one existed on the machine that built the leg. A package built on one
    /// distribution family therefore looks for a file that does not exist on another, and
    /// every verification fails for a reason that has nothing to do with the
    /// configuration. Probing at run time is what makes the same package work on the
    /// distributions the agent supports.
    const std::vector<std::string>& wellKnownCaBundles();

    /// @brief Decide which certificate bundle to verify a registry against.
    ///
    /// Resolution order: the configured path, then the well-known locations, then
    /// nothing. Nothing is a failure, not a fallback to an unverified connection: a
    /// caller that cannot verify a registry does not talk to it.
    ///
    /// @param configured Path from the configuration, empty when none is set.
    /// @param exists     Existence predicate, injected so the order can be tested
    ///                   without depending on the machine running the tests.
    CaBundle resolveCaBundle(const std::string& configured,
                             const std::function<bool(const std::string&)>& exists = {});
} // namespace containerimages

#endif // _CA_BUNDLE_HPP
