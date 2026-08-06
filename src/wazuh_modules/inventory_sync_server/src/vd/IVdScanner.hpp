/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_VD_I_VD_SCANNER_HPP
#define _INVSYNC_VD_I_VD_SCANNER_HPP

#include "sync/fullSessionValidator.hpp"
#include <cstdint>

namespace invsync::vd
{

    /**
     * @brief What the scan lane learned from asking the scanner to run one session's scan.
     *
     * A scan FAILURE is not a value here on purpose: it is an exception out of scan(), because it
     * poisons the whole session (500, nothing indexed) while these two outcomes both continue into
     * indexing (D22 skip semantics).
     */
    enum class ScanVerdict
    {
        Ok,      ///< The scan ran and its findings were delivered by VD itself.
        Skipped, ///< Legitimate skip: the scanner is disabled. The inventory MUST still be
                 ///< indexed.
    };

    /**
     * @brief Seam over the vulnerability scanner for the scan lane.
     *
     * The production implementation forwards to the vulnerability_scanner module (feed readiness,
     * current feed offset, and the scan itself through the neutral-view entry point); tests
     * substitute a fake so the lane's gating -- the D22 contract -- can be pinned without a feed.
     */
    class IVdScanner
    {
    public:
        virtual ~IVdScanner() = default;

        /// @brief Whether the CVE feed is ready for scans. Cheap (an atomic load in production):
        /// the strand calls it at admission and the lane worker re-checks it at dispatch.
        virtual bool feedReady() const = 0;

        /// @brief This node's current VD feed offset, for validating a VDFirst/VDSync session's
        /// Start.feed_offset before scanning it. Cheap in production (an atomic load behind the
        /// database feed manager).
        virtual std::uint64_t currentFeedOffset() const = 0;

        /**
         * @brief Run the vulnerability scan for one validated session, SYNCHRONOUSLY.
         *
         * VD writes the vulnerability findings with its own connector before returning; the caller
         * only ever indexes the session's INVENTORY afterwards. Throws when the scan fails -- the
         * lane answers 500 with zero inventory documents indexed (the gating of D22).
         */
        virtual ScanVerdict scan(const sync::ValidatedSession& session) = 0;
    };

} // namespace invsync::vd

#endif // _INVSYNC_VD_I_VD_SCANNER_HPP
