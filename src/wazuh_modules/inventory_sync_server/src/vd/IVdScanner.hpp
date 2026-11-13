/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
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
#include <string>

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
        Skipped, ///< The scanner had nothing to scan in this session (a first sync with an empty
                 ///< inventory). The inventory MUST still be indexed.
    };

    /**
     * @brief What the lane learned from asking the scanner to scan one agent, with no session.
     *
     * Separate from ScanVerdict because the two calls have genuinely different failure sets. A
     * session's scan either runs, has nothing to scan, or poisons the session (an exception); an
     * on-demand scan has no session to poison and several distinct reasons to come back later,
     * and its caller -- the Task Manager's dispatcher -- needs them apart: a transient one must
     * back off and retry, while a permanent one must stop.
     *
     * Deliberately NOT the scanner's own ScanTriggerResult: this header is the neutral seam, and
     * the adapter is where that vocabulary is translated.
     */
    enum class AgentScanOutcome
    {
        Ok,       ///< The scan ran and its findings were delivered by VD itself.
        NotReady, ///< The feed is loading, the scanner is not up, or no indexer host is healthy.
                  ///< Worth retrying.
        NotFound, ///< The agent is not in global.db. Permanent: retrying cannot find it.
        Failed    ///< The scan itself failed. Worth retrying.
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

        /// @brief Whether this node can scan right now: false until the scanner has started and
        /// its CVE feed is loaded, and for as long as a scanner that failed to start stays down.
        /// Every node runs the scanner, so "not ready" never means "nothing to scan": the caller
        /// defers the session and the agent sends it again. Cheap (two atomic loads in
        /// production): the strand calls it at admission and the lane worker re-checks it at
        /// dispatch.
        virtual bool feedReady() const = 0;

        /// @brief Whether the scanner failed to start. feedReady() then stays false until the
        /// manager is restarted, which is an operator's problem and not the ordinary wait for a
        /// feed: the caller says so in its log instead of deferring quietly.
        virtual bool startFailed() const = 0;

        /// @brief This node's current VD feed offset, for validating a VDFirst/VDSync session's
        /// Start.feed_offset before scanning it. Cheap in production (an atomic load behind the
        /// database feed manager).
        virtual std::uint64_t currentFeedOffset() const = 0;

        /**
         * @brief Run the vulnerability scan for one validated session, SYNCHRONOUSLY.
         *
         * VD writes the vulnerability findings with its own connector before returning; the caller
         * only ever indexes the session's INVENTORY afterwards. Throws when the scan fails or
         * cannot run -- the lane answers 500 with zero inventory documents indexed (the gating of
         * D22).
         */
        virtual ScanVerdict scan(const sync::ValidatedSession& session) = 0;

        /**
         * @brief Scan ONE agent, with no session behind it, SYNCHRONOUSLY.
         *
         * The on-demand rescan an agent asks for after noticing the feed offset moved. There is no
         * inventory to index afterwards: VD reads the agent's packages from what is already stored
         * and writes its findings with its own connector, so the lane's answer is the scan's own
         * outcome and nothing more.
         *
         * Reports failure by RETURN VALUE rather than by exception, unlike scan(): there is no
         * session to poison, and every failure here is something the caller has to tell apart to
         * decide whether to come back.
         */
        virtual AgentScanOutcome scanAgent(const std::string& agentId) = 0;
    };

} // namespace invsync::vd

#endif // _INVSYNC_VD_I_VD_SCANNER_HPP
