/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_RESCAN_REQUESTER_HPP
#define _HC_RESCAN_REQUESTER_HPP

#include "backoff.hpp"
#include "cmacSigner.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"
#include "vdOffsetStore.hpp"

#include <cstdint>

/**
 * @brief Requests a VD re-scan via POST /scan/vd when agent-info's durable
 * `vd_feed_state` reports one pending.
 *
 * Runs blocking on the control thread, same class of request as /control
 * itself: the manager side is expected to answer quickly (enqueue-and-return,
 * per the issue's design), so waiting for the response inline is not a
 * concern. A failed attempt re-arms itself for free, because the pending flag
 * stays set in agent-info until a 200 OK actually clears it -- the next
 * Notify (or this same call, for a 409 that reports a newer offset) retries.
 *
 * The 409 (offset mismatch) case is handled here, not by the shared
 * classifier: classifyOutcome() maps 409 to OutcomeClass::VersionRejected
 * globally (the /control meaning, #37733), so RetrySender stops retrying
 * after one attempt -- this class inspects the 409 body itself
 * (current_version) and decides whether to advance the offset and retry with
 * a fresh request, bounded to a few rounds so a pathological manager
 * responding with an ever-increasing offset cannot loop forever.
 */
class RescanRequester final
{
    public:
        RescanRequester(const ModuleConfig& config, IHttpPerformer& performer,
                        const ISigner& signer, IClock& clock, IRandom& random,
                        AuthGate& authGate, IVdOffsetStore& store);

        /// Attempts to satisfy the pending re-scan for `offset` (as reported by
        /// IVdOffsetStore::observe()). Returns true if the request succeeded
        /// (and the pending flag was cleared); false if it is still pending
        /// after this call -- the next Notify (via observe()'s no-op path)
        /// will retry.
        bool requestRescan(uint64_t offset, Waiter& waiter);

    private:
        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        IVdOffsetStore& m_store;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_RESCAN_REQUESTER_HPP
