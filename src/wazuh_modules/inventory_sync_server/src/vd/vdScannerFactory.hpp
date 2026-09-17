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

#ifndef _INVSYNC_VD_VD_SCANNER_FACTORY_HPP
#define _INVSYNC_VD_VD_SCANNER_FACTORY_HPP

#include "vd/IVdScanner.hpp"

#include <memory>

namespace invsync::vd
{

    /**
     * @brief Build the production scanner seam (the bridge to the vulnerability_scanner module).
     *
     * A factory function rather than exposing the adapter class: the adapter's translation unit is
     * the ONE place in this module that compiles the scanner's headers (and their transitive
     * include soup), and keeping it out of every other TU is what keeps that coupling contained.
     *
     * @param vdConfiguredEnabled Whether `<vulnerability-detection>` is present and enabled in this
     *        node's OWN configuration, read directly off the vulnerability_scanner wmodule's parsed
     *        config before that module's start() has necessarily run (see feedGateOpen()).
     */
    std::shared_ptr<IVdScanner> makeProductionVdScanner(bool vdConfiguredEnabled);

    /**
     * @brief Pure decision for feedReady(): open (legitimate skip / never gate) vs. deferred.
     *
     * Extracted out of VdScannerAdapter so the startup/failure gate can be pinned by a unit test
     * without a live VulnerabilityScannerFacade.
     *
     * @param started Facade's hasStarted(): start() has begun executing at least once.
     * @param enabled Facade's isEnabled(): vulnerability detection is enabled on this node.
     * @param startFailed Facade's startFailed(): start() ran to completion and threw.
     * @param initialized Facade's isInitialized(): start() ran to completion without throwing.
     * @param feedReady Facade's isFeedReady(): the CVE feed is loaded and ready to scan against.
     * @param configuredEnabled Whether this node's OWN configuration has VD enabled, known before
     *        started is true (see makeProductionVdScanner()) -- the only signal available for a
     *        session that arrives before wm_vulnerability_scanner's start() has begun at all: two
     *        separate wmodules run on independent threads with no ordering guarantee between them.
     * @return true if the gate is open (legitimate skip, or never going to run here), false if the
     *         caller should defer with a retryable 503.
     */
    bool feedGateOpen(
        bool started, bool enabled, bool startFailed, bool initialized, bool feedReady, bool configuredEnabled);

} // namespace invsync::vd

#endif // _INVSYNC_VD_VD_SCANNER_FACTORY_HPP
