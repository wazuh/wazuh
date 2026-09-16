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
     */
    std::shared_ptr<IVdScanner> makeProductionVdScanner();

    /**
     * @brief Pure decision for feedReady(): open (legitimate skip / never gate) vs. deferred.
     *
     * Extracted out of VdScannerAdapter so the startup gate can be pinned by a unit test without a
     * live VulnerabilityScannerFacade.
     *
     * @param started Facade's hasStarted(): start() has begun executing at least once.
     * @param enabled Facade's isEnabled(): vulnerability detection is enabled on this node.
     * @param initialized Facade's isInitialized(): start() ran to completion.
     * @param feedReady Facade's isFeedReady(): the CVE feed is loaded and ready to scan against.
     * @return true if the gate is open (legitimate skip, or never going to run here), false if the
     *         caller should defer with a retryable 503.
     */
    bool feedGateOpen(bool started, bool enabled, bool initialized, bool feedReady);

} // namespace invsync::vd

#endif // _INVSYNC_VD_VD_SCANNER_FACTORY_HPP
