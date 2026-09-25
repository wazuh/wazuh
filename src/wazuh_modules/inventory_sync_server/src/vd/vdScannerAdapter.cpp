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

#include "vd/vdScannerFactory.hpp"

#include "vulnerabilityScannerFacade.hpp"
#include "vulnerabilityScannerSync.hpp"

#include <string_view>
#include <vector>

namespace invsync::vd
{

    bool vdWillRunHere(bool started, bool enabled, bool configuredEnabled)
    {
        return started ? enabled : configuredEnabled;
    }

    bool feedGateOpen(bool willRunHere, bool startFailed, bool initialized, bool feedReady)
    {
        if (!willRunHere || startFailed)
        {
            return true;
        }
        return initialized && feedReady;
    }

    /**
     * @brief Production IVdScanner: the scan lane's bridge to the vulnerability scanner module.
     *
     * Translates a ValidatedSession into the scanner's NEUTRAL views (no FlatBuffers cross this
     * boundary; the views alias the request body, which the lane keeps alive for the whole call)
     * and reproduces the legacy gate decision:
     *  - never going to run here (disabled, or a harness that never started it) -> legitimate
     *    skip, index anyway.
     *  - enabled but still starting -> deferred: the feed-not-ready gate answers a retryable 503
     *    instead, since this node is expected to run a scanner soon.
     *
     * There is no manager-initiated "feed-update fleet scan" to coordinate with anymore -- feed
     * updates no longer trigger an automatic rescan of every agent; agents detect the offset
     * change themselves and request a targeted rescan via /scan/vd. So every VDFirst/VDSync
     * session runs its own scan unconditionally; occasional overlap with an agent-requested
     * on-demand scan is a rare, accepted duplicate, not a correctness issue.
     */
    class VdScannerAdapter final : public IVdScanner
    {
    public:
        explicit VdScannerAdapter(bool vdConfiguredEnabled)
            : m_configuredEnabled(vdConfiguredEnabled)
        {
        }

        bool feedReady() const override
        {
            // Never going to run here -- it ran and found vulnerability detection disabled, or
            // ran and failed outright, or was never invoked at all AND this node's own
            // configuration does not have VD enabled either (a test harness that skips start()
            // entirely, e.g. the testtool's --no-vd, or a real node with no
            // <vulnerability-detection> section) -- none of those is a "feed not ready"
            // condition: those sessions skip the scan and index (D22's legitimate-skip row), so
            // they must pass this gate rather than wait on a feed that will never load.
            //
            // Otherwise -- either running (enabled, started, start() didn't fail), or not yet
            // started but this node's OWN config says it will be -- the real feed-readiness
            // signal decides, once initialized. This is what lets the D17 gate -- and the
            // /scan/vd on-demand path, which re-checks this same gate before scanAgent() --
            // defer the ENTIRE startup window (both before start() begins, and while it is still
            // validating) with a retryable 503, instead of routing a session that merely arrived
            // early through Skipped as if this node would never run a scanner.
            auto& scanner = VulnerabilityScannerFacade::instance();
            // Sequenced before isEnabled(): as sibling call arguments their evaluation order is
            // unspecified, and only running the acquire load first orders the other one.
            const bool started = scanner.hasStarted();
            return feedGateOpen(vdWillRunHere(started, scanner.isEnabled(), m_configuredEnabled),
                                scanner.startFailed(),
                                scanner.isInitialized(),
                                scanner.isFeedReady());
        }

        bool scannerRunning() const override
        {
            return VulnerabilityScannerFacade::instance().isInitialized();
        }

        std::uint64_t currentFeedOffset() const override
        {
            return VulnerabilityScannerFacade::instance().currentFeedOffset();
        }

        ScanVerdict scan(const sync::ValidatedSession& session) override
        {
            auto& scanner = VulnerabilityScannerFacade::instance();

            if (!scanner.isInitialized())
            {
                return ScanVerdict::Skipped;
            }

            // LCOV_EXCL_START - integration-only from here down: everything below drives the REAL
            // VulnerabilityScannerFacade (feed state, scan orchestration, indexer writes). This
            // adapter exists precisely so the lane above it can be unit-tested against IVdScanner
            // fakes; the adapter itself is exercised by qa/test_vd_lane.py, which runs in the
            // integration workflow against a live scanner and is never part of a coverage
            // capture. The gate above (isInitialized -> Skipped) stays measured: it is the one
            // branch the unit tests do reach.
            const bool vdFirst = session.option == schema::fb::Option_VDFirst;

            vd_sync::SessionInfoView info;
            info.vdFirst = vdFirst;
            info.agentId = session.agentId;
            info.agentName = session.agentName;
            info.agentVersion = session.agentVersion;
            info.architecture = session.architecture;
            info.hostname = session.hostname;
            info.osname = session.osname;
            info.osplatform = session.osplatform;
            info.ostype = session.ostype;
            info.osversion = session.osversion;
            info.clusterName = session.clusterName;
            info.groups = session.groups;
            info.indices = session.indices;

            const auto items = buildItems(session);

            const bool executed = scanner.runScannerFromViews(info, items);

            return executed ? ScanVerdict::Ok : ScanVerdict::Skipped;
        }

        AgentScanOutcome scanAgent(const std::string& agentId) override
        {
            auto& scanner = VulnerabilityScannerFacade::instance();

            if (!scanner.isInitialized())
            {
                // Reached for "never going to run here" (disabled, or a harness that never
                // started it) and for a scanner whose start() failed outright: the lane's
                // feedReady() re-check, one level up, already deferred the enabled-but-starting
                // case with a retryable 503 before calling scanAgent() at all. Skipped, not
                // NotReady: this gate is what the QA suite, the operator WARN and
                // vd.scans.skipped hang off.
                return AgentScanOutcome::Skipped;
            }

            // LCOV_EXCL_START - integration-only, same as scan() above: everything below drives
            // the REAL facade. The gate above stays measured.
            //
            // triggerAgentScan() re-runs its own readiness guards, so this translation is the only
            // thing here: the scanner's vocabulary is richer than the seam's, and each of its
            // values has exactly one right answer for a caller deciding whether to retry.
            switch (scanner.triggerAgentScan(agentId))
            {
                case VulnerabilityScannerFacade::ScanTriggerResult::Success: return AgentScanOutcome::Ok;

                // All transient, and all for reasons outside this request. NotInitialized cannot
                // actually occur here -- the `!isInitialized()` guard above already returns Skipped
                // for that case, and this is triggerAgentScan()'s only production call site -- but
                // it is listed defensively since triggerAgentScan() is public and a future direct
                // caller (or a unit test, which does call it directly) can still hit it. The other
                // three are real: the feed is still loading, the scanner is still starting, or no
                // indexer host is healthy.
                case VulnerabilityScannerFacade::ScanTriggerResult::NotInitialized:
                case VulnerabilityScannerFacade::ScanTriggerResult::FeedNotReady:
                case VulnerabilityScannerFacade::ScanTriggerResult::ScannerNotReady:
                case VulnerabilityScannerFacade::ScanTriggerResult::IndexerUnavailable:
                    return AgentScanOutcome::NotReady;

                // The agent has no record to scan. Permanent -- most likely it was deleted between
                // the request being made and being executed, which is a race nobody should retry.
                case VulnerabilityScannerFacade::ScanTriggerResult::AgentNotFound: return AgentScanOutcome::NotFound;

                case VulnerabilityScannerFacade::ScanTriggerResult::ScanFailed:
                default: return AgentScanOutcome::Failed;
            }
            // LCOV_EXCL_STOP
        }

    private:
        /// Set once at construction from this node's own configuration; see feedGateOpen().
        bool m_configuredEnabled;

        static std::vector<vd_sync::SyncItemView> buildItems(const sync::ValidatedSession& session)
        {
            std::vector<vd_sync::SyncItemView> items;
            const auto* payload = session.session->payload_as_SyncData();
            if (payload == nullptr)
            {
                return items;
            }

            const auto viewOf = [](const flatbuffers::String* value)
            {
                return value ? value->string_view() : std::string_view {};
            };

            const auto* values = payload->values();
            const auto* contexts = payload->contexts();
            items.reserve((values ? values->size() : 0) + (contexts ? contexts->size() : 0));

            if (values != nullptr)
            {
                for (const auto* value : *values)
                {
                    vd_sync::SyncItemView item;
                    item.operation = value->operation() == schema::fb::Operation_Delete
                                         ? vd_sync::ItemOperation::Delete
                                         : vd_sync::ItemOperation::Upsert;
                    item.id = viewOf(value->id());
                    item.index = viewOf(value->index());
                    if (value->data() != nullptr)
                    {
                        item.json = std::string_view {reinterpret_cast<const char*>(value->data()->data()),
                                                      value->data()->size()};
                    }
                    items.push_back(item);
                }
            }

            if (contexts != nullptr)
            {
                // DataContext is always an Upsert of details, exactly like the legacy parse.
                for (const auto* context : *contexts)
                {
                    vd_sync::SyncItemView item;
                    item.operation = vd_sync::ItemOperation::Upsert;
                    item.id = viewOf(context->id());
                    item.index = viewOf(context->index());
                    if (context->data() != nullptr)
                    {
                        item.json = std::string_view {reinterpret_cast<const char*>(context->data()->data()),
                                                      context->data()->size()};
                    }
                    items.push_back(item);
                }
            }

            return items;
        }
        // LCOV_EXCL_STOP
    };

    std::shared_ptr<IVdScanner> makeProductionVdScanner(bool vdConfiguredEnabled)
    {
        return std::make_shared<VdScannerAdapter>(vdConfiguredEnabled);
    }

} // namespace invsync::vd
