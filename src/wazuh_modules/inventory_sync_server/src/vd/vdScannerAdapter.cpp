/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
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

    /**
     * @brief Production IVdScanner: the scan lane's bridge to the vulnerability scanner module.
     *
     * Translates a ValidatedSession into the scanner's NEUTRAL views (no FlatBuffers cross this
     * boundary; the views alias the request body, which the lane keeps alive for the whole call).
     *
     * Every node runs the scanner, so a session is either scanned or deferred: while the scanner
     * is starting, its feed is loading, or its start failed, the feed-not-ready gate answers a
     * retryable 503 and nothing is indexed. An agent therefore never records as delivered a
     * session that no scanner has seen.
     *
     * There is no manager-initiated "feed-update fleet scan" to coordinate with -- agents detect
     * the offset change themselves and request a targeted rescan via /scan/vd. So every
     * VDFirst/VDSync session runs its own scan unconditionally; occasional overlap with an
     * agent-requested on-demand scan is a rare, accepted duplicate, not a correctness issue.
     */
    class VdScannerAdapter final : public IVdScanner
    {
    public:
        bool feedReady() const override
        {
            const auto& scanner = VulnerabilityScannerFacade::instance();
            return scanner.isInitialized() && scanner.isFeedReady();
        }

        bool startFailed() const override
        {
            return VulnerabilityScannerFacade::instance().startFailed();
        }

        std::uint64_t currentFeedOffset() const override
        {
            return VulnerabilityScannerFacade::instance().currentFeedOffset();
        }

        ScanVerdict scan(const sync::ValidatedSession& session) override
        {
            // LCOV_EXCL_START - integration-only: everything below drives the REAL
            // VulnerabilityScannerFacade (feed state, scan orchestration, indexer writes). This
            // adapter exists precisely so the lane above it can be unit-tested against IVdScanner
            // fakes; the adapter itself is exercised by the vulnerability-detection integration
            // workflow against a live scanner and is never part of a coverage capture.
            auto& scanner = VulnerabilityScannerFacade::instance();

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

            return scanner.runScannerFromViews(info, items) ? ScanVerdict::Ok : ScanVerdict::Skipped;
            // LCOV_EXCL_STOP
        }

        AgentScanOutcome scanAgent(const std::string& agentId) override
        {
            auto& scanner = VulnerabilityScannerFacade::instance();

            // LCOV_EXCL_START - integration-only, same as scan() above.
            //
            // triggerAgentScan() runs its own readiness guards, so this translation is the only
            // thing here: the scanner's vocabulary is richer than the seam's, and each of its
            // values has exactly one right answer for a caller deciding whether to retry.
            switch (scanner.triggerAgentScan(agentId))
            {
                case VulnerabilityScannerFacade::ScanTriggerResult::Success: return AgentScanOutcome::Ok;

                // None of these is about this request: the scanner failed to start or is still
                // starting, the feed is still loading, or no indexer host is healthy.
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
        // LCOV_EXCL_START - integration-only, same as scan() above.
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

    std::shared_ptr<IVdScanner> makeProductionVdScanner()
    {
        return std::make_shared<VdScannerAdapter>();
    }

} // namespace invsync::vd
