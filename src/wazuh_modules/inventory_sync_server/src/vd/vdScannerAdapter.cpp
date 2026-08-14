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

    /**
     * @brief Production IVdScanner: the scan lane's bridge to the vulnerability scanner module.
     *
     * Translates a ValidatedSession into the scanner's NEUTRAL views (no FlatBuffers cross this
     * boundary; the views alias the request body, which the lane keeps alive for the whole call)
     * and reproduces the legacy gate decision:
     *  - scanner not initialized (disabled, or still starting) -> legitimate skip, index anyway.
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
        bool feedReady() const override
        {
            auto& scanner = VulnerabilityScannerFacade::instance();
            // An uninitialized scanner is not a "feed not ready" condition: those sessions skip
            // the scan and index (D22's legitimate-skip row), so they must pass this gate.
            return !scanner.isInitialized() || scanner.isFeedReady();
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

    private:
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
    };

    std::shared_ptr<IVdScanner> makeProductionVdScanner()
    {
        return std::make_shared<VdScannerAdapter>();
    }

} // namespace invsync::vd
