/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_DELIVERY_GATE_HPP
#define _TASK_MANAGER_UPGRADE_DELIVERY_GATE_HPP

#include "errorCodes.hpp"

#include <string_view>

namespace task_manager::upgrade
{
    /**
     * @brief `<remote>` settings the upgrade gates depend on.
     *
     * VERIFY_UNSET and VERIFY_NONE are mirrored by hand from src/config/include/remote-config.h
     * rather than included: that header is part of the manager's static configuration library, and
     * this shared object deliberately links none of it. Keep them in sync -- the distinction between
     * them is load-bearing (UNSET means the operator said nothing and remoted resolves a default;
     * NONE means the operator explicitly turned verification off), and collapsing the two would
     * change which upgrades are blocked.
     */
    struct RemotedSettings
    {
        static constexpr int VERIFY_UNSET {-1};
        static constexpr int VERIFY_NONE {0};

        /**
         * @brief Whether the two fields below were actually read.
         *
         * False means the read failed, and the gate then FAILS OPEN -- exactly what the retired code
         * did when ReadConfig() returned an error. A configuration problem is remoted's to report;
         * blocking every upgrade on it would turn one daemon's transient parse failure into a
         * fleet-wide outage of a feature that has nothing to do with it.
         */
        bool valid {false};
        bool legacyEnabled {false};
        int verificationMode {VERIFY_UNSET};
    };

    /**
     * @brief Outcome of the delivery gates.
     */
    struct DeliveryVerdict
    {
        UpgradeError error {UpgradeError::Success};
        /**
         * @brief The upgrade is proceeding only because `force` was set, over an HTTPS verification
         *        mode that may leave the agent unable to reconnect. The caller logs it; keeping the
         *        decision and the logging apart is what lets this function stay pure.
         */
        bool forcedOverUnsafeVerification {false};
    };

    /**
     * @brief Decide whether the upgrade can actually be DELIVERED, as opposed to merely being valid.
     *
     * Ported from wm_agent_upgrade_validate_remoted_delivery(). Two independent gates, either of
     * which may apply, both or neither:
     *
     *   - The agent is below v5.0.0, so its WPK can only reach it over remoted's legacy push. If
     *     `remote.legacy.enabled` is false the task would be created and then never delivered, which
     *     is worse than refusing it: LegacyDeliveryDisabled.
     *   - The target is v5.0.0 or newer, so the agent will come back speaking HTTPS. If remoted's
     *     verification_mode is anything other than unset or none, the freshly upgraded agent may not
     *     be able to re-establish a connection: HttpsVerificationModeUnsafe, unless forced.
     *
     * When neither applies -- a v5 agent upgrading to another v5 -- there is nothing to check and
     * `settings` is not consulted at all, which is why the caller may leave it invalid.
     *
     * @param currentVersion Agent's version. Empty means "not known", and skips the legacy gate.
     * @param targetVersion  Version being installed. Empty skips the HTTPS gate. The custom-WPK path
     *                       passes v5.0.0 unconditionally: a custom file's NAME cannot be trusted to
     *                       say what it installs, so it is treated as if it might be 5.x.
     * @param forceUpgrade   Overrides the HTTPS gate only. It never overrides the legacy gate --
     *                       forcing there would create a task that is provably undeliverable.
     */
    DeliveryVerdict checkRemotedDelivery(std::string_view currentVersion,
                                         std::string_view targetVersion,
                                         bool forceUpgrade,
                                         const RemotedSettings& settings);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_DELIVERY_GATE_HPP
