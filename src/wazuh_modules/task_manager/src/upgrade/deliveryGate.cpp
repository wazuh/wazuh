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

#include "deliveryGate.hpp"

#include "version.hpp"

namespace task_manager::upgrade
{
    DeliveryVerdict checkRemotedDelivery(const std::string_view currentVersion,
                                         const std::string_view targetVersion,
                                         const bool forceUpgrade,
                                         const RemotedSettings& settings)
    {
        DeliveryVerdict verdict;

        const bool checkLegacyDelivery {!currentVersion.empty() &&
                                        compareVersions(currentVersion, FIVE_X_MINIMUM_VERSION, true) < 0};
        const bool checkHttpsVerification {!targetVersion.empty() &&
                                           compareVersions(targetVersion, FIVE_X_MINIMUM_VERSION, true) >= 0};

        if (!checkLegacyDelivery && !checkHttpsVerification)
        {
            return verdict;
        }

        if (!settings.valid)
        {
            return verdict; // Fail open -- see RemotedSettings::valid.
        }

        if (checkLegacyDelivery && !settings.legacyEnabled)
        {
            verdict.error = UpgradeError::LegacyDeliveryDisabled;
            return verdict;
        }

        if (checkHttpsVerification && settings.verificationMode != RemotedSettings::VERIFY_UNSET &&
            settings.verificationMode != RemotedSettings::VERIFY_NONE)
        {
            if (!forceUpgrade)
            {
                verdict.error = UpgradeError::HttpsVerificationModeUnsafe;
                return verdict;
            }

            verdict.forcedOverUnsafeVerification = true;
        }

        return verdict;
    }
} // namespace task_manager::upgrade
