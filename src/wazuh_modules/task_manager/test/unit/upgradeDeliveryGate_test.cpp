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

#include "upgrade/deliveryGate.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace task_manager::upgrade;

namespace
{
    constexpr int VERIFY_UNSET {RemotedSettings::VERIFY_UNSET};
    constexpr int VERIFY_NONE {RemotedSettings::VERIFY_NONE};
    constexpr int VERIFY_CERTIFICATE {1};
    constexpr int VERIFY_FULL {2};

    RemotedSettings settings(const bool legacyEnabled, const int verificationMode)
    {
        return {true, legacyEnabled, verificationMode};
    }

    struct GateCase
    {
        const char* label;
        const char* currentVersion;
        const char* targetVersion;
        bool force;
        RemotedSettings remoted;
        UpgradeError expected;
    };
} // namespace

TEST(UpgradeDeliveryGate, CoversTheWholeMatrix)
{
    // With ReadConfig() lifted out of this decision, the matrix is small enough to state in full --
    // which the retired code could not do, because every one of these cases needed a wrapped
    // ReadConfig and a hand-built `remoted` struct.
    const std::vector<GateCase> cases {
        // Neither gate applies: a v5 agent moving to a PRE-v5 target. Note it takes both halves to
        // get here -- a v5 agent staying on v5 still trips the https gate, because the target is
        // v5+. `remoted` is never consulted, so an invalid one is fine.
        {"v5 agent, pre-v5 target, settings never read",
         "v5.0.0",
         "v4.14.0",
         false,
         RemotedSettings {},
         UpgradeError::Success},

        // Legacy gate only: pre-v5 agent, pre-v5 target.
        {"pre-v5 agent, pre-v5 target, legacy on",
         "v4.14.0",
         "v4.14.1",
         false,
         settings(true, VERIFY_FULL),
         UpgradeError::Success},
        {"pre-v5 agent, pre-v5 target, legacy off",
         "v4.14.0",
         "v4.14.1",
         false,
         settings(false, VERIFY_UNSET),
         UpgradeError::LegacyDeliveryDisabled},
        {"the legacy gate ignores force",
         "v4.14.0",
         "v4.14.1",
         true,
         settings(false, VERIFY_UNSET),
         UpgradeError::LegacyDeliveryDisabled},

        // HTTPS gate only: v5 agent moving to v5+.
        {"v5 agent, verification unset",
         "v5.0.0",
         "v5.1.0",
         false,
         settings(false, VERIFY_UNSET),
         UpgradeError::Success},
        {"v5 agent, verification none", "v5.0.0", "v5.1.0", false, settings(false, VERIFY_NONE), UpgradeError::Success},
        {"v5 agent, verification certificate",
         "v5.0.0",
         "v5.1.0",
         false,
         settings(false, VERIFY_CERTIFICATE),
         UpgradeError::HttpsVerificationModeUnsafe},
        {"v5 agent, verification full",
         "v5.0.0",
         "v5.1.0",
         false,
         settings(false, VERIFY_FULL),
         UpgradeError::HttpsVerificationModeUnsafe},
        {"the https gate honours force", "v5.0.0", "v5.1.0", true, settings(false, VERIFY_FULL), UpgradeError::Success},

        // Both gates: the pre-v5 to v5 crossing, which is the whole reason both exist.
        {"both gates, legacy off wins",
         "v4.14.0",
         "v5.0.0",
         false,
         settings(false, VERIFY_FULL),
         UpgradeError::LegacyDeliveryDisabled},
        {"both gates, legacy on then https blocks",
         "v4.14.0",
         "v5.0.0",
         false,
         settings(true, VERIFY_FULL),
         UpgradeError::HttpsVerificationModeUnsafe},
        {"both gates, legacy on and forced",
         "v4.14.0",
         "v5.0.0",
         true,
         settings(true, VERIFY_FULL),
         UpgradeError::Success},
        {"both gates, all clear", "v4.14.0", "v5.0.0", false, settings(true, VERIFY_NONE), UpgradeError::Success},

        // Unreadable settings fail OPEN, for every gate.
        {"unreadable settings, legacy gate", "v4.14.0", "v4.14.1", false, RemotedSettings {}, UpgradeError::Success},
        {"unreadable settings, https gate", "v5.0.0", "v5.1.0", false, RemotedSettings {}, UpgradeError::Success},

        // Absent versions skip their gate.
        {"no current version skips the legacy gate",
         "",
         "v4.14.1",
         false,
         settings(false, VERIFY_UNSET),
         UpgradeError::Success},
        {"no target version skips the https gate",
         "v5.0.0",
         "",
         false,
         settings(false, VERIFY_FULL),
         UpgradeError::Success},
    };

    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(testCase.label);
        EXPECT_EQ(
            checkRemotedDelivery(testCase.currentVersion, testCase.targetVersion, testCase.force, testCase.remoted)
                .error,
            testCase.expected);
    }
}

TEST(UpgradeDeliveryGate, NeitherGateApplyingSkipsTheSettingsEntirely)
{
    // A v5 agent going to a pre-v5 target: not below v5, and the target is not v5+. Invalid settings
    // must not matter, because they are never read -- this is what lets the orchestrator skip the
    // remoted lookup for the common intra-v5 case.
    const auto verdict {checkRemotedDelivery("v5.0.0", "v4.14.0", false, RemotedSettings {})};
    EXPECT_EQ(verdict.error, UpgradeError::Success);
    EXPECT_FALSE(verdict.forcedOverUnsafeVerification);
}

TEST(UpgradeDeliveryGate, ReportsWhenForceOverrodeAnUnsafeVerificationMode)
{
    // The flag exists so the decision stays pure and the ORCHESTRATOR logs; a caller that ignores it
    // silently accepts a risk the operator asked to be told about.
    const auto forced {checkRemotedDelivery("v5.0.0", "v5.1.0", true, settings(true, VERIFY_FULL))};
    EXPECT_EQ(forced.error, UpgradeError::Success);
    EXPECT_TRUE(forced.forcedOverUnsafeVerification);

    // Not raised when there was nothing to override.
    const auto clean {checkRemotedDelivery("v5.0.0", "v5.1.0", true, settings(true, VERIFY_NONE))};
    EXPECT_EQ(clean.error, UpgradeError::Success);
    EXPECT_FALSE(clean.forcedOverUnsafeVerification);
}

TEST(UpgradeDeliveryGate, UnsetIsNotTheSameAsNone)
{
    // Both are <= 0, which is why they cannot ride the config POD's "no opinion" sentinel rule and
    // why RemotedSettings carries an explicit validity flag instead. They happen to agree here --
    // both allow the upgrade -- but they are distinct values remoted resolves differently, and
    // collapsing them would silently change behaviour the day that stops being true.
    EXPECT_NE(VERIFY_UNSET, VERIFY_NONE);
    EXPECT_LE(VERIFY_UNSET, 0);
    EXPECT_LE(VERIFY_NONE, 0);
}

TEST(UpgradeDeliveryGate, TheCustomWpkPathIsTreatedAsIfItTargetsFive)
{
    // upgrade_custom passes v5.0.0 unconditionally and force=false, because a custom file's NAME
    // cannot be trusted to say what it installs. That makes the https gate unconditional and
    // un-overridable for custom WPKs -- there is no `force` parameter on /agents/upgrade_custom.
    EXPECT_EQ(checkRemotedDelivery("v5.0.0", "v5.0.0", false, settings(true, VERIFY_FULL)).error,
              UpgradeError::HttpsVerificationModeUnsafe);
    EXPECT_EQ(checkRemotedDelivery("v5.0.0", "v5.0.0", false, settings(true, VERIFY_NONE)).error,
              UpgradeError::Success);
}
