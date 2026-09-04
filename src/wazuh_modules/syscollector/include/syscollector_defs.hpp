/*
 * Wazuh Syscollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSCOLLECTOR_DEFS_HPP
#define _SYSCOLLECTOR_DEFS_HPP

// Test-only access to Syscollector's internals, following the same pattern as
// vulnerabilityScannerFacade_defs.hpp. Nothing here exists in a production build: the module is
// a `final` singleton with a private constructor, so a test subclass of the kind SCA uses
// (SCAMock, which assigns m_spSyncProtocol directly) is not available to it, and the alternative
// -- a public setter -- would add API that only tests would ever call.
//
// What this buys: the identity resync and its VD-versus-plain routing become assertable. Driving
// them for real needs a manager to answer every notifyDataClean(), which is why the recovery path
// carried no assertions at all until #38601 added these. The same reasoning applies to
// SyscollectorImpTest's local-transport-unavailable cases (#38621): they used to reach in through
// a public setSyncProtocol()/setSyncProtocolVD() pair that existed only for this, the one seam
// that had no compile guard.
//
// The fixture is befriended as well as its cases: FRIEND_TEST reaches the TEST_F bodies only, and
// the setup those bodies share has to establish state that start() computes and never runs here --
// m_vdSyncEnabled above all, so that no case can model a VD lane a real agent could not have.
#ifdef SYSCOLLECTOR_UNIT_TESTING
#include <gtest/gtest_prod.h>

#define SYSCOLLECTOR_FRIEND_TEST_DECLARATIONS                                                                          \
    friend class SyscollectorIdentityTest;                                                                             \
    FRIEND_TEST(SyscollectorIdentityTest, AbsentMarkerIsAdoptedWithoutResync);                                         \
    FRIEND_TEST(SyscollectorIdentityTest, UnchangedIdIsANoOp);                                                         \
    FRIEND_TEST(SyscollectorIdentityTest, UnknownIdIsANoOp);                                                           \
    FRIEND_TEST(SyscollectorIdentityTest, FailedMarkerReadAdoptsNothing);                                              \
    FRIEND_TEST(SyscollectorIdentityTest, ChangedIdResendsEachTableOnItsOwnLane);                                      \
    FRIEND_TEST(SyscollectorIdentityTest, ChangedIdSkipsDisabledCollectors);                                           \
    FRIEND_TEST(SyscollectorIdentityTest, ChangedIdSendsTheVDInventoryAsAFirstSync);                                   \
    FRIEND_TEST(SyscollectorIdentityTest, RefusedDataCleanWithholdsTheMarkerAndKeepsGoing);                            \
    FRIEND_TEST(SyscollectorIdentityTest, ResyncStampsTheIntegrityClockPerTable);                                      \
    FRIEND_TEST(SyscollectorIdentityTest, PlainLaneFailureDoesNotRedoTheVDLaneNextCycle);                              \
    FRIEND_TEST(SyscollectorIdentityTest, DisabledVDLaneDoesNotClaimTheVDMarker);                                      \
    FRIEND_TEST(SyscollectorImpTest, SyncModule_LocalTransportUnavailableWithinToleranceLogsDeferred);                 \
    FRIEND_TEST(SyscollectorImpTest, SyncModule_LocalTransportUnavailableAtToleranceLogsDeferred);                     \
    FRIEND_TEST(SyscollectorImpTest, SyncModule_LocalTransportUnavailablePastToleranceLogsWarning)
#else
#define SYSCOLLECTOR_FRIEND_TEST_DECLARATIONS
#endif // SYSCOLLECTOR_UNIT_TESTING

#endif //_SYSCOLLECTOR_DEFS_HPP
