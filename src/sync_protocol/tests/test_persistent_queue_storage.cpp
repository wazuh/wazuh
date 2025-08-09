/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "persistent_queue_storage.hpp"

struct QueueScenario
{
    std::string name;
    std::vector<PersistedData> initial;
    bool doFetchAndSync;
    std::vector<PersistedData> eventsInSync;
    bool removeSynced;
    bool resetSyncing;
    size_t expectedRows;
    Operation expectedOp;
};

inline void PrintTo(const QueueScenario& q, std::ostream* os)
{
    *os << q.name;
}

class PersistentQueueFullParamTest :
    public ::testing::TestWithParam<QueueScenario>
{
    protected:
        std::unique_ptr<PersistentQueueStorage> storage;

        void SetUp() override
        {
            storage = std::make_unique<PersistentQueueStorage>(":memory:");
        }

        void TearDown() override
        {
            storage.reset();
        }
};

TEST_P(PersistentQueueFullParamTest, HandlesSubmitFetchRemoveResetCorrectly)
{
    auto param = GetParam();

    // 1. Init DB
    for (auto& ev : param.initial)
    {
        storage->submitOrCoalesce(ev);
    }

    // 2. Simulate fetchAndMarkForSync
    if (param.doFetchAndSync)
    {
        storage->fetchAndMarkForSync();

        // 3. Events during a sincronization
        for (auto& evs : param.eventsInSync)
        {
            storage->submitOrCoalesce(evs);
        }
    }

    // 4. Simulate removeAllSynced
    if (param.removeSynced)
    {
        storage->removeAllSynced();
    }

    // 5. Simulate resetAllSyncing
    if (param.resetSyncing)
    {
        storage->resetAllSyncing();
    }

    // 6. Verify final status
    auto rows = storage->fetchAndMarkForSync();
    EXPECT_EQ(rows.size(), param.expectedRows);

    if (!rows.empty())
    {
        EXPECT_EQ(rows[0].operation, param.expectedOp);
    }
}

INSTANTIATE_TEST_SUITE_P(
    FullQueueCases,
    PersistentQueueFullParamTest,
    ::testing::Values(
// 1. CREATE
QueueScenario
{
    "Case 1",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    false, {}, false, false,
    1, Operation::CREATE
},
// 2. CREATE + MODIFY no sync -> MODIFY
QueueScenario
{
    "Case 2",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY}
    },
    false, {}, false, false,
    1, Operation::MODIFY
},
// 3. CREATE + DELETE no sync -> row deleted
QueueScenario
{
    "Case 3",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE}
    },
    false, {}, false, false,
    0, Operation::CREATE
},
// 4. MODIFY + DELETE no sync -> DELETE
QueueScenario
{
    "Case 4",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::MODIFY},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE}
    },
    false, {}, false, false,
    1, Operation::DELETE
},
// 5. DELETE
QueueScenario
{
    "Case 5",
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE} },
    false, {}, false, false,
    1, Operation::DELETE
},
// 6. CREATE + Sync + MODIFY during  sync + sync success -> MODIFY
QueueScenario
{
    "Case 6",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true,
    { PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY} },
    true, false,
    1, Operation::MODIFY
},
// 7. CREATE + Sync + DELETE during  sync + sync success -> DELETE
QueueScenario
{
    "Case 7",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true,
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE} },
    true, false,
    1, Operation::DELETE
},
// 8. CREATE + Sync + DELETE during  sync + sync fail -> row deleted
QueueScenario
{
    "Case 8",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true,
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE} },
    false, true,
    0, Operation::DELETE
},
// 9. CREATE + Sync + MODIFY during  sync + fail -> MODIFY
QueueScenario
{
    "Case 9",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true,
    { PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY} },
    false, true,
    1, Operation::MODIFY
},
// 10. DELETE + MODIFY -> MODIFY
QueueScenario
{
    "Case 10",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY}
    },
    false, {}, false, false,
    1, Operation::MODIFY
},
// 11. Sync
QueueScenario
{
    "Case 11",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true, {}, true, false,
    0, Operation::CREATE
},
// 12. Two MODIFY -> MODIFY
QueueScenario
{
    "Case 12",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::MODIFY},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY},
    },
    false, {}, false, false,
    1, Operation::MODIFY
},
// 13. Two IDs
QueueScenario
{
    "Case 13",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE},
        PersistedData{0, "id2", "idx", "{}", Operation::MODIFY}
    },
    false, {}, false, false,
    2, Operation::CREATE
},
// 14. MODIFY + Sync + DELETE + CREATE + DELETE during sync + sync fail -> DELETE
QueueScenario
{
    "Case 14",
    { PersistedData{0, "id1", "idx", "{}", Operation::MODIFY} },
    true,
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE},
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE}
    },
    false, true,
    1, Operation::DELETE
},
// 15. CREATE -> DELETE -> CREATE -> CREATE
QueueScenario
{
    "Case 15",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE},
        PersistedData{0, "id1", "idx2", "{}", Operation::CREATE}
    },
    false, {}, false, false,
    1, Operation::CREATE
},
// 16. CREATE + Sync + MODIFY + DELETE + MODIFY during sync + sync success -> MODIFY
QueueScenario
{
    "Case 16",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true,
    {
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE},
        PersistedData{0, "id1", "idx3", "{}", Operation::MODIFY}
    },
    true, false,
    1, Operation::MODIFY
},
// 17. CREATE + Sync + DELETE + CREATE during sync + sync fail -> CREATE
QueueScenario
{
    "Case 17",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE} },
    true,
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE},
        PersistedData{0, "id1", "idx2", "{}", Operation::CREATE}
    },
    false, true,
    1, Operation::CREATE
}
    )
);
