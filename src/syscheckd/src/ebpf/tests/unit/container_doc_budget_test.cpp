#include "container_doc_budget.h"

#include <gtest/gtest.h>

/// Unlimited is the default and must stay entirely free of accounting: an agent
/// whose manager predates O10 sends no budget, and must behave exactly as it did
/// before container FIM had one.
TEST(ContainerDocBudget, AnUnsetBudgetReportsEverythingAndCountsNothing)
{
    for (const int stored : {0, 1})
    {
        for (const int is_delete : {0, 1})
        {
            const auto d = container_budget_decide(0, 1000000, stored, is_delete);
            EXPECT_EQ(d.sync_flag, 1);
            EXPECT_EQ(d.count_delta, 0);
        }
    }

    const auto negative = container_budget_decide(-1, 0, 0, 0);
    EXPECT_EQ(negative.sync_flag, 1);
    EXPECT_EQ(negative.count_delta, 0);
}

TEST(ContainerDocBudget, RowsAreReportedUpToTheBudgetAndWithheldAfterIt)
{
    EXPECT_EQ(container_budget_decide(3, 0, 0, 0).sync_flag, 1);
    EXPECT_EQ(container_budget_decide(3, 2, 0, 0).sync_flag, 1);

    // At the budget, not one past it: `current < limit` is the boundary, and an
    // off-by-one here reports exactly one document more than the operator asked
    // for, on every agent, for ever.
    const auto at_limit = container_budget_decide(3, 3, 0, 0);
    EXPECT_EQ(at_limit.sync_flag, 0);
    EXPECT_EQ(at_limit.count_delta, 0) << "a withheld row must not consume a slot";
}

TEST(ContainerDocBudget, AGrantedRowConsumesExactlyOneSlot)
{
    const auto granted = container_budget_decide(10, 4, 0, 0);
    EXPECT_EQ(granted.sync_flag, 1);
    EXPECT_EQ(granted.count_delta, 1);
}

/// A modification of a row that is already reported must not be counted again.
/// Counting it twice makes the budget drift DOWN by one per modification, so a
/// busy container silently loses its allowance over time rather than at once —
/// the failure mode hardest to attribute in the field.
TEST(ContainerDocBudget, ModifyingAnAlreadyReportedRowDoesNotSpendTheBudgetTwice)
{
    const auto d = container_budget_decide(10, 4, 1, 0);
    EXPECT_EQ(d.sync_flag, 1);
    EXPECT_EQ(d.count_delta, 0);
}

/// Deleting a reported row releases its slot; deleting a WITHHELD one must not
/// credit the budget, or the count drifts upward and eventually reports space
/// that does not exist.
TEST(ContainerDocBudget, OnlyAReportedRowReleasesItsSlotWhenDeleted)
{
    const auto reported = container_budget_decide(10, 4, 1, 1);
    EXPECT_EQ(reported.sync_flag, 1);
    EXPECT_EQ(reported.count_delta, -1);

    const auto withheld = container_budget_decide(10, 10, 0, 1);
    EXPECT_EQ(withheld.sync_flag, 0);
    EXPECT_EQ(withheld.count_delta, 0);
}

/// The property that matters over a lifetime: replaying a mixed sequence must
/// leave the counter equal to the number of rows actually reported, never above
/// the budget. A budget that drifts is worse than none, because it looks healthy.
TEST(ContainerDocBudget, TheCounterNeverExceedsTheBudgetAcrossAMixedSequence)
{
    constexpr int limit = 5;
    int count = 0;
    int reported = 0;

    // 20 inserts, then modify and delete a mixture of reported and withheld rows.
    for (int i = 0; i < 20; ++i)
    {
        const auto d = container_budget_decide(limit, count, 0, 0);
        count += d.count_delta;
        reported += d.sync_flag;
        EXPECT_LE(count, limit);
    }
    EXPECT_EQ(count, limit);
    EXPECT_EQ(reported, limit) << "exactly `limit` rows may be reported";

    for (int i = 0; i < 10; ++i)
    {
        count += container_budget_decide(limit, count, 1, 0).count_delta; // modify reported
        count += container_budget_decide(limit, count, 0, 0).count_delta; // insert, no room
        EXPECT_LE(count, limit);
    }
    EXPECT_EQ(count, limit);

    for (int i = 0; i < limit; ++i)
    {
        count += container_budget_decide(limit, count, 1, 1).count_delta; // delete reported
    }
    EXPECT_EQ(count, 0) << "every slot taken must be released again";

    // Deleting withheld rows afterwards must not push the counter negative.
    for (int i = 0; i < 5; ++i)
    {
        count += container_budget_decide(limit, count, 0, 1).count_delta;
    }
    EXPECT_EQ(count, 0);
}
