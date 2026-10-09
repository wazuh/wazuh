#include "container_row_budget.h"

#include <gtest/gtest.h>

/// Unlimited is the default, and must stay the default: an agent whose operator
/// has set no container ceiling must behave exactly as it did before one
/// existed.
TEST(ContainerRowBudget, AnUnsetCeilingAdmitsEverything)
{
    EXPECT_TRUE(container_row_admitted(0, 0));
    EXPECT_TRUE(container_row_admitted(0, 1000000));
    EXPECT_TRUE(container_row_admitted(-1, 1000000));
}

TEST(ContainerRowBudget, RowsAreAdmittedUpToTheCeilingAndRefusedAtIt)
{
    EXPECT_TRUE(container_row_admitted(3, 0));
    EXPECT_TRUE(container_row_admitted(3, 2));

    // AT the ceiling, not one past it. An off-by-one here stores exactly one row
    // more than the operator asked for, per container, on every agent.
    EXPECT_FALSE(container_row_admitted(3, 3));
    EXPECT_FALSE(container_row_admitted(3, 4));
}

/// A container fills its own ceiling and stops; the count is its own, so a
/// second container starts from zero regardless of what the first did.
TEST(ContainerRowBudget, EachContainerFillsItsOwnCeiling)
{
    constexpr int limit = 4;
    constexpr size_t offered = 100;
    size_t busy = 0;

    // A bounded loop, not `while (admitted)`. Driving an unbounded loop from the
    // function under test means a mutation that makes it always-true HANGS the
    // suite instead of failing it — a CI timeout to diagnose rather than a red
    // assertion to read. Found by mutating this very rule.
    for (size_t i = 0; i < offered; ++i)
    {
        if (container_row_admitted(limit, busy))
        {
            ++busy;
        }
    }

    EXPECT_EQ(busy, static_cast<size_t>(limit))
            << "offering 100 rows against a ceiling of 4 must store exactly 4";
    EXPECT_FALSE(container_row_admitted(limit, busy));
    EXPECT_TRUE(container_row_admitted(limit, 0)) << "another container is unaffected";
}

/// D11 rule 4. The walker's own verdict is not the only way a row set becomes
/// incomplete — the database refusing a row leaves exactly the same hole, and
/// a delete detection over a subset deletes everything it cannot see.
TEST(ContainerRowBudget, ARefusedRowMakesTheScanPartialEvenWhenTheWalkWasWhole)
{
    EXPECT_FALSE(container_scan_is_partial(false, 0)) << "a whole walk that stored everything";

    EXPECT_TRUE(container_scan_is_partial(false, 1))
            << "the walk was complete but the database refused a row - still a partial view";
    EXPECT_TRUE(container_scan_is_partial(false, 8643))
            << "the count measured on a real node while scans reported 0 partial";

    EXPECT_TRUE(container_scan_is_partial(true, 0)) << "the walker's own verdict still counts";
    EXPECT_TRUE(container_scan_is_partial(true, 5)) << "and both together";
}

/// The property stated as an invariant rather than as cases: a scan is complete
/// only when nothing was withheld by either layer.
TEST(ContainerRowBudget, AScanIsCompleteOnlyWhenNothingWasWithheld)
{
    for (const bool walker : {false, true})
    {
        for (const size_t refused : {size_t {0}, size_t {1}, size_t {42}})
        {
            const bool complete = !container_scan_is_partial(walker, refused);
            EXPECT_EQ(complete, (!walker && refused == 0));
        }
    }
}
