#include "container_row_budget.h"

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

/// Unlimited is the default, and must stay the default: an agent whose operator
/// has set no container ceiling must behave exactly as it did before one
/// existed.
TEST(ContainerRowBudget, AnUnsetCeilingAdmitsEverything)
{
    EXPECT_TRUE(container_row_admitted(0, 0, false));
    EXPECT_TRUE(container_row_admitted(0, 1000000, false));
    EXPECT_TRUE(container_row_admitted(-1, 1000000, false));
}

TEST(ContainerRowBudget, RowsAreAdmittedUpToTheCeilingAndRefusedAtIt)
{
    EXPECT_TRUE(container_row_admitted(3, 0, false));
    EXPECT_TRUE(container_row_admitted(3, 2, false));

    // AT the ceiling, not one past it. An off-by-one here stores exactly one row
    // more than the operator asked for, per container, on every agent.
    EXPECT_FALSE(container_row_admitted(3, 3, false));
    EXPECT_FALSE(container_row_admitted(3, 4, false));
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
        if (container_row_admitted(limit, busy, false))
        {
            ++busy;
        }
    }

    EXPECT_EQ(busy, static_cast<size_t>(limit))
            << "offering 100 rows against a ceiling of 4 must store exactly 4";
    EXPECT_FALSE(container_row_admitted(limit, busy, false));
    EXPECT_TRUE(container_row_admitted(limit, 0, false)) << "another container is unaffected";
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
    for (const bool walker :
            {
                false, true
            })
    {
        for (const size_t refused :
                {
                    size_t {0}, size_t {1}, size_t {42}
                })
        {
            const bool complete = !container_scan_is_partial(walker, refused);
            EXPECT_EQ(complete, (!walker && refused == 0));
        }
    }
}

/// The accounting discipline the baseline's own reporting depends on.
///
/// A baseline reports a row total, and that total is what an operator and the
/// next engineer read as "what the agent knows". It therefore has to be rows
/// KEPT. Counting rows OFFERED is what let a baseline report 100,063 rows while
/// the database held 91,420 — the 8,643-row shortfall appeared in no counter,
/// no log line and no flag, which is why the defect survived a full e2e run.
///
/// Stored must be exactly what the ceiling allows, refused must be the rest,
/// and the two must account for every row offered.
TEST(ContainerRowBudget, StoredPlusRefusedAccountsForEveryRowOffered)
{
    struct Case
    {
        int limit;
        size_t offered;
        size_t expectStored;
    };

    const Case cases[] =
    {
        {   0, 2005, 2005 },  // unlimited: everything kept
        { 500, 2005,  500 },  // the measured Test B shape
        {3000, 2005, 2005 },  // ceiling above the load never bites
        {   1,    5,    1 },
        { 100,    0,    0 },  // nothing offered, nothing accounted
    };

    for (const auto& c : cases)
    {
        size_t stored = 0;
        size_t refused = 0;

        for (size_t i = 0; i < c.offered; ++i)
        {
            if (container_row_admitted(c.limit, stored, false))
            {
                ++stored;
            }
            else
            {
                ++refused;
            }
        }

        EXPECT_EQ(stored, c.expectStored) << "limit=" << c.limit << " offered=" << c.offered;
        EXPECT_EQ(stored + refused, c.offered) << "every offered row must be accounted for";

        // The reported total is `stored`. If it were `offered`, this is the
        // assertion that would catch it.
        EXPECT_LE(stored, c.offered);
        EXPECT_TRUE(c.limit <= 0 || stored <= static_cast<size_t>(c.limit));
    }
}

/// A refresh never grows the container, so the ceiling never refuses one --
/// not at the limit, and not above it after the limit was lowered.
TEST(ContainerRowBudget, AStoredRowIsAlwaysRefreshed)
{
    EXPECT_TRUE(container_row_admitted(3, 3, true));
    EXPECT_TRUE(container_row_admitted(3, 10, true));
    EXPECT_FALSE(container_row_admitted(3, 3, false));
}

/// The review's scenario, across passes: with limit L, a new file sorted before
/// the cut used to leave the container holding L+1 rows, then more each pass,
/// because a capped pass kept its unrefreshed rows and the next counted from
/// zero. Holdings must stay within L while files come and go, and a vanished
/// file must free its slot.
TEST(ContainerRowBudget, HoldingsNeverExceedTheCeilingAcrossPasses)
{
    constexpr int limit = 3;
    std::set<std::string> stored;
    std::vector<std::string> files {"f2", "f3", "f4", "f5"};

    const auto pass = [&]()
    {
        std::set<std::string> refreshed;
        size_t held = stored.size();

        for (const auto& file : files)
        {
            const bool known = stored.count(file) != 0;

            if (container_row_admitted(limit, held, known))
            {
                refreshed.insert(file);
                held += known ? 0 : 1;
                EXPECT_LE(held, static_cast<size_t>(limit));
            }
        }

        // Cap refusals do not make the scan partial, so unrefreshed rows age out.
        EXPECT_FALSE(container_scan_is_partial(false, 0));
        stored = refreshed;
    };

    pass();
    EXPECT_EQ(stored, (std::set<std::string> {"f2", "f3", "f4"}));

    for (const auto& added :
            {"f0", "f1", "e9"
            })
    {
        files.insert(files.begin(), added);
        pass();
        EXPECT_EQ(stored.size(), static_cast<size_t>(limit)) << "after adding " << added;
    }
    EXPECT_EQ(stored, (std::set<std::string> {"f2", "f3", "f4"})) << "stored files keep their slots";

    files.erase(files.begin() + 3); // f2 is deleted
    pass();
    EXPECT_EQ(stored, (std::set<std::string> {"f3", "f4"})) << "a vanished file ages out first";
    pass();
    EXPECT_EQ(stored, (std::set<std::string> {"e9", "f3", "f4"})) << "and its slot goes to a new file";
}
