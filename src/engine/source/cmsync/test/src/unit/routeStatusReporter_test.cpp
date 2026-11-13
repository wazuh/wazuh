// SPDX-License-Identifier: AGPL-3.0-or-later
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <cmsync/routeStatusReporter.hpp>

#include "captureLogs.hpp"

namespace
{

using cm::sync::RouteStatusReporter;

const std::string NO_ROUTES_MSG {"[CMSync] No active routes available. Incoming events will be discarded until "
                                 "content synchronization completes"};
const std::string ACTIVE_MSG {"[CMSync] Event processing is now active"};

// Occurrences of `needle` at any level: used to assert that nothing was logged
std::size_t countOf(const std::string& text, const std::string& needle)
{
    std::size_t count {0};
    for (auto pos = text.find(needle); pos != std::string::npos; pos = text.find(needle, pos + needle.size()))
    {
        ++count;
    }
    return count;
}

// Returns the given router states, one per call
std::function<bool()> routeStates(std::vector<bool> states)
{
    return [states = std::move(states), next = std::size_t {0}]() mutable
    {
        return states.at(next++);
    };
}

class RouteStatusReporterTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        logging::setLevel(logging::Level::Info);
    }

    void TearDown() override { logging::setLevel(logging::Level::Warn); }
};

} // namespace

TEST_F(RouteStatusReporterTest, NoRoutesOnRestartLogsWarning)
{
    RouteStatusReporter reporter([]() { return false; }, false);

    const auto logs = captureLogs([&]() { reporter.report(); });

    EXPECT_EQ(countAtLevel(logs.warn, "warning", NO_ROUTES_MSG), 1);
    EXPECT_EQ(countOf(logs.info, NO_ROUTES_MSG), 0);
}

TEST_F(RouteStatusReporterTest, NoRoutesOnFirstStartLogsInfo)
{
    RouteStatusReporter reporter([]() { return false; }, true);

    const auto logs = captureLogs([&]() { reporter.report(); });

    EXPECT_EQ(countAtLevel(logs.info, "info", NO_ROUTES_MSG), 1);
    EXPECT_TRUE(logs.warn.empty()) << logs.warn;
}

TEST_F(RouteStatusReporterTest, RoutesOnFirstReportLogsActive)
{
    RouteStatusReporter reporter([]() { return true; }, false);

    const auto logs = captureLogs([&]() { reporter.report(); });

    EXPECT_EQ(countAtLevel(logs.info, "info", ACTIVE_MSG), 1);
    EXPECT_TRUE(logs.warn.empty()) << logs.warn;
}

TEST_F(RouteStatusReporterTest, LogsOnlyOnTransitions)
{
    RouteStatusReporter reporter(routeStates({false, false, true, true, false}), false);

    const auto logs = captureLogs(
        [&]()
        {
            for (auto i = 0; i < 5; ++i)
            {
                reporter.report();
            }
        });

    EXPECT_EQ(countAtLevel(logs.warn, "warning", NO_ROUTES_MSG), 2);
    EXPECT_EQ(countAtLevel(logs.info, "info", ACTIVE_MSG), 1);
    EXPECT_EQ(countOf(logs.info, NO_ROUTES_MSG), 0);
}

// Once stopped the reporter never logs again, so whether a suppressed report kept the last reported state cannot
// be seen here: report() checks the shutdown before it updates that state.
TEST_F(RouteStatusReporterTest, NoRouteStatusAfterShutdown)
{
    RouteStatusReporter reporter(routeStates({true, false, false}), false);
    auto logs = captureLogs([&]() { reporter.report(); });
    ASSERT_EQ(countAtLevel(logs.info, "info", ACTIVE_MSG), 1);

    reporter.requestShutdown();
    logs = captureLogs(
        [&]()
        {
            reporter.report();
            reporter.report();
        });

    EXPECT_EQ(countOf(logs.warn, NO_ROUTES_MSG), 0);
    EXPECT_EQ(countOf(logs.info, NO_ROUTES_MSG), 0);
}

TEST_F(RouteStatusReporterTest, NoRecoveryAfterShutdown)
{
    RouteStatusReporter reporter(routeStates({false, true}), false);
    auto logs = captureLogs([&]() { reporter.report(); });
    ASSERT_EQ(countAtLevel(logs.warn, "warning", NO_ROUTES_MSG), 1);

    reporter.requestShutdown();
    logs = captureLogs([&]() { reporter.report(); });

    EXPECT_EQ(countOf(logs.info, ACTIVE_MSG), 0);
}

TEST_F(RouteStatusReporterTest, RequestShutdownIsIdempotent)
{
    RouteStatusReporter reporter([]() { return false; }, false);

    const auto logs = captureLogs(
        [&]()
        {
            reporter.requestShutdown();
            reporter.requestShutdown();
            EXPECT_NO_THROW(reporter.report());
        });

    EXPECT_TRUE(logs.warn.empty()) << logs.warn;
    EXPECT_EQ(countOf(logs.info, NO_ROUTES_MSG), 0);
    EXPECT_EQ(countOf(logs.info, ACTIVE_MSG), 0);
}

// The router is torn down while a report is querying it: the report sees no routes only after the shutdown
// request returned, so it must not log them. requestShutdown() runs on this thread while the report is parked in
// the query; a lock held across the query would hang the test.
TEST_F(RouteStatusReporterTest, InFlightReportAtShutdownEmitsNothing)
{
    std::promise<void> entered;
    std::promise<void> release;
    auto released = release.get_future();
    bool parkNextQuery {false};

    RouteStatusReporter reporter(
        [&]()
        {
            if (!parkNextQuery)
            {
                return true;
            }
            entered.set_value();
            released.wait();
            return false;
        },
        false);
    auto logs = captureLogs([&]() { reporter.report(); });
    ASSERT_EQ(countAtLevel(logs.info, "info", ACTIVE_MSG), 1);

    parkNextQuery = true;
    logs = captureLogs(
        [&]()
        {
            std::thread reporting([&]() { reporter.report(); });
            entered.get_future().wait();
            reporter.requestShutdown();
            release.set_value();
            reporting.join();
        });

    EXPECT_EQ(countOf(logs.warn, NO_ROUTES_MSG), 0);
    EXPECT_EQ(countOf(logs.info, NO_ROUTES_MSG), 0);
}

TEST_F(RouteStatusReporterTest, PredicateExceptionLeavesStateUntouched)
{
    auto calls = 0;
    RouteStatusReporter reporter(
        [&]() -> bool
        {
            if (calls++ == 0)
            {
                throw std::runtime_error("router unavailable");
            }
            return false;
        },
        false);

    auto logs = captureLogs([&]() { EXPECT_THROW(reporter.report(), std::runtime_error); });
    EXPECT_TRUE(logs.warn.empty()) << logs.warn;
    EXPECT_EQ(countOf(logs.info, NO_ROUTES_MSG), 0);

    // Still the first report: it logs
    logs = captureLogs([&]() { reporter.report(); });
    EXPECT_EQ(countAtLevel(logs.warn, "warning", NO_ROUTES_MSG), 1);
}
