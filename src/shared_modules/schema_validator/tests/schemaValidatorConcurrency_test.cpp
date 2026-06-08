/*
 * Regression tests for the schema validator factory concurrent-initialization
 * data race.
 *
 * SchemaValidatorFactory is a process-wide singleton initialized from several
 * modules running in the same wazuh-modulesd process (syscollector, sca), each with a check-then-act guard
 * (if (!isInitialized()) initialize();) living outside the factory. Before the
 * fix the factory had no synchronization, so concurrent initialize() calls
 * mutated the same std::map at the same time (undefined behaviour): a validator
 * that had been loaded could become unreachable, which surfaced in production as
 * spurious "No schema validator found for index: ..." warnings (and could also
 * crash or hang the process).
 *
 * These tests exercise the same scenario and assert that no validator reachable
 * after a single-threaded initialization is ever lost when initialize() is
 * called concurrently from many threads.
 */

#include "schemaValidator.hpp"
#include <gtest/gtest.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

using namespace SchemaValidator;

namespace
{
    // Indices that the embedded schemas may register. The test only requires the
    // subset that is actually present in the build, so it adapts to whatever is
    // embedded instead of hard-coding a fixed count.
    const std::vector<std::string> kCandidateIndices =
    {
        "wazuh-states-inventory-system",
        "wazuh-states-inventory-hardware",
        "wazuh-states-inventory-hotfixes",
        "wazuh-states-inventory-packages",
        "wazuh-states-inventory-processes",
        "wazuh-states-inventory-ports",
        "wazuh-states-inventory-interfaces",
        "wazuh-states-inventory-protocols",
        "wazuh-states-inventory-networks",
        "wazuh-states-inventory-users",
        "wazuh-states-inventory-groups",
        "wazuh-states-inventory-services",
        "wazuh-states-inventory-browser-extensions",
        "wazuh-states-fim-files",
        "wazuh-states-fim-registry-keys",
        "wazuh-states-fim-registry-values",
        "wazuh-states-sca",
    };

    std::vector<std::string> reachableIndices(SchemaValidatorFactory& factory)
    {
        std::vector<std::string> reachable;

        for (const auto& index : kCandidateIndices)
        {
            if (factory.getValidator(index))
            {
                reachable.push_back(index);
            }
        }

        return reachable;
    }
}

class SchemaValidatorConcurrencyTest : public ::testing::Test
{
    protected:
        void TearDown() override
        {
            // Leave the shared singleton in an initialized state for any test
            // that runs afterwards (initialize() is idempotent).
            SchemaValidatorFactory::getInstance().initialize();
        }
};

// Baseline: a single-threaded initialization reaches a non-empty set of
// validators. Guards the concurrency test below against a build with no embedded
// schemas (which would make the regression check vacuously pass).
TEST_F(SchemaValidatorConcurrencyTest, SingleThreadedInitializeReachesSchemas)
{
    auto& factory = SchemaValidatorFactory::getInstance();

    factory.reset();
    ASSERT_TRUE(factory.initialize());
    ASSERT_TRUE(factory.isInitialized());
    ASSERT_FALSE(reachableIndices(factory).empty())
            << "No schemas embedded; cannot exercise the concurrency regression.";
}

// Regression: many threads run the same check-then-act guard as the real modules
// and call initialize() simultaneously. The factory must end up initialized and
// every validator reachable after a clean single-threaded init must still be
// reachable (no key lost to a corrupted std::map).
TEST_F(SchemaValidatorConcurrencyTest, ConcurrentInitializeDoesNotLoseValidators)
{
    auto& factory = SchemaValidatorFactory::getInstance();

    // Establish the expected reachable set with a clean single-threaded init.
    factory.reset();
    ASSERT_TRUE(factory.initialize());
    const auto expected = reachableIndices(factory);
    ASSERT_FALSE(expected.empty());

    constexpr int kIterations = 100;
    constexpr int kThreads = 8;

    for (int iteration = 0; iteration < kIterations; ++iteration)
    {
        factory.reset();

        std::atomic<int> ready {0};
        std::atomic<bool> go {false};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);

        for (int t = 0; t < kThreads; ++t)
        {
            threads.emplace_back([&]()
            {
                ready.fetch_add(1);

                while (!go.load())
                {
                    // Spin so all threads hit initialize() at the same time.
                }

                if (!factory.isInitialized())
                {
                    factory.initialize();
                }
            });
        }

        while (ready.load() < kThreads)
        {
            // Wait until every thread is parked on the barrier.
        }

        go.store(true);

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_TRUE(factory.isInitialized()) << "factory not initialized at iteration " << iteration;

        for (const auto& index : expected)
        {
            EXPECT_NE(factory.getValidator(index), nullptr)
                    << "validator lost for index '" << index << "' at iteration " << iteration;
        }
    }
}
