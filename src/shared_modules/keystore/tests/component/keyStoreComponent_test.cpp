/*
 * Wazuh keystore
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "keyStoreComponent_test.hpp"
#include "include/keyStore.hpp"
#include "rocksDBWrapper.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <thread>
#include <vector>

constexpr auto DATABASE_PATH {"queue/keystore"};
constexpr auto KS_VERSION {"2"};
constexpr auto KS_VERSION_FIELD {"version"};

std::string getKeystoreVersion()
{
    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);
    std::string value;
    keystoreDB.get(KS_VERSION_FIELD, value, "default");
    return value;
}

TEST(KeyStoreComponentTest, TestPutGet)
{
    std::filesystem::remove_all(DATABASE_PATH);

    // Check that the keystore version is empty when the database is empty
    ASSERT_EQ(getKeystoreVersion(), "");

    // Put a value in the keystore and check that the version is updated
    Keystore::put("default", "key1", "value1");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);
    Keystore::put("default", "key2", "value2");

    // Get the value from the keystore and check that it is the same as the one put
    std::string out;
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "value1");
    Keystore::get("default", "key2", out);
    ASSERT_EQ(out, "value2");
}

TEST(KeyStoreComponentTest, TestGetDoesNotCreateColumnFamily)
{
    std::filesystem::remove_all(DATABASE_PATH);

    std::string out;
    Keystore::get("missing", "key1", out);
    ASSERT_EQ(out, "");
    ASSERT_EQ(Keystore::get("missing", "key1"), "");

    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);
    ASSERT_FALSE(keystoreDB.columnExists("missing"));
}

TEST(KeyStoreComponentTest, TestGetWaitsForAnotherHandleInsteadOfRepairing)
{
    std::filesystem::remove_all(DATABASE_PATH);
    Keystore::put("default", "key1", "value1");

    // Another handle (as the CLI or another consumer would) holds the database for a while.
    auto holder = std::make_unique<Utils::RocksDBWrapper>(DATABASE_PATH, false);
    std::thread releaser(
        [&holder]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            holder.reset();
        });

    std::string out;
    EXPECT_NO_THROW(Keystore::get("default", "key1", out));
    releaser.join();

    EXPECT_EQ(out, "value1");
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(DATABASE_PATH) / "lost"));
}

TEST(KeyStoreComponentTest, TestConcurrentAccessSucceeds)
{
    std::filesystem::remove_all(DATABASE_PATH);
    Keystore::put("default", "key1", "value1");

    constexpr auto THREADS {8};
    constexpr auto ITERATIONS {5};
    std::atomic<int> failures {0};
    std::vector<std::thread> workers;

    for (int i = 0; i < THREADS; ++i)
    {
        workers.emplace_back(
            [&failures, i]()
            {
                for (int j = 0; j < ITERATIONS; ++j)
                {
                    try
                    {
                        if (i % 2 == 0)
                        {
                            if (Keystore::get("default", "key1") != "value1")
                            {
                                ++failures;
                            }
                        }
                        else
                        {
                            Keystore::put("default", "writer" + std::to_string(i), "value");
                        }
                    }
                    catch (const std::exception&)
                    {
                        ++failures;
                    }
                }
            });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(failures.load(), 0);
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(DATABASE_PATH) / "lost"));
}

TEST(KeyStoreComponentTest, TestALockHeldPastTheWaitIsReportedAsBusyAndChangesNothing)
{
    std::filesystem::remove_all(DATABASE_PATH);
    Keystore::put("default", "key1", "value1");

    {
        // Another handle holds the database for longer than the caller is willing to wait.
        Utils::RocksDBWrapper holder(DATABASE_PATH, false);

        std::string out;
        EXPECT_THROW(Keystore::get("default", "key1", out, std::chrono::milliseconds(100)), KeystoreLockTimeout);
        EXPECT_EQ(out, "");
        EXPECT_THROW(Keystore::put("default", "key1", "changed", std::chrono::milliseconds(100)), KeystoreLockTimeout);
    }

    EXPECT_EQ(Keystore::get("default", "key1"), "value1") << "a put that gave up must not have written";
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(DATABASE_PATH) / "lost"));
}

TEST(KeyStoreComponentTest, TestTheCallersWaitIsHonoured)
{
    std::filesystem::remove_all(DATABASE_PATH);
    Keystore::put("default", "key1", "value1");

    auto holder = std::make_unique<Utils::RocksDBWrapper>(DATABASE_PATH, false);
    std::thread releaser(
        [&holder]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            holder.reset();
        });

    std::string out;
    EXPECT_NO_THROW(Keystore::get("default", "key1", out, Keystore::CLI_LOCK_WAIT));
    releaser.join();
    EXPECT_EQ(out, "value1");
}

TEST(KeyStoreComponentTest, TestTheCliWaitsLongerThanTheDaemons)
{
    // A burst of daemon reads must delay the CLI, not fail it.
    EXPECT_GT(Keystore::CLI_LOCK_WAIT, Keystore::DEFAULT_LOCK_WAIT);
    EXPECT_EQ(Keystore::DEFAULT_LOCK_WAIT, std::chrono::milliseconds(5000));
}
