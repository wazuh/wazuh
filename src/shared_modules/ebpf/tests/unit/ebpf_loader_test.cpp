/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "bounded_queue.hpp"
#include "ebpf_types.hpp"
#include "mocks/mock_ebpf_loader.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

using namespace wazuh::ebpf;
using ::testing::_;
using ::testing::Return;

TEST(EbpfLoaderMockTest, ConsumerOwnsLoadAndPollLoop) {
    MockEbpfLoader loader;

    EXPECT_CALL(loader, load(EventClass::FILE, _)).WillOnce(Return(true));
    EXPECT_CALL(loader, poll(_, _)).WillOnce([](const FileEventCallback& callback, int) {
        FileEvent event;
        event.type = FileEventType::OPEN_CREATE;
        event.path = "/etc/shadow";
        event.identity.pid = 1234;
        event.correlation.cgroup_id = 42;
        callback(event);
        return true;
    });

    ASSERT_TRUE(loader.load(EventClass::FILE, "lib/modern.bpf.o"));

    std::vector<std::string> delivered;

    ASSERT_TRUE(loader.poll(
        [&](const FileEvent& event) {
            EXPECT_EQ(event.identity.pid, 1234u);
            EXPECT_EQ(event.correlation.cgroup_id, 42u);
            delivered.push_back(event.path);
        },
        250));

    EXPECT_EQ(delivered, std::vector<std::string> {"/etc/shadow"});
}

TEST(EbpfLoaderMockTest, UnimplementedClassesAreRejected) {
    MockEbpfLoader loader;

    EXPECT_CALL(loader, load(EventClass::PROCESS, _)).WillOnce(Return(false));
    EXPECT_FALSE(loader.load(EventClass::PROCESS, ""));
}

TEST(BoundedQueueTest, DropsWhenFullAndKeepsOrder) {
    BoundedQueue<std::string> queue(2);

    EXPECT_TRUE(queue.push("first"));
    EXPECT_TRUE(queue.push("second"));
    EXPECT_FALSE(queue.push("third")); // full: reported, never blocks the poller

    std::string value;
    ASSERT_TRUE(queue.pop(value, 0));
    EXPECT_EQ(value, "first");
    ASSERT_TRUE(queue.pop(value, 0));
    EXPECT_EQ(value, "second");
}

TEST(BoundedQueueTest, PopTimesOutWhenEmpty) {
    BoundedQueue<std::string> queue(1);

    std::string value;
    EXPECT_FALSE(queue.pop(value, 10));
}

TEST(BoundedQueueTest, PopWakesOnPushFromAnotherThread) {
    BoundedQueue<std::string> queue(1);

    std::thread producer([&queue]() { queue.push("late"); });

    std::string value;
    EXPECT_TRUE(queue.pop(value, 2000));
    EXPECT_EQ(value, "late");
    producer.join();
}
