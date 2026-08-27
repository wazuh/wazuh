/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ebpf_types.hpp"
#include "mocks/mock_ebpf_loader.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace wazuh::ebpf;
using ::testing::_;
using ::testing::Return;

TEST(EbpfFilterTest, PrefixMatching) {
    const std::vector<std::string> prefixes {"/etc", "/var/ossec"};

    EXPECT_TRUE(matchesAnyPrefix("/etc/shadow", prefixes));
    EXPECT_TRUE(matchesAnyPrefix("/var/ossec/etc/ossec.conf", prefixes));
    EXPECT_FALSE(matchesAnyPrefix("/usr/bin/ls", prefixes));
    EXPECT_FALSE(matchesAnyPrefix("/et", prefixes));
}

TEST(EbpfFilterTest, EmptyPrefixListMatchesNothing) {
    EXPECT_FALSE(matchesAnyPrefix("/etc/shadow", {}));
    EXPECT_FALSE(matchesAnyPrefix("/etc/shadow", {""}));
}

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

    const std::vector<std::string> monitored {"/etc"};
    std::vector<std::string> delivered;

    ASSERT_TRUE(loader.poll(
        [&](const FileEvent& event) {
            if (matchesAnyPrefix(event.path, monitored)) {
                EXPECT_EQ(event.identity.pid, 1234u);
                EXPECT_EQ(event.correlation.cgroup_id, 42u);
                delivered.push_back(event.path);
            }
        },
        250));

    EXPECT_EQ(delivered, std::vector<std::string> {"/etc/shadow"});
}

TEST(EbpfLoaderMockTest, UnimplementedClassesAreRejected) {
    MockEbpfLoader loader;

    EXPECT_CALL(loader, load(EventClass::PROCESS, _)).WillOnce(Return(false));
    EXPECT_FALSE(loader.load(EventClass::PROCESS, ""));
}
