/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <vector>
#include "systemd_units_linux.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::StrEq;
using ::testing::Sequence;
using ::testing::Invoke;

class MockDBusWrapper : public ISDBusWrapper
{
    public:
        MOCK_METHOD(int, sd_bus_open_system, (sd_bus** ret), (override));
        MOCK_METHOD(sd_bus*, sd_bus_unref, (sd_bus* bus), (override));
        MOCK_METHOD(sd_bus_message*, sd_bus_message_unref, (sd_bus_message* m), (override));
        MOCK_METHOD(int, sd_bus_message_enter_container, (sd_bus_message* m, char type, const char* contents), (override));
        MOCK_METHOD(int, sd_bus_message_exit_container, (sd_bus_message* m), (override));
        MOCK_METHOD(int, sd_bus_get_property_string, (sd_bus* bus, const char* destination, const char* path, const char* interface, const char* member, sd_bus_error* retError, char** ret), (override));
        MOCK_METHOD(int, callListUnits, (sd_bus* bus, sd_bus_message** reply, sd_bus_error* error), (override));
        MOCK_METHOD(int, parseSystemdUnit, (sd_bus_message* m, SystemdUnit& outData), (override));
};

class MockSystemWrapper : public ISystemWrapper
{
    public:
        MOCK_METHOD(long, sysconf, (int name), (const, override));
        MOCK_METHOD(FILE*, fopen, (const char*, const char*), (override));
        MOCK_METHOD(int, fclose, (FILE*), (override));
        MOCK_METHOD(char*, strerror, (int), (override));
};

class SystemdUnitsProviderTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockDBusWrapper> mockDBusWrapper;
        std::shared_ptr<MockSystemWrapper> mockSystemWrapper;
        std::unique_ptr<SystemdUnitsProvider> provider;

        void SetUp() override
        {
            mockDBusWrapper = std::make_shared<MockDBusWrapper>();
            mockSystemWrapper = std::make_shared<MockSystemWrapper>();
            provider = std::make_unique<SystemdUnitsProvider>(mockDBusWrapper, mockSystemWrapper);
        }
};

TEST_F(SystemdUnitsProviderTest, CollectsUnitsSuccessfully)
{
    sd_bus* mock_bus = reinterpret_cast<sd_bus*>(100); // A dummy bus pointer
    sd_bus_message* mock_reply = reinterpret_cast<sd_bus_message*>(200); // A dummy reply pointer
    char* mock_error_str = strdup("No error"); // Mock strerror

    Sequence s;

    EXPECT_CALL(*mockDBusWrapper, sd_bus_open_system(_))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<0>(mock_bus), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, callListUnits(mock_bus, _, nullptr))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<1>(mock_reply), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_ARRAY, StrEq("(ssssssouso)")))
    .InSequence(s)
    .WillOnce(Return(0)); // Successfully enter array

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_STRUCT, StrEq("ssssssouso")))
    .InSequence(s)
    .WillOnce(Return(1)); // One unit found

    EXPECT_CALL(*mockDBusWrapper, parseSystemdUnit(mock_reply, _))
    .InSequence(s)
    .WillOnce(Invoke(
                  [](sd_bus_message*, SystemdUnit & outData) -> int
    {
        outData.id = "unit_id_mock";
        outData.description = "description_mock";
        outData.loadState = "loaded_mock";
        outData.activeState = "active_mock";
        outData.subState = "sub_mock";
        outData.following = "following_mock";
        outData.objectPath = "/org/freedesktop/systemd1/unit/mock";
        outData.jobId = 123;
        outData.jobType = "start_mock";
        outData.jobPath = "/org/freedesktop/systemd1/job/mock";
        return 0;
    }));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    StrEq("org.freedesktop.systemd1"),
                    StrEq("/org/freedesktop/systemd1/unit/mock"),
                    StrEq("org.freedesktop.systemd1.Unit"),
                    StrEq("FragmentPath"),
                    nullptr,
                    _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("/etc/systemd/system/mock.service")), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    StrEq("org.freedesktop.systemd1"),
                    StrEq("/org/freedesktop/systemd1/unit/mock"),
                    StrEq("org.freedesktop.systemd1.Unit"),
                    StrEq("SourcePath"),
                    nullptr,
                    _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("/lib/systemd/system/mock.service")), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    StrEq("org.freedesktop.systemd1"),
                    StrEq("/org/freedesktop/systemd1/unit/mock"),
                    StrEq("org.freedesktop.systemd1.Service"),
                    StrEq("User"),
                    nullptr,
                    _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("root")), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    StrEq("org.freedesktop.systemd1"),
                    StrEq("/org/freedesktop/systemd1/unit/mock"),
                    StrEq("org.freedesktop.systemd1.Unit"),
                    StrEq("UnitFileState"),
                    nullptr,
                    _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("enabled")), Return(0)));

    // Expectations for exiting the struct container
    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_exit_container(mock_reply))
    .InSequence(s)
    .WillOnce(Return(0));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_STRUCT, StrEq("ssssssouso")))
    .InSequence(s)
    .WillOnce(Return(0)); // Second call: no more units, exit loop

    // Expectations for exiting the array container
    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_exit_container(mock_reply))
    .InSequence(s)
    .WillOnce(Return(0));

    // Expectations for unreferencing reply and bus
    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_unref(mock_reply))
    .InSequence(s)
    .WillOnce(Return(mock_reply));
    EXPECT_CALL(*mockDBusWrapper, sd_bus_unref(mock_bus))
    .InSequence(s)
    .WillOnce(Return(mock_bus));

    EXPECT_CALL(*mockSystemWrapper, strerror(_))
    .WillRepeatedly(Return(mock_error_str));

    // Call the method under test
    nlohmann::json result = provider->collect();

    // Assertions
    ASSERT_TRUE(result.is_array());
    ASSERT_EQ(result.size(), 1u);

    const auto& unit = result[0];
    EXPECT_EQ(unit["id"], "unit_id_mock");
    EXPECT_EQ(unit["description"], "description_mock");
    EXPECT_EQ(unit["loadState"], "loaded_mock");
    EXPECT_EQ(unit["activeState"], "active_mock");
    EXPECT_EQ(unit["subState"], "sub_mock");
    EXPECT_EQ(unit["following"], "following_mock");
    EXPECT_EQ(unit["objectPath"], "/org/freedesktop/systemd1/unit/mock");
    EXPECT_EQ(unit["jobId"], 123);
    EXPECT_EQ(unit["jobType"], "start_mock");
    EXPECT_EQ(unit["jobPath"], "/org/freedesktop/systemd1/job/mock");
    EXPECT_EQ(unit["fragmentPath"], "/etc/systemd/system/mock.service");
    EXPECT_EQ(unit["sourcePath"], "/lib/systemd/system/mock.service");
    EXPECT_EQ(unit["user"], "root");
    EXPECT_EQ(unit["unitFileState"], "enabled");

    free(mock_error_str); // Clean up allocated string
}

TEST_F(SystemdUnitsProviderTest, ReturnsEmptyJsonWhenBusOpenFails)
{

    char* mock_error_str = strdup("Permission denied");

    EXPECT_CALL(*mockDBusWrapper, sd_bus_open_system(_))
    .WillOnce(Return(-1)); // Simulate failure

    EXPECT_CALL(*mockSystemWrapper, strerror(1)) // Expect strerror(1) since -ret becomes 1
    .WillOnce(Return(mock_error_str));

    nlohmann::json result = provider->collect();

    ASSERT_TRUE(result.is_array());
    ASSERT_TRUE(result.empty());

    free(mock_error_str);
}

TEST_F(SystemdUnitsProviderTest, ReturnsEmptyJsonWhenCallMethodFails)
{

    sd_bus* mock_bus = reinterpret_cast<sd_bus*>(100);
    char* mock_error_str = strdup("Method not found");

    EXPECT_CALL(*mockDBusWrapper, sd_bus_open_system(_))
    .WillOnce(DoAll(SetArgPointee<0>(mock_bus), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, callListUnits(_, _, _))
    .WillOnce(Return(-2)); // Simulate failure

    EXPECT_CALL(*mockSystemWrapper, strerror(2)) // Expect strerror(2)
    .WillOnce(Return(mock_error_str));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_unref(mock_bus))
    .WillOnce(Return(mock_bus));

    nlohmann::json result = provider->collect();

    ASSERT_TRUE(result.is_array());
    ASSERT_TRUE(result.empty());

    free(mock_error_str);
}

TEST_F(SystemdUnitsProviderTest, ReturnsEmptyJsonWhenEnterArrayContainerFails)
{

    sd_bus* mock_bus = reinterpret_cast<sd_bus*>(100);
    sd_bus_message* mock_reply = reinterpret_cast<sd_bus_message*>(200);
    char* mock_error_str = strdup("Invalid array format");

    EXPECT_CALL(*mockDBusWrapper, sd_bus_open_system(_))
    .WillOnce(DoAll(SetArgPointee<0>(mock_bus), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, callListUnits(mock_bus, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(mock_reply), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_ARRAY, StrEq("(ssssssouso)")))
    .WillOnce(Return(-3)); // Simulate failure

    EXPECT_CALL(*mockSystemWrapper, strerror(3)) // Expect strerror(3)
    .WillOnce(Return(mock_error_str));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_unref(mock_reply))
    .WillOnce(Return(mock_reply));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_unref(mock_bus))
    .WillOnce(Return(mock_bus));

    nlohmann::json result = provider->collect();

    ASSERT_TRUE(result.is_array());
    ASSERT_TRUE(result.empty());

    free(mock_error_str);
}

TEST_F(SystemdUnitsProviderTest, HandlesMessageReadFailure)
{

    sd_bus* mock_bus = reinterpret_cast<sd_bus*>(100);
    sd_bus_message* mock_reply = reinterpret_cast<sd_bus_message*>(200);
    char* mock_error_str = strdup("Corrupt message");

    Sequence s;
    EXPECT_CALL(*mockDBusWrapper, sd_bus_open_system(_))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<0>(mock_bus), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, callListUnits(mock_bus, _, _))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<1>(mock_reply), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_ARRAY, StrEq("(ssssssouso)")))
    .InSequence(s)
    .WillOnce(Return(0));

    // Simulate entering one struct, then failing to read it
    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_STRUCT, StrEq("ssssssouso")))
    .InSequence(s)
    .WillOnce(Return(1)); // Enter one struct

    EXPECT_CALL(*mockDBusWrapper, parseSystemdUnit(mock_reply, _))
    .InSequence(s)
    .WillOnce(Return(-4)); // Simulate read failure

    EXPECT_CALL(*mockSystemWrapper, strerror(4)) // Expect strerror(4)
    .InSequence(s)
    .WillOnce(Return(mock_error_str));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_exit_container(mock_reply))
    .InSequence(s)
    .WillOnce(Return(0)); // Exit the array container

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_unref(mock_reply))
    .InSequence(s)
    .WillOnce(Return(mock_reply));
    EXPECT_CALL(*mockDBusWrapper, sd_bus_unref(mock_bus))
    .InSequence(s)
    .WillOnce(Return(mock_bus));

    nlohmann::json result = provider->collect();

    ASSERT_TRUE(result.is_array());
    ASSERT_TRUE(result.empty()); // Should be empty because the read failed before adding any unit

    free(mock_error_str);
}

TEST_F(SystemdUnitsProviderTest, HandlesPropertyRetrievalError)
{

    sd_bus* mock_bus = reinterpret_cast<sd_bus*>(100);
    sd_bus_message* mock_reply = reinterpret_cast<sd_bus_message*>(200);
    char* mock_error_str = strdup("Property not found");

    Sequence s;
    EXPECT_CALL(*mockDBusWrapper, sd_bus_open_system(_))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<0>(mock_bus), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, callListUnits(mock_bus, _, _))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<1>(mock_reply), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_ARRAY, StrEq("(ssssssouso)")))
    .InSequence(s)
    .WillOnce(Return(0));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_STRUCT, StrEq("ssssssouso")))
    .InSequence(s)
    .WillOnce(Return(1)); // One unit

    EXPECT_CALL(*mockDBusWrapper, parseSystemdUnit(mock_reply, _))
    .InSequence(s)
    .WillOnce(Invoke(
                  [](sd_bus_message*, SystemdUnit & outData) -> int
    {
        outData.id = "unit_id_mock";
        outData.description = "description_mock";
        outData.loadState = "loaded_mock";
        outData.activeState = "active_mock";
        outData.subState = "sub_mock";
        outData.following = "following_mock";
        outData.objectPath = "/org/freedesktop/systemd1/unit/mock";
        outData.jobId = 123;
        outData.jobType = "start_mock";
        outData.jobPath = "/org/freedesktop/systemd1/job/mock";
        return 0;
    }));

    // Simulate failure for FragmentPath property
    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    _, // Any destination
                    StrEq("/org/freedesktop/systemd1/unit/mock"),
                    StrEq("org.freedesktop.systemd1.Unit"),
                    StrEq("FragmentPath"),
                    nullptr,
                    _
                ))
    .InSequence(s)
    .WillOnce(Return(-5)); // Simulate failure

    EXPECT_CALL(*mockSystemWrapper, strerror(5)) // Expect strerror(5)
    .InSequence(s)
    .WillOnce(Return(mock_error_str));

    // The other property calls should still succeed or be mocked
    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    _, _, _, StrEq("SourcePath"), nullptr, _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("/lib/systemd/system/mock.service")), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    _, _, _, StrEq("User"), nullptr, _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("root")), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_get_property_string(
                    mock_bus,
                    _, _, _, StrEq("UnitFileState"), nullptr, _
                ))
    .InSequence(s)
    .WillOnce(DoAll(SetArgPointee<6>(strdup("enabled")), Return(0)));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_exit_container(mock_reply))
    .InSequence(s)
    .WillOnce(Return(0));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_enter_container(mock_reply, SD_BUS_TYPE_STRUCT, StrEq("ssssssouso")))
    .InSequence(s)
    .WillOnce(Return(0)); // No more units

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_exit_container(mock_reply))
    .InSequence(s)
    .WillOnce(Return(0));

    EXPECT_CALL(*mockDBusWrapper, sd_bus_message_unref(mock_reply))
    .InSequence(s)
    .WillOnce(Return(mock_reply));
    EXPECT_CALL(*mockDBusWrapper, sd_bus_unref(mock_bus))
    .InSequence(s)
    .WillOnce(Return(mock_bus));

    nlohmann::json result = provider->collect();

    ASSERT_TRUE(result.is_array());
    ASSERT_EQ(result.size(), 1u); // One unit should still be present

    const auto& unit = result[0];
    EXPECT_EQ(unit["fragmentPath"], ""); // Should be empty due to failure
    EXPECT_EQ(unit["sourcePath"], "/lib/systemd/system/mock.service");
    EXPECT_EQ(unit["user"], "root");
    EXPECT_EQ(unit["unitFileState"], "enabled");

    free(mock_error_str);
}
