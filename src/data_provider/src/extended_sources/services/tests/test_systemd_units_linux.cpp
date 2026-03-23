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
#include "idbus_wrapper.hpp"
#include "systemd_units_linux.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::SetArgReferee;

class MockDBusWrapper : public IDBusWrapper
{
    public:
        MOCK_METHOD(void, error_init, (DBusError*), (override));
        MOCK_METHOD(bool, error_is_set, (const DBusError*), (override));
        MOCK_METHOD(void, error_free, (DBusError*), (override));
        MOCK_METHOD(DBusConnection*, bus_get, (DBusBusType, DBusError*), (override));
        MOCK_METHOD(DBusMessage*, message_new_method_call, (const std::string&, const std::string&, const std::string&, const std::string&), (override));
        MOCK_METHOD(DBusMessage*, connection_send_with_reply_and_block, (DBusConnection*, DBusMessage*, int, DBusError*), (override));
        MOCK_METHOD(void, message_unref, (DBusMessage*), (override));
        MOCK_METHOD(bool, message_iter_init, (DBusMessage*, DBusMessageIter*), (override));
        MOCK_METHOD(int, message_iter_get_arg_type, (DBusMessageIter*), (override));
        MOCK_METHOD(void, message_iter_recurse, (DBusMessageIter*, DBusMessageIter*), (override));
        MOCK_METHOD(void, message_iter_get_basic, (DBusMessageIter*, void*), (override));
        MOCK_METHOD(bool, message_iter_next, (DBusMessageIter*), (override));
        MOCK_METHOD(bool, getProperty, (DBusConnection*, const std::string&, const std::string&, const std::string&, const std::string&, std::string&), (override));
};

const char*     servicePath = "/org/freedesktop/systemd1/unit/test_service";
const char*     devicePath = "/org/freedesktop/systemd1/unit/test_device";
const char*     secondServicePath = "/org/freedesktop/systemd1/unit/second_test_service";

void SetUpTestMock(std::shared_ptr<MockDBusWrapper>& mockDbusWrapper)
{
    DBusConnection* conn  = reinterpret_cast<DBusConnection*>(0x1);
    DBusMessage*    msg   = reinterpret_cast<DBusMessage*>(0x2);
    DBusMessage*    reply = reinterpret_cast<DBusMessage*>(0x3);

    // Initialization
    EXPECT_CALL(*mockDbusWrapper, error_init(_));

    EXPECT_CALL(*mockDbusWrapper, bus_get(DBUS_BUS_SYSTEM, _))
    .WillOnce(DoAll(
                  Invoke([](DBusBusType, DBusError * err)
    {
        *err = {};
    }),
    Return(conn)
              ));

    EXPECT_CALL(*mockDbusWrapper, error_is_set(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(*mockDbusWrapper,
                message_new_method_call("org.freedesktop.systemd1",
                                        "/org/freedesktop/systemd1",
                                        "org.freedesktop.systemd1.Manager",
                                        "ListUnits"))
    .WillOnce(Return(msg));

    EXPECT_CALL(*mockDbusWrapper,
                connection_send_with_reply_and_block(conn, msg, -1, _))
    .WillOnce(DoAll(
                  Invoke([](DBusConnection*, DBusMessage*, int, DBusError * err)
    {
        *err = {};
    }),
    Return(reply)
              ));

    EXPECT_CALL(*mockDbusWrapper, message_iter_init(reply, _))
    .WillOnce(DoAll(
    Invoke([](DBusMessage*, DBusMessageIter*) {}),
    Return(true)
              ));

    EXPECT_CALL(*mockDbusWrapper, message_iter_get_arg_type(_))
    .WillOnce(Return(DBUS_TYPE_ARRAY)) // Called at initialization
    .WillOnce(Return(DBUS_TYPE_STRUCT)) // First unit
    .WillOnce(Return(DBUS_TYPE_STRUCT)) // Second unit
    .WillOnce(Return(DBUS_TYPE_STRUCT)) // Third unit
    .WillOnce(Return(DBUS_TYPE_INVALID)); // End of unit

    EXPECT_CALL(*mockDbusWrapper, message_iter_recurse(_, _))
    .WillRepeatedly(DoAll(
    Invoke([](DBusMessageIter*, DBusMessageIter*) {}),
    Return()
                    ));

    EXPECT_CALL(*mockDbusWrapper, message_iter_get_basic(_, _))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "test_service.service";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "Test service description";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "loaded";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "active";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "running";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = servicePath;
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(uint32_t*)v = 0;
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "/";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "test_device.device";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "Test device description";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "loaded";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "active";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "running";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = devicePath;
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(uint32_t*)v = 1;
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "/";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "second.test.service.service";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "Another test service description";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "loaded";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "active";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "running";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = secondServicePath;
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(uint32_t*)v = 2;
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "";
    }))
    .WillOnce(Invoke([](DBusMessageIter*, void* v)
    {
        *(const char**)v = "/";
    }));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            servicePath,
                            "org.freedesktop.systemd1.Unit",
                            "FragmentPath",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("/lib/systemd/system/test_service.service")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            servicePath,
                            "org.freedesktop.systemd1.Unit",
                            "SourcePath",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("/etc/systemd/system/test_service.service")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            servicePath,
                            "org.freedesktop.systemd1.Service",
                            "User",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("root")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            servicePath,
                            "org.freedesktop.systemd1.Unit",
                            "UnitFileState",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("enabled")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            devicePath,
                            "org.freedesktop.systemd1.Unit",
                            "FragmentPath",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("/lib/systemd/system/test_device.device")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            devicePath,
                            "org.freedesktop.systemd1.Unit",
                            "SourcePath",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("/etc/systemd/system/test_device.device")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            devicePath,
                            "org.freedesktop.systemd1.Service",
                            "User",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("root")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            devicePath,
                            "org.freedesktop.systemd1.Unit",
                            "UnitFileState",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("enabled")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            secondServicePath,
                            "org.freedesktop.systemd1.Unit",
                            "FragmentPath",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("/lib/systemd/system/second.test.service.service")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            secondServicePath,
                            "org.freedesktop.systemd1.Unit",
                            "SourcePath",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("/etc/systemd/system/second.test.service.service")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            secondServicePath,
                            "org.freedesktop.systemd1.Service",
                            "User",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("root")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper,
                getProperty(conn,
                            "org.freedesktop.systemd1",
                            secondServicePath,
                            "org.freedesktop.systemd1.Unit",
                            "UnitFileState",
                            _))
    .WillOnce(DoAll(SetArgReferee<5>(std::string("enabled")), Return(true)));

    EXPECT_CALL(*mockDbusWrapper, message_iter_next(_))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true)) // End of first unit
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true)) // End of second unit;
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(true))
    .WillOnce(Return(false)); // End of last unit;

    EXPECT_CALL(*mockDbusWrapper, message_unref(_))
    .WillRepeatedly(Invoke([](auto)
    {
        // do nothing
    }));

    EXPECT_CALL(*mockDbusWrapper, error_free(_))
    .WillRepeatedly(Invoke([](auto)
    {
        // do nothing
    }));
}

TEST(SystemdUnitsProviderTest, CollectsUnitsSuccessfully)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();

    SetUpTestMock(mockDbusWrapper);

    SystemdUnitsProvider provider(mockDbusWrapper);

    nlohmann::json unitsJson = provider.collect();
    ASSERT_EQ(unitsJson.size(), 2u);

    EXPECT_EQ(unitsJson[0]["id"],             "test_service");
    EXPECT_EQ(unitsJson[0]["description"],    "Test service description");
    EXPECT_EQ(unitsJson[0]["load_state"],     "loaded");
    EXPECT_EQ(unitsJson[0]["active_state"],   "active");
    EXPECT_EQ(unitsJson[0]["sub_state"],      "running");
    EXPECT_EQ(unitsJson[0]["following"],      "");
    EXPECT_EQ(unitsJson[0]["object_path"],    servicePath);
    EXPECT_EQ(unitsJson[0]["job_id"],         0u);
    EXPECT_EQ(unitsJson[0]["job_type"],       "");
    EXPECT_EQ(unitsJson[0]["job_path"],       "/");
    EXPECT_EQ(unitsJson[0]["fragment_path"],  "/lib/systemd/system/test_service.service");
    EXPECT_EQ(unitsJson[0]["source_path"],    "/etc/systemd/system/test_service.service");
    EXPECT_EQ(unitsJson[0]["user"],           "root");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "enabled");

    EXPECT_EQ(unitsJson[1]["id"],             "second.test.service");
    EXPECT_EQ(unitsJson[1]["description"],    "Another test service description");
    EXPECT_EQ(unitsJson[1]["load_state"],     "loaded");
    EXPECT_EQ(unitsJson[1]["active_state"],   "active");
    EXPECT_EQ(unitsJson[1]["sub_state"],      "running");
    EXPECT_EQ(unitsJson[1]["following"],      "");
    EXPECT_EQ(unitsJson[1]["object_path"],    secondServicePath);
    EXPECT_EQ(unitsJson[1]["job_id"],         2u);
    EXPECT_EQ(unitsJson[1]["job_type"],       "");
    EXPECT_EQ(unitsJson[1]["job_path"],       "/");
    EXPECT_EQ(unitsJson[1]["fragment_path"],  "/lib/systemd/system/second.test.service.service");
    EXPECT_EQ(unitsJson[1]["source_path"],    "/etc/systemd/system/second.test.service.service");
    EXPECT_EQ(unitsJson[1]["user"],           "root");
    EXPECT_EQ(unitsJson[1]["unit_file_state"], "enabled");
}

TEST(SystemdUnitsProviderTest, FailsWhenBusConnectionFails)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper);

    EXPECT_CALL(*mockDbusWrapper, error_init(_));
    EXPECT_CALL(*mockDbusWrapper, bus_get(DBUS_BUS_SYSTEM, _))
    .WillOnce(DoAll(
                  Invoke([](DBusBusType, DBusError * err)
    {
        *err = {};
    }),
    Return(nullptr)
              ));

    EXPECT_CALL(*mockDbusWrapper, error_free(_))
    .WillRepeatedly(Invoke([](auto)
    {
        // do nothing
    }));
    auto result = provider.collect();
    EXPECT_TRUE(result.empty());
}

TEST(SystemdUnitsProviderTest, FailsWhenMessageCreationFails)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper);

    DBusConnection* conn = reinterpret_cast<DBusConnection*>(0x1);

    EXPECT_CALL(*mockDbusWrapper, error_init(_));
    EXPECT_CALL(*mockDbusWrapper, error_free(_))
    .WillRepeatedly(Invoke([](auto)
    {
        // do nothing
    }));
    EXPECT_CALL(*mockDbusWrapper, bus_get(DBUS_BUS_SYSTEM, _))
    .WillOnce(DoAll(
                  Invoke([](DBusBusType, DBusError * err)
    {
        *err = {};
    }),
    Return(conn)
              ));
    EXPECT_CALL(*mockDbusWrapper, error_is_set(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, _))
    .WillOnce(Return(nullptr));

    auto result = provider.collect();
    EXPECT_TRUE(result.empty());
}

TEST(SystemdUnitsProviderTest, FailsWhenReplyHasNoArguments)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper);

    DBusConnection* conn = reinterpret_cast<DBusConnection*>(0x1);
    DBusMessage* msg = reinterpret_cast<DBusMessage*>(0x2);
    DBusMessage* reply = reinterpret_cast<DBusMessage*>(0x3);

    EXPECT_CALL(*mockDbusWrapper, error_init(_));
    EXPECT_CALL(*mockDbusWrapper, error_free(_));
    EXPECT_CALL(*mockDbusWrapper, bus_get(DBUS_BUS_SYSTEM, _))
    .WillOnce(Return(conn));
    EXPECT_CALL(*mockDbusWrapper, error_is_set(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, _))
    .WillOnce(Return(msg));
    EXPECT_CALL(*mockDbusWrapper, connection_send_with_reply_and_block(_, _, _, _))
    .WillOnce(Return(reply));
    EXPECT_CALL(*mockDbusWrapper, message_unref(msg));
    EXPECT_CALL(*mockDbusWrapper, message_iter_init(reply, _))
    .WillOnce(Return(false));
    EXPECT_CALL(*mockDbusWrapper, message_unref(reply));

    auto result = provider.collect();
    EXPECT_TRUE(result.empty());
}

TEST(SystemdUnitsProviderTest, FailsWhenReplyIsNotArray)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper);

    DBusConnection* conn = reinterpret_cast<DBusConnection*>(0x1);
    DBusMessage* msg = reinterpret_cast<DBusMessage*>(0x2);
    DBusMessage* reply = reinterpret_cast<DBusMessage*>(0x3);

    EXPECT_CALL(*mockDbusWrapper, error_init(_));
    EXPECT_CALL(*mockDbusWrapper, error_free(_));
    EXPECT_CALL(*mockDbusWrapper, bus_get(DBUS_BUS_SYSTEM, _))
    .WillOnce(Return(conn));
    EXPECT_CALL(*mockDbusWrapper, error_is_set(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, _))
    .WillOnce(Return(msg));
    EXPECT_CALL(*mockDbusWrapper, connection_send_with_reply_and_block(_, _, _, _))
    .WillOnce(Return(reply));
    EXPECT_CALL(*mockDbusWrapper, message_unref(msg));
    EXPECT_CALL(*mockDbusWrapper, message_iter_init(reply, _))
    .WillOnce(Return(true));
    EXPECT_CALL(*mockDbusWrapper, message_iter_get_arg_type(_))
    .WillOnce(Return(DBUS_TYPE_STRING));
    EXPECT_CALL(*mockDbusWrapper, message_unref(reply));

    auto result = provider.collect();
    EXPECT_TRUE(result.empty());
}
