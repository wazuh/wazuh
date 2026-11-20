/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
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
        MOCK_METHOD(DBusConnection*, bus_get_private, (DBusBusType, DBusError*), (override));
        MOCK_METHOD(void, connection_close, (DBusConnection*), (override));
        MOCK_METHOD(void, connection_unref, (DBusConnection*), (override));
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

// ListUnitFiles answers with an empty list: only the loaded units are reported.
void ExpectEmptyUnitFiles(std::shared_ptr<MockDBusWrapper>& mockDbusWrapper, DBusConnection* conn)
{
    DBusMessage* filesMsg   = reinterpret_cast<DBusMessage*>(0x4);
    DBusMessage* filesReply = reinterpret_cast<DBusMessage*>(0x5);

    EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, "ListUnitFiles")).WillOnce(Return(filesMsg));
    EXPECT_CALL(*mockDbusWrapper, connection_send_with_reply_and_block(conn, filesMsg, -1, _)).WillOnce(Return(filesReply));
    EXPECT_CALL(*mockDbusWrapper, message_iter_init(filesReply, _)).WillOnce(Return(true));
}

void SetUpTestMock(std::shared_ptr<MockDBusWrapper>& mockDbusWrapper)
{
    DBusConnection* conn  = reinterpret_cast<DBusConnection*>(0x1);
    DBusMessage*    msg   = reinterpret_cast<DBusMessage*>(0x2);
    DBusMessage*    reply = reinterpret_cast<DBusMessage*>(0x3);

    // Initialization, once for ListUnits and once for ListUnitFiles.
    EXPECT_CALL(*mockDbusWrapper, error_init(_)).Times(2);
    ExpectEmptyUnitFiles(mockDbusWrapper, conn);

    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _))
    .WillOnce(DoAll(
                  Invoke([](DBusBusType, DBusError * err)
    {
        *err = {};
    }),
    Return(conn)
              ));

    // The connection is acquired privately, so the provider owns it and must close and
    // release it exactly once, on this path as on every other.
    EXPECT_CALL(*mockDbusWrapper, connection_close(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(conn)).Times(1);

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
    .WillOnce(Return(DBUS_TYPE_INVALID)) // End of unit
    .WillOnce(Return(DBUS_TYPE_ARRAY))   // ListUnitFiles reply
    .WillOnce(Return(DBUS_TYPE_INVALID)); // No unit files

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

    // Non-service units are discarded before their properties are queried.
    EXPECT_CALL(*mockDbusWrapper, getProperty(_, _, devicePath, _, _, _)).Times(0);

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

void SetUpSingleUnitMock(std::shared_ptr<MockDBusWrapper>& mockDbusWrapper,
                         const std::string& loadState,
                         const std::string& activeState,
                         const std::string& subState,
                         bool expectProperties)
{
    DBusConnection* conn  = reinterpret_cast<DBusConnection*>(0x1);
    DBusMessage*    msg   = reinterpret_cast<DBusMessage*>(0x2);
    DBusMessage*    reply = reinterpret_cast<DBusMessage*>(0x3);

    EXPECT_CALL(*mockDbusWrapper, error_init(_)).Times(2);
    ExpectEmptyUnitFiles(mockDbusWrapper, conn);
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _)).WillOnce(Return(conn));
    EXPECT_CALL(*mockDbusWrapper, connection_close(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, error_is_set(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, "ListUnits")).WillOnce(Return(msg));
    EXPECT_CALL(*mockDbusWrapper, connection_send_with_reply_and_block(conn, msg, -1, _)).WillOnce(Return(reply));
    EXPECT_CALL(*mockDbusWrapper, message_iter_init(reply, _)).WillOnce(Return(true));

    EXPECT_CALL(*mockDbusWrapper, message_iter_get_arg_type(_))
    .WillOnce(Return(DBUS_TYPE_ARRAY))
    .WillOnce(Return(DBUS_TYPE_STRUCT))
    .WillOnce(Return(DBUS_TYPE_INVALID))
    .WillOnce(Return(DBUS_TYPE_ARRAY))
    .WillOnce(Return(DBUS_TYPE_INVALID));

    EXPECT_CALL(*mockDbusWrapper, message_iter_recurse(_, _)).WillRepeatedly(Return());

    // ssssssouso: the job id (index 7) is the only non-string field.
    auto fields = std::make_shared<std::vector<std::string>>(std::vector<std::string>
    {
        "apt-daily.service", "apt-daily.service", loadState, activeState, subState, "", servicePath, "", "", "/"
    });
    auto index = std::make_shared<size_t>(0);

    EXPECT_CALL(*mockDbusWrapper, message_iter_get_basic(_, _))
    .Times(10)
    .WillRepeatedly(Invoke([fields, index](DBusMessageIter*, void* v)
    {
        const auto i = (*index)++;

        if (i == 7)
        {
            *(uint32_t*)v = 0;
        }
        else
        {
            *(const char**)v = (*fields)[i].c_str();
        }
    }));

    if (expectProperties)
    {
        const std::vector<std::tuple<std::string, std::string, std::string>> properties
        {
            {"org.freedesktop.systemd1.Unit", "FragmentPath", "/lib/systemd/system/apt-daily.service"},
            {"org.freedesktop.systemd1.Unit", "SourcePath", "/etc/systemd/system/apt-daily.service"},
            {"org.freedesktop.systemd1.Service", "User", "root"},
            {"org.freedesktop.systemd1.Unit", "UnitFileState", "enabled"}
        };

        for (const auto& [interface, name, value] : properties)
        {
            EXPECT_CALL(*mockDbusWrapper, getProperty(conn, "org.freedesktop.systemd1", servicePath, interface, name, _))
            .WillOnce(DoAll(SetArgReferee<5>(value), Return(true)));
        }
    }
    else
    {
        EXPECT_CALL(*mockDbusWrapper, getProperty(_, _, _, _, _, _)).Times(0);
    }

    EXPECT_CALL(*mockDbusWrapper, message_iter_next(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockDbusWrapper, message_unref(_)).WillRepeatedly(Return());
    EXPECT_CALL(*mockDbusWrapper, error_free(_)).WillRepeatedly(Return());
}

TEST(SystemdUnitsProviderTest, SkipsInactiveNotFoundUnits)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();

    SetUpSingleUnitMock(mockDbusWrapper, "not-found", "inactive", "dead", false);

    SystemdUnitsProvider provider(mockDbusWrapper);

    EXPECT_TRUE(provider.collect().empty());
}

// load_state, active_state, sub_state of units that must still be reported.
class SystemdUnitsKeptStatesTest : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::string>>
{
};

TEST_P(SystemdUnitsKeptStatesTest, ReportsUnitWithItsProperties)
{
    const auto& [loadState, activeState, subState] = GetParam();
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();

    SetUpSingleUnitMock(mockDbusWrapper, loadState, activeState, subState, true);

    SystemdUnitsProvider provider(mockDbusWrapper);

    nlohmann::json unitsJson = provider.collect();
    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],              "apt-daily");
    EXPECT_EQ(unitsJson[0]["load_state"],      loadState);
    EXPECT_EQ(unitsJson[0]["active_state"],    activeState);
    EXPECT_EQ(unitsJson[0]["sub_state"],       subState);
    EXPECT_EQ(unitsJson[0]["fragment_path"],   "/lib/systemd/system/apt-daily.service");
    EXPECT_EQ(unitsJson[0]["source_path"],     "/etc/systemd/system/apt-daily.service");
    EXPECT_EQ(unitsJson[0]["user"],            "root");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "enabled");
}

INSTANTIATE_TEST_SUITE_P(
    SystemdUnitsProviderTest,
    SystemdUnitsKeptStatesTest,
    ::testing::Values(
        // Installed but stopped services.
        std::make_tuple("loaded", "inactive", "dead"),
        std::make_tuple("masked", "inactive", "dead"),
        // Unit file removed while the process is still around.
        std::make_tuple("not-found", "active", "running"),
        std::make_tuple("not-found", "failed", "failed"),
        std::make_tuple("not-found", "activating", "start"),
        std::make_tuple("not-found", "deactivating", "stop-sigterm")));

TEST(SystemdUnitsProviderTest, FailsWhenBusConnectionFails)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper);

    EXPECT_CALL(*mockDbusWrapper, error_init(_));
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _))
    .WillOnce(DoAll(
                  Invoke([](DBusBusType, DBusError * err)
    {
        *err = {};
    }),
    Return(nullptr)
              ));

    // Nothing was acquired, so nothing may be closed or released.
    EXPECT_CALL(*mockDbusWrapper, connection_close(_)).Times(0);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(_)).Times(0);

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
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _))
    .WillOnce(DoAll(
                  Invoke([](DBusBusType, DBusError * err)
    {
        *err = {};
    }),
    Return(conn)
              ));

    // The connection is acquired privately, so the provider owns it and must close and
    // release it exactly once, on this path as on every other.
    EXPECT_CALL(*mockDbusWrapper, connection_close(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(conn)).Times(1);
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
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _))
    .WillOnce(Return(conn));

    // The connection is acquired privately, so the provider owns it and must close and
    // release it exactly once, on this path as on every other.
    EXPECT_CALL(*mockDbusWrapper, connection_close(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(conn)).Times(1);
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
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _))
    .WillOnce(Return(conn));

    // The connection is acquired privately, so the provider owns it and must close and
    // release it exactly once, on this path as on every other.
    EXPECT_CALL(*mockDbusWrapper, connection_close(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(conn)).Times(1);
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

// One ListUnits row: a loaded, running service whose properties all resolve.
struct LoadedUnit
{
    std::string name;
    std::string description {"desc"};
    std::string activeState {"active"};
    std::string subState {"running"};
    std::string fragmentPath {"loaded-value"};
    std::string sourcePath {"loaded-value"};
    std::string user {"loaded-value"};
    std::string unitFileState {"loaded-value"};
};

// One ListUnitFiles row.
struct UnitFileEntry
{
    std::string path;
    std::string state;
};

enum class UnitFilesOutcome
{
    Reply,
    NoMessage,
    NoReply,
    ErrorReply,
    NotArray
};

void SetUpUnitFilesMock(std::shared_ptr<MockDBusWrapper>& mockDbusWrapper,
                        const std::vector<LoadedUnit>& loadedUnits,
                        const std::vector<UnitFileEntry>& unitFiles,
                        UnitFilesOutcome outcome = UnitFilesOutcome::Reply)
{
    DBusConnection* conn       = reinterpret_cast<DBusConnection*>(0x1);
    DBusMessage*    unitsMsg   = reinterpret_cast<DBusMessage*>(0x2);
    DBusMessage*    unitsReply = reinterpret_cast<DBusMessage*>(0x3);
    DBusMessage*    filesMsg   = reinterpret_cast<DBusMessage*>(0x4);
    DBusMessage*    filesReply = reinterpret_cast<DBusMessage*>(0x5);

    EXPECT_CALL(*mockDbusWrapper, error_init(_)).Times(2);
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _)).WillOnce(Return(conn));
    EXPECT_CALL(*mockDbusWrapper, connection_close(conn)).Times(1);
    EXPECT_CALL(*mockDbusWrapper, connection_unref(conn)).Times(1);
    // Checked after connecting and after each reply; only the ListUnitFiles reply can carry an error.
    EXPECT_CALL(*mockDbusWrapper, error_is_set(_))
    .WillOnce(Return(false))
    .WillOnce(Return(false))
    .WillRepeatedly(Return(outcome == UnitFilesOutcome::ErrorReply));

    EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, "ListUnits")).WillOnce(Return(unitsMsg));
    EXPECT_CALL(*mockDbusWrapper, connection_send_with_reply_and_block(conn, unitsMsg, -1, _)).WillOnce(Return(unitsReply));
    EXPECT_CALL(*mockDbusWrapper, message_iter_init(unitsReply, _)).WillOnce(Return(true));

    // Argument types, in call order: ListUnits array and rows, then ListUnitFiles.
    std::vector<int> argTypes {DBUS_TYPE_ARRAY};
    argTypes.insert(argTypes.end(), loadedUnits.size(), DBUS_TYPE_STRUCT);
    argTypes.push_back(DBUS_TYPE_INVALID);

    // Values returned by message_iter_get_basic, in call order; nullopt marks the job id.
    auto values = std::make_shared<std::vector<std::optional<std::string>>>();

    for (const auto& unit : loadedUnits)
    {
        values->insert(values->end(), {unit.name, unit.description, "loaded", unit.activeState, unit.subState, "",
                                       SystemdUnitsProvider::unitObjectPath(unit.name), std::nullopt, "", "/"
                                      });
    }

    if (outcome == UnitFilesOutcome::NoMessage)
    {
        EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, "ListUnitFiles")).WillOnce(Return(nullptr));
    }
    else
    {
        EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, "ListUnitFiles")).WillOnce(Return(filesMsg));
        EXPECT_CALL(*mockDbusWrapper, connection_send_with_reply_and_block(conn, filesMsg, -1, _))
        .WillOnce(Return(outcome == UnitFilesOutcome::NoReply ? nullptr : filesReply));

        if (outcome == UnitFilesOutcome::NoReply || outcome == UnitFilesOutcome::ErrorReply)
        {
            // The reply is not read.
        }
        else
        {
            EXPECT_CALL(*mockDbusWrapper, message_iter_init(filesReply, _)).WillOnce(Return(true));
        }

        if (outcome == UnitFilesOutcome::NotArray)
        {
            argTypes.push_back(DBUS_TYPE_STRING);
        }
        else if (outcome == UnitFilesOutcome::Reply)
        {
            argTypes.push_back(DBUS_TYPE_ARRAY);
            argTypes.insert(argTypes.end(), unitFiles.size(), DBUS_TYPE_STRUCT);
            argTypes.push_back(DBUS_TYPE_INVALID);

            for (const auto& file : unitFiles)
            {
                values->insert(values->end(), {file.path, file.state});
            }
        }
    }

    auto typeIndex = std::make_shared<size_t>(0);
    EXPECT_CALL(*mockDbusWrapper, message_iter_get_arg_type(_))
    .Times(static_cast<int>(argTypes.size()))
    .WillRepeatedly(Invoke([argTypes, typeIndex](DBusMessageIter*)
    {
        return argTypes[(*typeIndex)++];
    }));

    auto valueIndex = std::make_shared<size_t>(0);
    EXPECT_CALL(*mockDbusWrapper, message_iter_get_basic(_, _))
    .Times(static_cast<int>(values->size()))
    .WillRepeatedly(Invoke([values, valueIndex](DBusMessageIter*, void* v)
    {
        const auto& value = (*values)[(*valueIndex)++];

        if (value)
        {
            *(const char**)v = value->c_str();
        }
        else
        {
            *(uint32_t*)v = 0;
        }
    }));

    EXPECT_CALL(*mockDbusWrapper, getProperty(_, _, _, _, _, _))
    .WillRepeatedly(Invoke([loadedUnits](DBusConnection*, const std::string&, const std::string & objectPath,
                                         const std::string&, const std::string & propertyName, std::string & value)
    {
        for (const auto& unit : loadedUnits)
        {
            if (SystemdUnitsProvider::unitObjectPath(unit.name) == objectPath)
            {
                const std::map<std::string, std::string> properties
                {
                    {"FragmentPath", unit.fragmentPath},
                    {"SourcePath", unit.sourcePath},
                    {"User", unit.user},
                    {"UnitFileState", unit.unitFileState}
                };
                value = properties.at(propertyName);
                return true;
            }
        }

        return false;
    }));

    EXPECT_CALL(*mockDbusWrapper, message_iter_recurse(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(*mockDbusWrapper, message_iter_next(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockDbusWrapper, message_unref(_)).WillRepeatedly(Return());
    EXPECT_CALL(*mockDbusWrapper, error_free(_)).WillRepeatedly(Return());
}

// Temporary directory removed at the end of the test.
class TempDir final
{
    public:
        TempDir()
            : m_path(std::filesystem::temp_directory_path() /
                     ("systemd_units_test_" + std::to_string(::getpid()) + "_" +
                      ::testing::UnitTest::GetInstance()->current_test_info()->name()))
        {
            std::filesystem::remove_all(m_path);
            std::filesystem::create_directories(m_path);
        }

        ~TempDir()
        {
            std::error_code ec;
            std::filesystem::remove_all(m_path, ec);
        }

        const std::filesystem::path& path() const
        {
            return m_path;
        }

    private:
        std::filesystem::path m_path;
};

TEST(SystemdUnitsProviderTest, ReportsUnloadedUnitFileAsStoppedService)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{"/nonexistent/ith-test.service", "disabled"}});

    SystemdUnitsProvider provider(mockDbusWrapper);
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],              "ith-test");
    // systemd falls back to the unit name when the file has no Description=.
    EXPECT_EQ(unitsJson[0]["description"],     "ith-test.service");
    EXPECT_EQ(unitsJson[0]["load_state"],      "not-loaded");
    EXPECT_EQ(unitsJson[0]["active_state"],    "inactive");
    EXPECT_EQ(unitsJson[0]["sub_state"],       "dead");
    EXPECT_EQ(unitsJson[0]["following"],       "");
    EXPECT_EQ(unitsJson[0]["object_path"],     "/org/freedesktop/systemd1/unit/ith_2dtest_2eservice");
    EXPECT_EQ(unitsJson[0]["job_id"],          0u);
    EXPECT_EQ(unitsJson[0]["job_type"],        "");
    EXPECT_EQ(unitsJson[0]["job_path"],        "/");
    EXPECT_EQ(unitsJson[0]["fragment_path"],   "/nonexistent/ith-test.service");
    EXPECT_EQ(unitsJson[0]["source_path"],     "");
    EXPECT_EQ(unitsJson[0]["user"],            "");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "disabled");
}

TEST(SystemdUnitsProviderTest, SkipsLoadedTemplateAliasAndNonServiceUnitFiles)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper,
    {{"cron.service"}},
    {
        {"/nonexistent/lib/cron.service", "enabled"},
        {"/nonexistent/lib/getty@.service", "static"},
        {"/nonexistent/etc/dbus-org.freedesktop.timesync1.service", "alias"},
        {"/nonexistent/lib/ssh.socket", "enabled"},
        {"/nonexistent/etc/packagekit.service", "static"},
        {"/nonexistent/lib/packagekit.service", "static"}
    });

    SystemdUnitsProvider provider(mockDbusWrapper);
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 2u);
    EXPECT_EQ(unitsJson[0]["id"],            "cron");
    EXPECT_EQ(unitsJson[0]["active_state"],  "active");
    EXPECT_EQ(unitsJson[0]["fragment_path"], "loaded-value");
    // systemd lists each name once; if one repeats, the first entry is kept.
    EXPECT_EQ(unitsJson[1]["id"],            "packagekit");
    EXPECT_EQ(unitsJson[1]["fragment_path"], "/nonexistent/etc/packagekit.service");
}

class SystemdUnitFilesFailureTest : public ::testing::TestWithParam<UnitFilesOutcome>
{
};

// Returning only the loaded units would report every unloaded unit as deleted, so the
// collection fails and the scan keeps the previous inventory.
TEST_P(SystemdUnitFilesFailureTest, ThrowsInsteadOfDroppingUnloadedUnits)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {{"cron.service"}}, {}, GetParam());

    SystemdUnitsProvider provider(mockDbusWrapper);

    EXPECT_THROW(provider.collect(), std::runtime_error);
}

INSTANTIATE_TEST_SUITE_P(
    SystemdUnitsProviderTest,
    SystemdUnitFilesFailureTest,
    ::testing::Values(UnitFilesOutcome::NoMessage,
                      UnitFilesOutcome::NoReply,
                      UnitFilesOutcome::ErrorReply,
                      UnitFilesOutcome::NotArray));

TEST(SystemdUnitsProviderTest, ReadsUnloadedUnitValuesFromUnitFile)
{
    TempDir dir;
    const auto unitPath = dir.path() / "legacy.service";
    std::ofstream(unitPath) << "[Unit]\nDescription=Legacy daemon\nSourcePath=/etc/init.d/legacy\n"
                            "[Service]\nUser=daemon\nExecStart=/bin/true\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{unitPath.string(), "generated"}});

    SystemdUnitsProvider provider(mockDbusWrapper);
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],              "legacy");
    EXPECT_EQ(unitsJson[0]["description"],     "Legacy daemon");
    EXPECT_EQ(unitsJson[0]["source_path"],     "/etc/init.d/legacy");
    EXPECT_EQ(unitsJson[0]["user"],            "daemon");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "generated");
}

TEST(SystemdUnitsProviderTest, KeepsMaskedUnitAndSkipsAliasSymlink)
{
    TempDir dir;
    const auto realPath = dir.path() / "real.service";
    const auto aliasPath = dir.path() / "other-name.service";
    const auto maskedPath = dir.path() / "masked.service";
    std::ofstream(realPath) << "[Unit]\nDescription=Real\n";
    std::filesystem::create_symlink(realPath, aliasPath);
    std::filesystem::create_symlink("/dev/null", maskedPath);

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    // Older systemd lists aliases with their target's state instead of "alias".
    SetUpUnitFilesMock(mockDbusWrapper, {},
    {
        {aliasPath.string(), "enabled"},
        {maskedPath.string(), "masked"}
    });

    SystemdUnitsProvider provider(mockDbusWrapper);
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],              "masked");
    EXPECT_EQ(unitsJson[0]["description"],     "masked.service");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "masked");
}

TEST(SystemdUnitsProviderTest, ParseUnitFileReadsOnlyExpectedKeys)
{
    std::istringstream input
    {
        "# comment\n"
        "; comment\n"
        "[Unit]\n"
        "  Description =  First  \n"
        "Description=Second description\n"
        "User=ignored-in-unit-section\n"
        "\n"
        "[Service]\n"
        "Description=ignored-in-service-section\n"
        "User=first\n"
        "User=svc-user\r\n"
        "NoSeparatorLine\n"
        "[Install]\n"
        "SourcePath=ignored-in-install-section\n"
    };

    const auto values = SystemdUnitsProvider::parseUnitFile(input);

    EXPECT_EQ(values.description, "Second description");
    EXPECT_EQ(values.user,        "svc-user");
    EXPECT_EQ(values.sourcePath,  "");
}

TEST(SystemdUnitsProviderTest, ParseUnitFileHandlesEmptyInput)
{
    std::istringstream input;
    const auto values = SystemdUnitsProvider::parseUnitFile(input);

    EXPECT_TRUE(values.description.empty());
    EXPECT_TRUE(values.user.empty());
    EXPECT_TRUE(values.sourcePath.empty());
}

TEST(SystemdUnitsProviderTest, UnitObjectPathMatchesSystemdEscaping)
{
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("cron.service"), "/org/freedesktop/systemd1/unit/cron_2eservice");
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("apt-news.service"), "/org/freedesktop/systemd1/unit/apt_2dnews_2eservice");
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("user@1000.service"), "/org/freedesktop/systemd1/unit/user_401000_2eservice");
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("b\\c.service"), "/org/freedesktop/systemd1/unit/b_5cc_2eservice");
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("Ab_c.service"), "/org/freedesktop/systemd1/unit/Ab_5fc_2eservice");
    // A leading digit is escaped, later ones are not.
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("1abc.service"), "/org/freedesktop/systemd1/unit/_31abc_2eservice");
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath("a1.service"), "/org/freedesktop/systemd1/unit/a1_2eservice");
    EXPECT_EQ(SystemdUnitsProvider::unitObjectPath(""), "/org/freedesktop/systemd1/unit/_");
}

TEST(SystemdUnitsProviderTest, ParseUnitFileJoinsContinuedLines)
{
    std::istringstream input
    {
        "[Unit]\n"
        "Description=First part \\\n"
        "# comment inside the value\n"
        "  second part\n"
        "[Service]\n"
        "User=svc\\\n"
    };

    const auto values = SystemdUnitsProvider::parseUnitFile(input);

    EXPECT_EQ(values.description, "First part  second part");
    EXPECT_EQ(values.user,        "svc");
}

TEST(SystemdUnitsProviderTest, ParseUnitFileKeepsPreviousValues)
{
    std::istringstream input {"[Service]\nUser=override\n"};
    const auto values = SystemdUnitsProvider::parseUnitFile(input, {"Base description", "base", "/etc/init.d/base"});

    EXPECT_EQ(values.description, "Base description");
    EXPECT_EQ(values.user,        "override");
    EXPECT_EQ(values.sourcePath,  "/etc/init.d/base");
}

TEST(SystemdUnitsProviderTest, AppliesDropInsInSystemdOrder)
{
    TempDir dir;
    const auto etc = dir.path() / "etc";
    const auto lib = dir.path() / "lib";
    std::filesystem::create_directories(etc / "web-app.service.d");
    std::filesystem::create_directories(lib / "web-app.service.d");
    std::filesystem::create_directories(lib / "web-.service.d");
    std::filesystem::create_directories(lib / "service.d");

    const auto unitPath = lib / "web-app.service";
    std::ofstream(unitPath) << "[Unit]\nDescription=Base\n[Service]\nUser=base\n";
    // Same name in a higher-priority directory hides the lower one.
    std::ofstream(lib / "web-app.service.d" / "10-user.conf") << "[Service]\nUser=hidden\n";
    std::ofstream(etc / "web-app.service.d" / "10-user.conf") << "[Service]\nUser=admin\n";
    // Sorted by file name across directories: 20 (prefix) is applied after 10.
    std::ofstream(lib / "web-.service.d" / "20-desc.conf") << "[Unit]\nDescription=From prefix drop-in\n";
    // Applies to every service, and sorts first.
    std::ofstream(lib / "service.d" / "05-all.conf") << "[Unit]\nDescription=From service.d\n";
    // Not a .conf file.
    std::ofstream(etc / "web-app.service.d" / "99-ignored.txt") << "[Service]\nUser=ignored\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{unitPath.string(), "disabled"}});

    SystemdUnitsProvider provider(mockDbusWrapper, {etc.string(), lib.string()});
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["description"], "From prefix drop-in");
    EXPECT_EQ(unitsJson[0]["user"],        "admin");
}

TEST(SystemdUnitsProviderTest, DoesNotBlockOnFifoUnitFile)
{
    TempDir dir;
    const auto fifoPath = dir.path() / "fifo.service";
    ASSERT_EQ(::mkfifo(fifoPath.c_str(), 0600), 0);

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{fifoPath.string(), "static"}});

    SystemdUnitsProvider provider(mockDbusWrapper, {});
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["description"], "fifo.service");
}

// A stopped unit must produce the same row whether systemd has it loaded or not; any
// difference would be reported as a change each time systemd loads or unloads it.
TEST(SystemdUnitsProviderTest, LoadedStoppedAndUnloadedUnitGiveSameRow)
{
    TempDir dir;
    std::filesystem::create_directories(dir.path() / "app.service.d");
    const auto unitPath = dir.path() / "app.service";
    std::ofstream(unitPath) << "[Unit]\nDescription=App daemon\n[Service]\nUser=app\nExecStart=/bin/true\n";
    std::ofstream(dir.path() / "app.service.d" / "override.conf") << "[Service]\nUser=override\n";

    LoadedUnit loaded {"app.service"};
    loaded.description = "App daemon";
    loaded.activeState = "inactive";
    loaded.subState = "dead";
    loaded.fragmentPath = unitPath.string();
    loaded.sourcePath = "";
    loaded.user = "override";
    loaded.unitFileState = "disabled";

    auto loadedMock = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(loadedMock, {loaded}, {{unitPath.string(), "disabled"}});
    auto loadedRows = SystemdUnitsProvider(loadedMock, {dir.path().string()}).collect();

    auto unloadedMock = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(unloadedMock, {}, {{unitPath.string(), "disabled"}});
    auto unloadedRows = SystemdUnitsProvider(unloadedMock, {dir.path().string()}).collect();

    ASSERT_EQ(loadedRows.size(), 1u);
    ASSERT_EQ(unloadedRows.size(), 1u);

    // load_state is not part of the inventory row.
    loadedRows[0].erase("load_state");
    unloadedRows[0].erase("load_state");
    EXPECT_EQ(loadedRows[0], unloadedRows[0]);
}
