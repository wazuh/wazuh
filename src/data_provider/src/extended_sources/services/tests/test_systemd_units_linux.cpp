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
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fcntl.h>
#include <future>
#include <thread>
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

// Settings that do not depend on the host: no drop-in directories unless given, systemd
// running unless the runtime directory says otherwise, and a failure counter of its own.
SystemdUnitsSettings TestSettings(std::vector<std::string> unitSearchPaths = {}, std::string runtimeDirectory = "/")
{
    return {std::move(unitSearchPaths), std::move(runtimeDirectory), std::make_shared<std::atomic<unsigned int>>(0)};
}

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

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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
    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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
    // Reporting no units would report every service as deleted.
    EXPECT_THROW(provider.collect(), std::runtime_error);
}

TEST(SystemdUnitsProviderTest, FailsWhenMessageCreationFails)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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

    // Reporting no units would report every service as deleted.
    EXPECT_THROW(provider.collect(), std::runtime_error);
}

TEST(SystemdUnitsProviderTest, FailsWhenReplyHasNoArguments)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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

    // Reporting no units would report every service as deleted.
    EXPECT_THROW(provider.collect(), std::runtime_error);
}

TEST(SystemdUnitsProviderTest, FailsWhenReplyIsNotArray)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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

    // Reporting no units would report every service as deleted.
    EXPECT_THROW(provider.collect(), std::runtime_error);
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
                        UnitFilesOutcome outcome = UnitFilesOutcome::Reply,
                        const std::string& systemdVersion = "255.4-1ubuntu8")
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
    .WillRepeatedly(Invoke([loadedUnits, systemdVersion](DBusConnection*, const std::string&, const std::string & objectPath,
                                                         const std::string&, const std::string & propertyName, std::string & value)
    {
        if (objectPath == "/org/freedesktop/systemd1" && propertyName == "Version")
        {
            value = systemdVersion;
            return !value.empty();
        }

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
    TempDir dir;
    const auto unitPath = dir.path() / "ith-test.service";
    std::ofstream(unitPath) << "[Service]\nExecStart=/usr/bin/sleep infinity\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{unitPath.string(), "disabled"}});

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],              "ith-test");
    // systemd falls back to the unit name when the file has no Description=.
    EXPECT_EQ(unitsJson[0]["description"],     "ith-test.service");
    EXPECT_EQ(unitsJson[0]["load_state"],      "");
    EXPECT_EQ(unitsJson[0]["active_state"],    "inactive");
    EXPECT_EQ(unitsJson[0]["sub_state"],       "dead");
    EXPECT_EQ(unitsJson[0]["following"],       "");
    EXPECT_EQ(unitsJson[0]["object_path"],     "/org/freedesktop/systemd1/unit/ith_2dtest_2eservice");
    EXPECT_EQ(unitsJson[0]["job_id"],          0u);
    EXPECT_EQ(unitsJson[0]["job_type"],        "");
    EXPECT_EQ(unitsJson[0]["job_path"],        "/");
    EXPECT_EQ(unitsJson[0]["fragment_path"],   unitPath.string());
    EXPECT_EQ(unitsJson[0]["source_path"],     "");
    EXPECT_EQ(unitsJson[0]["user"],            "");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "disabled");
}

TEST(SystemdUnitsProviderTest, SkipsLoadedTemplateAliasAndNonServiceUnitFiles)
{
    TempDir dir;
    std::filesystem::create_directories(dir.path() / "etc");
    std::filesystem::create_directories(dir.path() / "lib");
    const auto etcUnit = dir.path() / "etc" / "packagekit.service";
    const auto libUnit = dir.path() / "lib" / "packagekit.service";
    std::ofstream(etcUnit) << "[Unit]\nDescription=PackageKit\n";
    std::ofstream(libUnit) << "[Unit]\nDescription=PackageKit\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper,
    {{"cron.service"}},
    {
        {"/nonexistent/lib/cron.service", "enabled"},
        {"/nonexistent/lib/getty@.service", "static"},
        {"/nonexistent/etc/dbus-org.freedesktop.timesync1.service", "alias"},
        {"/nonexistent/lib/ssh.socket", "enabled"},
        {etcUnit.string(), "static"},
        {libUnit.string(), "static"}
    });

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 2u);
    EXPECT_EQ(unitsJson[0]["id"],            "cron");
    EXPECT_EQ(unitsJson[0]["active_state"],  "active");
    EXPECT_EQ(unitsJson[0]["fragment_path"], "loaded-value");
    // systemd lists each name once; if one repeats, the first entry is kept.
    EXPECT_EQ(unitsJson[1]["id"],            "packagekit");
    EXPECT_EQ(unitsJson[1]["fragment_path"], etcUnit.string());
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

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

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

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());
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

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());
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

// Same layout as a check against systemd 255 (systemctl show -p DropInPaths): the unit's own
// and prefix directories in every search path come first, then the alias's, then service.d.
TEST(SystemdUnitsProviderTest, AppliesDropInsInSystemdOrder)
{
    TempDir dir;
    const auto etc = dir.path() / "etc";
    const auto lib = dir.path() / "lib";

    for (const auto& subdir :
            {
                etc / "service.d", etc / "ith-al.service.d", etc / "ith-a-.service.d",
                lib / "ith-a-b.service.d", lib / "ith-a-.service.d"
            })
    {
        std::filesystem::create_directories(subdir);
    }

    const auto unitPath = lib / "ith-a-b.service";
    const auto aliasPath = etc / "ith-al.service";
    std::ofstream(unitPath) << "[Unit]\nDescription=frag\nSourcePath=/frag\n[Service]\nUser=frag\n";
    std::filesystem::create_symlink(unitPath, aliasPath);

    // The unit's own directory beats service.d, whatever their search paths.
    std::ofstream(lib / "ith-a-b.service.d" / "10-x.conf") << "[Unit]\nDescription=usr-own-dir\n";
    std::ofstream(etc / "service.d" / "10-x.conf") << "[Unit]\nDescription=etc-toplevel\n";
    // So does a prefix directory.
    std::ofstream(lib / "ith-a-.service.d" / "20-p.conf") << "[Service]\nUser=usr-prefix-dir\n";
    std::ofstream(etc / "service.d" / "20-p.conf") << "[Service]\nUser=etc-toplevel\n";
    // And the alias's directory.
    std::ofstream(etc / "ith-al.service.d" / "30-a.conf") << "[Unit]\nSourcePath=/alias-dir\n";
    std::ofstream(etc / "service.d" / "30-a.conf") << "[Unit]\nSourcePath=/etc-toplevel\n";
    // Own and prefix directories go path by path, so a higher-priority path wins between them.
    std::ofstream(etc / "ith-a-.service.d" / "40-y.conf") << "[Service]\nUser=etc-prefix-dir\n";
    std::ofstream(lib / "ith-a-b.service.d" / "40-y.conf") << "[Service]\nUser=usr-own-dir\n";
    // Not a .conf file.
    std::ofstream(etc / "ith-al.service.d" / "99-ignored.txt") << "[Service]\nUser=ignored\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{aliasPath.string(), "alias"}, {unitPath.string(), "disabled"}});

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings({etc.string(), lib.string()}));
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],          "ith-a-b");
    EXPECT_EQ(unitsJson[0]["description"], "usr-own-dir");
    EXPECT_EQ(unitsJson[0]["source_path"], "/alias-dir");
    EXPECT_EQ(unitsJson[0]["user"],        "etc-prefix-dir");
}

// Prefix drop-ins exist since systemd 239 and service.d since 244.
class SystemdDropInVersionTest : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::string>>
{
};

TEST_P(SystemdDropInVersionTest, ReadsOnlyTheDropInsThatVersionApplies)
{
    const auto& [version, description, user] = GetParam();
    TempDir dir;
    std::filesystem::create_directories(dir.path() / "app-.service.d");
    std::filesystem::create_directories(dir.path() / "service.d");
    const auto unitPath = dir.path() / "app-x.service";
    std::ofstream(unitPath) << "[Unit]\nDescription=base\n[Service]\nUser=base\n";
    std::ofstream(dir.path() / "app-.service.d" / "10-prefix.conf") << "[Service]\nUser=prefix\n";
    std::ofstream(dir.path() / "service.d" / "20-top.conf") << "[Unit]\nDescription=toplevel\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{unitPath.string(), "static"}}, UnitFilesOutcome::Reply, version);

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings({dir.path().string()}));
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["description"], description);
    EXPECT_EQ(unitsJson[0]["user"],        user);
}

INSTANTIATE_TEST_SUITE_P(
    SystemdUnitsProviderTest,
    SystemdDropInVersionTest,
    ::testing::Values(
        std::make_tuple("219", "base", "base"),
        std::make_tuple("239 (239-78.el8)", "base", "prefix"),
        std::make_tuple("244", "toplevel", "prefix"),
        std::make_tuple("259.1-1ubuntu1", "toplevel", "prefix"),
        // Unknown version: taken as a current one.
        std::make_tuple("", "toplevel", "prefix")));

TEST(SystemdUnitsProviderTest, DoesNotBlockOnFifoUnitFile)
{
    TempDir dir;
    const auto fifoPath = dir.path() / "fifo.service";
    ASSERT_EQ(::mkfifo(fifoPath.c_str(), 0600), 0);

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{fifoPath.string(), "static"}});

    // Run on a detached thread so a blocking open fails the test instead of hanging it.
    auto provider = std::make_shared<SystemdUnitsProvider>(mockDbusWrapper, TestSettings());
    auto done = std::make_shared<std::promise<nlohmann::json>>();
    auto result = done->get_future();
    std::thread([provider, done]()
    {
        done->set_value(provider->collect());
    }).detach();

    ASSERT_EQ(result.wait_for(std::chrono::seconds(10)), std::future_status::ready) << "collect() blocked on a FIFO";
    const auto unitsJson = result.get();
    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["description"], "fifo.service");
}

TEST(SystemdUnitsProviderTest, ReadsAtMostOneMebibyteOfUnitFile)
{
    TempDir dir;
    const auto unitPath = dir.path() / "big.service";
    {
        std::ofstream unitFile(unitPath);
        unitFile << "[Unit]\nDescription=Big\n";
        const std::string comment(1023, '#');

        for (int i = 0; i < 1100; ++i)
        {
            unitFile << comment << '\n';
        }

        unitFile << "[Service]\nUser=past-the-limit\n";
    }

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{unitPath.string(), "static"}});

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["description"], "Big");
    EXPECT_EQ(unitsJson[0]["user"],        "");
}

// A unit file removed between the listing and the read is no longer installed.
TEST(SystemdUnitsProviderTest, SkipsUnitFileRemovedAfterListing)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{"/nonexistent/gone.service", "disabled"}});

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());

    EXPECT_TRUE(provider.collect().empty());
}

// A masked unit reports no values, whatever its file holds, and ignores its drop-ins.
TEST(SystemdUnitsProviderTest, MaskedStateIgnoresUnitFileAndDropIns)
{
    TempDir dir;
    std::filesystem::create_directories(dir.path() / "runtime-masked.service.d");
    const auto unitPath = dir.path() / "runtime-masked.service";
    std::ofstream(unitPath) << "[Unit]\nDescription=Not applied\n";
    std::ofstream(dir.path() / "runtime-masked.service.d" / "override.conf") << "[Service]\nUser=not-applied\n";

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{unitPath.string(), "masked-runtime"}});

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings({dir.path().string()}));
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["description"],     "runtime-masked.service");
    EXPECT_EQ(unitsJson[0]["user"],            "");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "masked-runtime");
}

// A masked unit stays a masked unit whatever form its link to /dev/null takes.
TEST(SystemdUnitsProviderTest, KeepsMaskedUnitWithRelativeDevNullLink)
{
    TempDir dir;
    const auto maskedPath = dir.path() / "relative-mask.service";
    std::filesystem::create_symlink(std::filesystem::relative("/dev/null", dir.path()), maskedPath);

    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(mockDbusWrapper, {}, {{maskedPath.string(), "masked"}});

    SystemdUnitsProvider provider(mockDbusWrapper, TestSettings());
    const auto unitsJson = provider.collect();

    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"],              "relative-mask");
    EXPECT_EQ(unitsJson[0]["unit_file_state"], "masked");
}

// Without systemd there are no units to report, so a missing bus is not an error.
TEST(SystemdUnitsProviderTest, ReturnsNoUnitsWithoutSystemd)
{
    auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
    EXPECT_CALL(*mockDbusWrapper, error_init(_));
    EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(*mockDbusWrapper, error_free(_)).WillRepeatedly(Return());

    const auto settings = TestSettings({}, "/nonexistent/run/systemd/system");
    SystemdUnitsProvider provider(mockDbusWrapper, settings);

    EXPECT_TRUE(provider.collect().empty());
    EXPECT_EQ(settings.consecutiveFailures->load(), 0u);
}

// A persistent failure must not freeze the inventory: after MAX_CONSECUTIVE_FAILURES failed
// collections in a row, what systemd still lists is reported.
TEST(SystemdUnitsProviderTest, ReportsLoadedUnitsWhenUnitFilesFailPersistently)
{
    const auto settings = TestSettings();

    for (unsigned int attempt = 1; attempt < SystemdUnitsProvider::MAX_CONSECUTIVE_FAILURES; ++attempt)
    {
        auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
        SetUpUnitFilesMock(mockDbusWrapper, {{"cron.service"}}, {}, UnitFilesOutcome::NoReply);
        EXPECT_THROW(SystemdUnitsProvider(mockDbusWrapper, settings).collect(), std::runtime_error);
    }

    auto failingMock = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(failingMock, {{"cron.service"}}, {}, UnitFilesOutcome::NoReply);
    const auto unitsJson = SystemdUnitsProvider(failingMock, settings).collect();
    ASSERT_EQ(unitsJson.size(), 1u);
    EXPECT_EQ(unitsJson[0]["id"], "cron");

    // A complete collection starts the count again.
    auto workingMock = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(workingMock, {{"cron.service"}}, {});
    EXPECT_EQ(SystemdUnitsProvider(workingMock, settings).collect().size(), 1u);
    EXPECT_EQ(settings.consecutiveFailures->load(), 0u);

    auto failingAgainMock = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(failingAgainMock, {{"cron.service"}}, {}, UnitFilesOutcome::NoReply);
    EXPECT_THROW(SystemdUnitsProvider(failingAgainMock, settings).collect(), std::runtime_error);
}

// With nothing listed there is nothing to report, so the scan is skipped however long it fails.
TEST(SystemdUnitsProviderTest, KeepsThrowingWhenListUnitsFailsPersistently)
{
    const auto settings = TestSettings();

    for (unsigned int attempt = 1; attempt <= SystemdUnitsProvider::MAX_CONSECUTIVE_FAILURES + 1; ++attempt)
    {
        auto mockDbusWrapper = std::make_shared<MockDBusWrapper>();
        DBusConnection* conn = reinterpret_cast<DBusConnection*>(0x1);
        EXPECT_CALL(*mockDbusWrapper, error_init(_));
        EXPECT_CALL(*mockDbusWrapper, bus_get_private(DBUS_BUS_SYSTEM, _)).WillOnce(Return(conn));
        EXPECT_CALL(*mockDbusWrapper, connection_close(conn));
        EXPECT_CALL(*mockDbusWrapper, connection_unref(conn));
        EXPECT_CALL(*mockDbusWrapper, error_is_set(_)).WillRepeatedly(Return(false));
        EXPECT_CALL(*mockDbusWrapper, message_new_method_call(_, _, _, "ListUnits")).WillOnce(Return(nullptr));
        EXPECT_CALL(*mockDbusWrapper, error_free(_)).WillRepeatedly(Return());

        SystemdUnitsProvider provider(mockDbusWrapper, settings);

        EXPECT_THROW(provider.collect(), std::runtime_error);
    }
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
    auto loadedRows = SystemdUnitsProvider(loadedMock, TestSettings({dir.path().string()})).collect();

    auto unloadedMock = std::make_shared<MockDBusWrapper>();
    SetUpUnitFilesMock(unloadedMock, {}, {{unitPath.string(), "disabled"}});
    auto unloadedRows = SystemdUnitsProvider(unloadedMock, TestSettings({dir.path().string()})).collect();

    ASSERT_EQ(loadedRows.size(), 1u);
    ASSERT_EQ(unloadedRows.size(), 1u);

    // load_state is not part of the inventory row.
    loadedRows[0].erase("load_state");
    unloadedRows[0].erase("load_state");
    EXPECT_EQ(loadedRows[0], unloadedRows[0]);
}
