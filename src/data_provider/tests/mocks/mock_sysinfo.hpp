#pragma once

#include <gmock/gmock.h>
#include <string>
#include <sysInfoInterface.h>
#include <json.hpp>

// Simple mock for sysinfo interface needed by process rule evaluator tests
class MockSysInfo : public ISysInfo {
public:
    MOCK_METHOD(nlohmann::json, hardware, (), (override));
    MOCK_METHOD(nlohmann::json, packages, (), (override));
    MOCK_METHOD(nlohmann::json, os, (), (override));
    MOCK_METHOD(nlohmann::json, processes, (), (override));
    MOCK_METHOD(nlohmann::json, networks, (), (override));
    MOCK_METHOD(nlohmann::json, ports, (), (override));
    MOCK_METHOD(nlohmann::json, hotfixes, (), (override));
    MOCK_METHOD(nlohmann::json, groups, (), (override));
    MOCK_METHOD(nlohmann::json, users, (), (override));
    MOCK_METHOD(void, packages, (std::function<void(nlohmann::json&)>), (override));
    MOCK_METHOD(void, processes, (std::function<void(nlohmann::json&)>), (override));
};
