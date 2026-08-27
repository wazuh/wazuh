/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ebpf_loader.hpp"
#include <gmock/gmock.h>

namespace wazuh::ebpf {

/**
 * @brief GoogleMock loader for consumer unit tests. Lets FIM and Syscollector
 * exercise their event handling without kernel BPF or root privileges.
 */
class MockEbpfLoader : public EbpfLoader {
public:
    MOCK_METHOD(bool, load, (EventClass, const std::string&), (override));
    MOCK_METHOD(bool, poll, (const FileEventCallback&, int), (override));
    MOCK_METHOD(void, close, (), (override));
    MOCK_METHOD(bool, isLsmActive, (), (const, noexcept, override));
};

} // namespace wazuh::ebpf
