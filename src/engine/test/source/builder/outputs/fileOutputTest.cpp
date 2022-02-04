#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "outputs/file.hpp"
#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"
#include "json/json.hpp"

#include "test_utils.hpp"

using namespace builder::internals;

auto message = R"({
    "event": {
        "original": "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"
    },
    "wazuh": {
        "agent": {
            "id": "001",
            "name": "agentSim",
            "version": "PoC"
        },
        "event": {
            "format": "text",
            "id": "9aa69e7b-e1b0-530e-a710-49108e86019b",
            "ingested": "2021-10-26T16:50:34.348945Z",
            "kind": "event"
        },
        "host": {
            "architecture": "x86_64",
            "hostname": "hive",
            "ip": "127.0.1.1",
            "mac": "B0:7D:64:11:B3:13",
            "os": {
                "kernel": "5.14.14-arch1-1",
                "name": "Linux",
                "type": "posix",
                "version": "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"
            }
        },
        "module": {
            "name": "logcollector",
            "source": "apache-access"
        }
    }
})";

auto compact_message =
    R"({"event":{"original":"::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"},"wazuh":{"agent":{"id":"001","name":"agentSim","version":"PoC"},"event":{"format":"text","id":"9aa69e7b-e1b0-530e-a710-49108e86019b","ingested":"2021-10-26T16:50:34.348945Z","kind":"event"},"host":{"architecture":"x86_64","hostname":"hive","ip":"127.0.1.1","mac":"B0:7D:64:11:B3:13","os":{"kernel":"5.14.14-arch1-1","name":"Linux","type":"posix","version":"#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"}},"module":{"name":"logcollector","source":"apache-access"}}}
)";

TEST(FileOutput, Create)
{
    auto output = outputs::FileOutput("/tmp/file");
    std::filesystem::remove("/tmp/file");
}

TEST(FileOutput, Unknown_path)
{
    ASSERT_THROW(outputs::FileOutput("/tmp45/file"), std::invalid_argument);
}

TEST(FileOutput, Write)
{
    using event_t = json::Document;
    auto filepath = "/tmp/file";

    auto output = outputs::FileOutput(filepath);
    output.write(event_t(message));

    std::ifstream ifs(filepath);
    std::stringstream buffer;
    buffer << ifs.rdbuf();

    GTEST_COUT << buffer.str() << std::endl;
    ASSERT_TRUE(buffer.str() == compact_message);
    std::filesystem::remove(filepath);
}
