#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"
#include "json/json.hpp"
#include "outputs/file_output.hpp"

#include "test_utils.hpp"


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

auto compact_message = R"({"event":{"original":"::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"},"wazuh":{"agent":{"id":"001","name":"agentSim","version":"PoC"},"event":{"format":"text","id":"9aa69e7b-e1b0-530e-a710-49108e86019b","ingested":"2021-10-26T16:50:34.348945Z","kind":"event"},"host":{"architecture":"x86_64","hostname":"hive","ip":"127.0.1.1","mac":"B0:7D:64:11:B3:13","os":{"kernel":"5.14.14-arch1-1","name":"Linux","type":"posix","version":"#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"}},"module":{"name":"logcollector","source":"apache-access"}}}
)";

TEST(FileOutput, Create)
{
    auto output = outputs::FileOutput<json::Document>("/tmp/file");
    std::filesystem::remove("/tmp/file");
}

TEST(FileOutput, Unknown_path)
{
    ASSERT_THROW(outputs::FileOutput<json::Document>("/tmp45/file"), std::runtime_error);
}


TEST(FileOutput, Write)
{
    using event_t = json::Document;
    auto filepath = "/tmp/file";

    auto output = outputs::FileOutput<event_t>(filepath);
    auto obs = rxcpp::observable<>::create<event_t>([](rxcpp::subscriber<event_t> s){
        s.on_next(event_t(message));
        s.on_completed();
    });

    obs.subscribe(output.subscriber());
    std::ifstream ifs(filepath);
    std::stringstream buffer;
    buffer << ifs.rdbuf();

    GTEST_COUT << buffer.str() << std::endl;
    ASSERT_TRUE(buffer.str() == compact_message);
    std::filesystem::remove(filepath);
}

TEST(FileOutput, BufferedWrite)
{
    using event_t = json::Document;
    auto filepath = "/tmp/file";

    auto output = outputs::BufferedFileOutput<event_t>(filepath, 1);
    auto obs = rxcpp::observable<>::create<event_t>([](rxcpp::subscriber<event_t> s){
        s.on_next(event_t(message));
        s.on_completed();
    });

    obs.subscribe(output.subscriber());
    std::ifstream ifs(filepath);
    std::stringstream buffer;
    buffer << ifs.rdbuf();

    GTEST_COUT << buffer.str() << std::endl;
    ASSERT_TRUE(buffer.str() == compact_message);
    std::filesystem::remove(filepath);
}

TEST(FileOutput, RotatingFileOutput)
{
    using event_t = json::Document;
    auto filepath = "/tmp/file";
    auto rotatedFile1 = "/tmp/file.0";
    auto rotatedFile2 = "/tmp/file.1";

    auto output = outputs::RotatingFileOutput<event_t>(filepath, 500);
    auto obs = rxcpp::observable<>::create<event_t>([](rxcpp::subscriber<event_t> s){
        s.on_next(event_t(message));
        s.on_next(event_t(message));
        s.on_completed();
    });

    obs.subscribe(output.subscriber());

    std::ifstream ifs1(rotatedFile1);
    std::stringstream buffer1;
    buffer1 << ifs1.rdbuf();

    std::ifstream ifs2(rotatedFile2);
    std::stringstream buffer2;
    buffer2 << ifs2.rdbuf();

    GTEST_COUT << "Rotated 1 ->" << buffer1.str() << std::endl;
    GTEST_COUT << "Rotated 2 ->" << buffer2.str() << std::endl;

    ASSERT_TRUE(buffer1.str() == compact_message);
    ASSERT_TRUE(buffer2.str() == compact_message);

    std::filesystem::remove(filepath);
    std::filesystem::remove(rotatedFile1);
    std::filesystem::remove(rotatedFile2);
}
