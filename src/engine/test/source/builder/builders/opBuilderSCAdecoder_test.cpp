/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include <logging/logging.hpp>
#include <wdb/wdb.hpp>

#include "opBuilderSCAdecoder.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace wazuhdb;
using namespace builder::internals::builders;

using std::string;

const string targetField {"/wdb/result"};
const string helperFunctionName {"sca_decoder"};
const std::vector<string> commonArguments {"$event.original", "$agent.id"};

// Result true, only mandatory fields present
TEST(opBuilderSCAdecoder, CheckEventJSON_OnlyMandatoryFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "result": "failed"
                }
            }
        }
    })")};
    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_TRUE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, not containing policy_id fields
TEST(opBuilderSCAdecoder, CheckEventJSON_NotContainingMandatoryFieldPolicyId)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "result": "failed"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, not containing check_id field
TEST(opBuilderSCAdecoder, CheckEventJSON_NotContainingMandatoryFieldCheckId)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "title": "Ensure mounting of cramfs",
                    "result": "failed"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, not containing check field
TEST(opBuilderSCAdecoder, CheckEventJSON_NotContainingMandatoryCheckField)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8"
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, not containing result fields
TEST(opBuilderSCAdecoder, CheckEventJSON_NotContainingMandatoryResultPolicyId)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result true, all fields present including not neccesary
TEST(opBuilderSCAdecoder, CheckEventJSON_AllFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "description": "The cramfs filesystem type is ...",
                    "rationale": "Removing support for unneeded filesystem...",
                    "remediation": "Edit or create a file in the /etc/mod.d",
                    "compliance":
                    {
                        "cis": "1.1.1.1",
                        "cis_csc": "5.1",
                        "pci_dss": "2.2.5",
                        "tsc": "CC6.3"
                    },
                    "rules":
                    [
                        "c:modprobe -n -v cramfs -> r:install /bin/true|Module",
                        "not c:lsmod -> r:cramfs"
                    ],
                    "condition": "all",
                    "directory": "/etc/audit/rules.d",
                    "process": "proc",
                    "registry": "reg",
                    "command": "modprobe -n -v cramfs",
                    "status":"Not applicable",
                    "result": "failed",
                    "reason": "Could not open file '/boot/grub2/user.cfg'"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_TRUE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, status and result both not present
TEST(opBuilderSCAdecoder, CheckEventJSON_FailedNotPresentStatusAndResult)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "reason": "Could not open file '/boot/grub2/user.cfg'"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, status present but reason not
TEST(opBuilderSCAdecoder, CheckEventJSON_FailedtStatusPresentAndReasonNot)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "status":"Not applicable"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// Result false, only mandatory fields but id is a string
TEST(opBuilderSCAdecoder, CheckEventJSON_IdFieldString)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": "631388619",
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "result": "failed"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_FALSE(sca::isValidCheckEvent(event, "/event/original"));
}

// TODO: should we check an empty field?
TEST(opBuilderSCAdecoder, CheckEventJSON_policyFieldEmpty)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "result": "failed"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // ASSERT_TRUE(sca::isValidCheckEvent(event, "/event/original"));
}

// Map only mandatory fields present
TEST(opBuilderSCAdecoder, FillCheckEventJSON_OnlyMandatoryFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "description": "The cramfs filesystem type is ...",
                    "rationale": "Removing support for unneeded filesystem...",
                    "remediation": "Edit or create a file in the /etc/mod.d",
                    "compliance":
                    {
                        "cis": "1.1.1.1",
                        "cis_csc": "5.1",
                        "pci_dss": "2.2.5",
                        "tsc": "CC6.3"
                    },
                    "references": "https://www.cisecurity.org/cis-benchmarks/",
                    "status": "Not applicable",
                    "reason": "Could not open file '/boot/grub2/user.cfg'"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // sca::fillCheckEvent(event, {}, "/event/original");

    ASSERT_EQ(event->getInt("/sca/id").value(), 631388619);
    ASSERT_EQ(event->getInt("/sca/check/id").value(), 6500);

    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(),
                 "CIS Benchmark for CentOS Linux 8");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "cis_centos8_linux");

    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(),
                 "Ensure mounting of cramfs");
    ASSERT_STREQ(event->getString("/sca/check/description").value().c_str(),
                 "The cramfs filesystem type is ...");
    ASSERT_STREQ(event->getString("/sca/check/rationale").value().c_str(),
                 "Removing support for unneeded filesystem...");
    ASSERT_STREQ(event->getString("/sca/check/remediation").value().c_str(),
                 "Edit or create a file in the /etc/mod.d");
    ASSERT_STREQ(event->getString("/sca/check/compliance/cis").value().c_str(),
                 "1.1.1.1");
    ASSERT_STREQ(event->getString("/sca/check/references").value().c_str(),
                 "https://www.cisecurity.org/cis-benchmarks/");
    ASSERT_STREQ(event->getString("/sca/check/status").value().c_str(), "Not applicable");
    ASSERT_STREQ(event->getString("/sca/check/reason").value().c_str(),
                 "Could not open file '/boot/grub2/user.cfg'");
}

// Map only mandatory fields present, result variation
TEST(opBuilderSCAdecoder, FillCheckEventJSON_OnlyMandatoryFieldsResultVariation)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "description": "The cramfs filesystem type is ...",
                    "rationale": "Removing support for unneeded filesystem...",
                    "remediation": "Edit or create a file in the /etc/mod.d",
                    "compliance":
                    {
                        "cis": "1.1.1.1",
                        "cis_csc": "5.1",
                        "pci_dss": "2.2.5",
                        "tsc": "CC6.3"
                    },
                    "references": "https://www.cisecurity.org/cis-benchmarks/",
                    "result": "failed"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // sca::fillCheckEvent(event, {}, "/event/original");

    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "failed");
}

// Map csv Fields To arrays
// TODO: there's an issue on converting strings to arrays
TEST(opBuilderSCAdecoder, FillCheckEventJSON_CsvFields)
{

    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 631388619,
                "policy": "CIS Benchmark for CentOS Linux 8",
                "policy_id": "cis_centos8_linux",
                "check":
                {
                    "id": 6500,
                    "title": "Ensure mounting of cramfs",
                    "description": "The cramfs filesystem type is ...",
                    "rationale": "Removing support for unneeded filesystem...",
                    "remediation": "Edit or create a file in the /etc/mod.d",
                    "compliance":
                    {
                        "cis": "1.5.3",
                        "cis_csc": "5.1",
                        "pci_dss": "2.2.4",
                        "nist_800_53": "CM.1",
                        "tsc": "CC5.2"
                    },
                    "references": "https://www.cisecurity.org/cis-benchmarks/",
                    "rules":
                    [
                        "f:/usr/lib/systemd/system/rescue.service -> r:ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue",
                        "f:/usr/lib/systemd/system/emergency.service -> r:ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency"
                    ],
                    "file": "/usr/lib/systemd/system/rescue.service,/usr/lib/systemd/system/emergency.service",
                    "directory": "/etc/audit/rules.d",
                    "command":"sysctl net.ipv4.ip_forward,sysctl net.ipv6.conf.all.forwarding",
                    "status": "Not applicable",
                    "reason": "passed"
                }
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // sca::fillCheckEvent(event, {}, "/event/original");

    ASSERT_STREQ(event->getString("/sca/check/file/0").value().c_str(),
                 "/usr/lib/systemd/system/rescue.service");
    ASSERT_STREQ(event->getString("/sca/check/file/1").value().c_str(),
                 "/usr/lib/systemd/system/emergency.service");
    ASSERT_STREQ(event->getString("/sca/check/command/0").value().c_str(),
                 "sysctl net.ipv4.ip_forward");
    ASSERT_STREQ(event->getString("/sca/check/command/1").value().c_str(),
                 "sysctl net.ipv6.conf.all.forwarding");
}

// Result true, checks mandatory fields present
TEST(opBuilderSCAdecoder, CheckDumpJSON_MandatoryField)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "elements_sent": 2,
                "policy_id": "cis_centos8_linux",
                "scan_id": "4602802"
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // auto [checkError, policyId, scanId] = sca::checkDumpJSON(event, "/event/original");

    // ASSERT_FALSE(checkError.has_value());
    // ASSERT_STREQ(policyId.c_str(), "cis_centos8_linux");
    // ASSERT_STREQ(scanId.c_str(), "4602802");
}

// Result false, not containing scan_id mandatory fields present
TEST(opBuilderSCAdecoder, CheckDumpJSON_FailedMandatoryFieldScan_id)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "elements_sent": 2,
                "policy_id": "cis_centos8_linux"
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // auto [checkError, policyId, scanId] = sca::checkDumpJSON(event, "/event/original");

    // ASSERT_TRUE(checkError.has_value());
}

// Result false, not containing elements_sent mandatory fields present
TEST(opBuilderSCAdecoder, CheckDumpJSON_FailedMandatoryFieldElementsSent)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "policy_id": "cis_centos8_linux",
                "scan_id": "4602802"
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // auto [checkError, policyId, scanId] = sca::checkDumpJSON(event, "/event/original");

    // ASSERT_TRUE(checkError.has_value());
}

// Result false, not containing policy_id mandatory fields present
TEST(opBuilderSCAdecoder, CheckDumpJSON_FailedMandatoryFieldPolicy_id)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"vm-centos8"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "elements_sent": 2,
                "scan_id": "4602802"
            }
        }
    })")};

    // TODO FIX THIS TEST
    GTEST_SKIP();
    // auto [checkError, policyId, scanId] = sca::checkDumpJSON(event, "/event/original");

    // ASSERT_TRUE(checkError.has_value());
}

// Result true, Executes Query and responds OK
TEST(opBuilderSCAdecoder, DeletePolicyCheckDistinct_ResultOk)
{
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(
            testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
            "agent vm-centos8 sca delete_check_distinct cis_centos8_linux|4602802");
        testSendMsg(clientRemoteFD, "ok ");
        close(clientRemoteFD);
    });

    ASSERT_TRUE(sca::deletePolicyCheckDistinct(
        "vm-centos8", "cis_centos8_linux", 4602802, wdb));

    t.join();
    close(serverSocketFD);
}

// Result true, Executes Query and responds Err
TEST(opBuilderSCAdecoder, DeletePolicyCheckDistinct_ResultTrueWithQueryError)
{
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(
            testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
            "agent vm-centos7 sca delete_check_distinct cis_centos7_linux|4602802");
        testSendMsg(clientRemoteFD, "err ");
        close(clientRemoteFD);
    });

    ASSERT_TRUE(sca::deletePolicyCheckDistinct(
        "vm-centos7", "cis_centos7_linux", 4602802, wdb));

    t.join();
    close(serverSocketFD);
}

// Result false, Executes Query and responds with anything besides regular options
TEST(opBuilderSCAdecoder, DeletePolicyCheckDistinct_ResultFalseWithRandomAnswer)
{
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(
            testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
            "agent vm-centos7 sca delete_check_distinct cis_centos7_linux|4602802");
        testSendMsg(clientRemoteFD, "anything_else ");
        close(clientRemoteFD);
    });

    ASSERT_FALSE(sca::deletePolicyCheckDistinct(
        "vm-centos7", "cis_centos7_linux", 4602802, wdb));

    t.join();
    close(serverSocketFD);
}

// Result true, Executes Query and responds OK found paylod
TEST(opBuilderSCAdecoder, FindCheckResults_ResultOkFound)
{
    GTEST_SKIP();
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent vm-centos8 sca query_results cis_centos8_linux");
        testSendMsg(clientRemoteFD, "ok found payload");
        close(clientRemoteFD);
    });

    // auto [resultCode, hashCheckResults] =
    //     sca::findCheckResults("vm-centos8", "cis_centos8_linux", wdb);
    // ASSERT_EQ(resultCode, sca::SearchResult::FOUND);
    // ASSERT_STREQ(hashCheckResults.c_str(), "payload");

    t.join();
    close(serverSocketFD);
}

// Result false, Executes Query and responds OK not found
TEST(opBuilderSCAdecoder, FindCheckResults_ResultOkNotFound)
{
    GTEST_SKIP();
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent vm-centos8 sca query_results cis_centos8_linux");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    // auto [resultCode, hashCheckResults] =
    //     sca::findCheckResults("vm-centos8", "cis_centos8_linux", wdb);
    // ASSERT_EQ(resultCode, sca::SearchResult::NOT_FOUND);
    // ASSERT_STREQ(hashCheckResults.c_str(), "");

    t.join();
    close(serverSocketFD);
}

// Result false, Executes Query and responds anything else outside available options
TEST(opBuilderSCAdecoder, FindCheckResults_ResultError)
{
    GTEST_SKIP();
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent vm-centos8 sca query_results cis_centos8_linux");
        testSendMsg(clientRemoteFD, "err not_found");
        close(clientRemoteFD);
    });

    // auto [resultCode, hashCheckResults] =
    //     sca::findCheckResults("vm-centos8", "cis_centos8_linux", wdb);
    // ASSERT_EQ(resultCode, sca::SearchResult::ERROR);
    // ASSERT_STREQ(hashCheckResults.c_str(), "");

    t.join();
    close(serverSocketFD);
}

// Result true, Executes Query and responds OK found paylod
TEST(opBuilderSCAdecoder, FindScanInfo_ResultOkFound)
{
    GTEST_SKIP();
    // FIXME
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent vm-centos8 sca query_scan cis_centos8_linux");
        testSendMsg(clientRemoteFD, "ok found payload");
        close(clientRemoteFD);
    });

    // auto [scanResultCode, hashScanInfo] =
    //     sca::findScanInfo("vm-centos8", "cis_centos8_linux", wdb);
    // ASSERT_EQ(scanResultCode, sca::SearchResult::FOUND);
    // ASSERT_STREQ(hashScanInfo.c_str(), "payload");

    t.join();
    close(serverSocketFD);
}

// Result true, Executes Query and responds OK not found
TEST(opBuilderSCAdecoder, FindScanInfo_ResultOkNotFound)
{
    GTEST_SKIP();
    // FIXME
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent vm-centos8 sca query_scan cis_centos8_linux");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    GTEST_SKIP();

    // auto [scanResultCode, hashScanInfo] =
    //    sca::findScanInfo("vm-centos8", "cis_centos8_linux", wdb);
    // ASSERT_EQ(scanResultCode, sca::SearchResult::NOT_FOUND);
    // ASSERT_STREQ(hashScanInfo.c_str(), "");

    // t.join();
    // close(serverSocketFD);
}

// Result true, Executes Query and responds err
TEST(opBuilderSCAdecoder, FindScanInfo_ResultErr)
{
    GTEST_SKIP();
    // FIXME
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent vm-centos8 sca query_scan cis_centos8_linux");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);
    });

    // auto [scanResultCode, hashScanInfo] =
    //    sca::findScanInfo("vm-centos8", "cis_centos8_linux", wdb);
    // ASSERT_EQ(scanResultCode, sca::SearchResult::ERROR);
    // ASSERT_STREQ(hashScanInfo.c_str(), "");

    t.join();
    close(serverSocketFD);
}

TEST(opBuilderSCAdecoder, BuildSimplest)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    ASSERT_NO_THROW(opBuilderSCAdecoder(tuple));
}

TEST(opBuilderSCAdecoder, checkWrongQttyParams)
{
    const std::vector<string> arguments {"$event.original"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderSCAdecoder(tuple), std::runtime_error);
}

TEST(opBuilderSCAdecoder, checkNoParams)
{
    const std::vector<string> arguments {};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderSCAdecoder(tuple), std::runtime_error);
}

TEST(opBuilderSCAdecoder, gettingEmptyReference)
{
    const std::vector<string> arguments {"$_event_json", "$agent.id"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(R"({"_event_json": ""})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_FALSE(result.payload().get()->getBool("/wdb/result").value());
}

TEST(opBuilderSCAdecoder, gettingNonExistingReference)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(R"({"$_not_event_json": "event"})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(opBuilderSCAdecoder, unexpectedType)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "unexpected_type"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

/* ************************************************************************************ */
//  Type: "check"
/* ************************************************************************************ */

const auto checkTypeEvtWithMandatoryFields {
    R"({
        "agent":
        {
            "id": "007"
        },
        "event":
        {
            "original":
            {
                "type": "check",
                "id": 404,
                "policy": "Some Policy",
                "policy_id": "some_Policy_ID",
                "check":
                {
                    "id": 911,
                    "title": "Some Title",
                    "result": "Some Result"
                }
            }
        }
    })"};

// Missing event parameters checks

TEST(checkTypeDecoderSCA, missingFields)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "check"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingPolicyField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingPolicyIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingCheckField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingCheckIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "title": "Some Title",
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingCheckTitleField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "result": "Some Result"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, missingCheckResultAndStatusFields)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title"
                    }
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, FindEventcheckUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_FALSE(result);
}

TEST(checkTypeDecoderSCA, FindEventcheckOkFoundWithoutComplianceNorRules)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok found this_seems_to_be_ignored");
        close(clientRemoteFD);

        // SaveEventcheck update (exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca update 911|Some Result|||404");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, FindEventcheckOkNotFoundWithoutComplianceNorRules)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveACompliance)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "compliance":
                        {
                            "keyI": "valueI"
                        }
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveCompliance
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_compliance 911|keyI|valueI");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveCompliances)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "compliance":
                        {
                            "keyI": "valueI",
                            "keyII": "2",
                            "keyIII": "3.0"
                        }
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveCompliance
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_compliance 911|keyI|valueI");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveCompliance
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca insert_compliance 911|keyII|2");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveCompliance
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_compliance 911|keyIII|3.0");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveFileRule)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "f:some_file_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|file|f:some_file_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveDirectoryRule)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "d:some_directory_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|directory|d:some_directory_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveRegistryRule)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "r:some_registry_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|registry|r:some_registry_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveCommandRule)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "c:some_command_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|command|c:some_command_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveProcessRule)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "p:some_process_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|process|p:some_process_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveNumericRule)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "n:some_numeric_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|numeric|n:some_numeric_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, InvalidRules)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "a:invalid_rule",
                            "b:invalid_rule",
                            "e:invalid_rule",
                            "g:invalid_rule",
                            "h:invalid_rule",
                            "i:invalid_rule",
                            "j:invalid_rule",
                            "k:invalid_rule",
                            "l:invalid_rule",
                            "m:invalid_rule",
                            "o:invalid_rule",
                            "q:invalid_rule",
                            "s:invalid_rule",
                            "t:invalid_rule",
                            "u:invalid_rule",
                            "v:invalid_rule",
                            "w:invalid_rule",
                            "x:invalid_rule",
                            "y:invalid_rule",
                            "z:invalid_rule",
                            "a:invalid_rule",
                            "b:invalid_rule",
                            "e:invalid_rule",
                            "g:invalid_rule",
                            "h:invalid_rule",
                            "i:invalid_rule",
                            "j:invalid_rule",
                            "k:invalid_rule",
                            "l:invalid_rule",
                            "m:invalid_rule",
                            "o:invalid_rule",
                            "q:invalid_rule",
                            "s:invalid_rule",
                            "t:invalid_rule",
                            "u:invalid_rule",
                            "v:invalid_rule",
                            "w:invalid_rule",
                            "x:invalid_rule",
                            "y:invalid_rule",
                            "z:invalid_rule",
                            "A:invalid_rule",
                            "B:invalid_rule",
                            "E:invalid_rule",
                            "G:invalid_rule",
                            "H:invalid_rule",
                            "I:invalid_rule",
                            "J:invalid_rule",
                            "K:invalid_rule",
                            "L:invalid_rule",
                            "M:invalid_rule",
                            "O:invalid_rule",
                            "Q:invalid_rule",
                            "S:invalid_rule",
                            "T:invalid_rule",
                            "U:invalid_rule",
                            "V:invalid_rule",
                            "W:invalid_rule",
                            "X:invalid_rule",
                            "Y:invalid_rule",
                            "Z:invalid_rule",
                            "0:invalid_rule",
                            "1:invalid_rule",
                            "2:invalid_rule",
                            "3:invalid_rule",
                            "4:invalid_rule",
                            "5:invalid_rule",
                            "6:invalid_rule",
                            "7:invalid_rule",
                            "8:invalid_rule",
                            "9:invalid_rule",
                            "0:invalid_rule",
                            " :invalid_rule",
                            "!:invalid_rule",
                            "#:invalid_rule",
                            "$:invalid_rule",
                            "%:invalid_rule",
                            "&:invalid_rule",
                            "':invalid_rule",
                            "*:invalid_rule",
                            "+:invalid_rule",
                            ",:invalid_rule",
                            "-:invalid_rule",
                            ".:invalid_rule",
                            "/:invalid_rule",
                            "::invalid_rule",
                            ";:invalid_rule",
                            "<:invalid_rule",
                            "=:invalid_rule",
                            ">:invalid_rule",
                            "?:invalid_rule",
                            "[:invalid_rule",
                            "]:invalid_rule",
                            "^:invalid_rule",
                            "_:invalid_rule",
                            "`:invalid_rule",
                            "|:invalid_rule",
                            "(:invalid_rule",
                            "):invalid_rule",
                            "{:invalid_rule",
                            "}:invalid_rule",
                            "\":invalid_rule",
                            "\\:invalid_rule",
                            "~:invalid_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(checkTypeDecoderSCA, SaveRules)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 404,
                    "policy": "Some Policy",
                    "policy_id": "some_Policy_ID",
                    "check":
                    {
                        "id": 911,
                        "title": "Some Title",
                        "result": "Some Result",
                        "rules":
                        [
                            "f:some_file_rule",
                            "d:some_directory_rule",
                            "r:some_registry_rule",
                            "c:some_command_rule",
                            "p:some_process_rule",
                            "n:some_numeric_rule"
                        ]
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok not found"); // result = 1
        close(clientRemoteFD);

        // SaveEventcheck insert (not exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedQuery = std::string {"agent 007 sca insert "}
                             + event->str("/event/original").value_or("error");
        ASSERT_STREQ(clientMessage.data(), expectedQuery.c_str());
        testSendMsg(clientRemoteFD, "this answer is always ignored");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|file|f:some_file_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|directory|d:some_directory_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|registry|r:some_registry_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|command|c:some_command_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|process|p:some_process_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);

        // SaveRule
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_rules 911|numeric|n:some_numeric_rule");
        testSendMsg(clientRemoteFD, "ok this answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

/* ************************************************************************************ */
//  Type: "summary"
/* ************************************************************************************ */

/*
    Mandatory fields are:
        "type": str,
        "policy_id": str,
        "scan_id": int,
        "start_time": int,
        "end_time": int,
        "passed": int,
        "failed": int,
        "invalid": int,
        "total_checks": int,
        "score": int,
        "hash": str,
        "hash_file": str,
        "file": str,
        "name": str

    Optional fields are:
        "description": str,
        "references": str,
        "first_scan": bool,
        "force_alert": str
*/

// [Type Summary missing fields tests] START

TEST(summaryTypeDecoderSCA, missingFields)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldPolicyId)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldScanId)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldStartTime)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldEndTime)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldPassed)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldFailed)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldInvalid)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "name": "some_name",
                    "file": "some_file"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldTotalChecks)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldScore)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldHash)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldHashFile)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "file": "some_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldFile)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "name": "some_name"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(summaryTypeDecoderSCA, missingFieldName)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

// [Type Summary missing fields tests] END

const auto firstScanSummaryEvt {
    R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "name": "some_name",
                    "file": "some_file",
                    "first_scan": true,
                    "force_alert": "Some force_alert"
                }
            }
        })"};

const auto notFirstScanSummaryEvt {
    R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 404,
                    "policy_id": "some_policy_id",
                    "description": "Some description",
                    "references": "Some references",
                    "start_time": 19920710,
                    "end_time": 20220808,
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "name": "some_name",
                    "file": "some_file",
                    "force_alert": "Some force_alert"
                }
            }
        })"};

// Auxiliar functions to improve readability of the tests' code

enum FuncName
{
    FindScanInfo,
    FindPolicyInfo,
    FindCheckResults
};

const static std::map<FuncName, string> Function2Operation = {
    {FuncName::FindScanInfo, "query_scan"},
    {FuncName::FindPolicyInfo, "query_policy"},
    {FuncName::FindCheckResults, "query_results"}};

static inline void ignoreCodeSection(const FuncName function,
                                     const int& serverSocketFD,
                                     const string& agentID,
                                     const string& policyID)
{
    auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemoteFD, 0);
    auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
    string operation {Function2Operation.find(function)->second};
    auto expectedMsg = string("agent ") + agentID + " sca " + operation + " " + policyID;
    ASSERT_STREQ(clientMessage.data(), expectedMsg.data());
    testSendMsg(clientRemoteFD, "unexpected answer");
    close(clientRemoteFD);
}

TEST(summaryTypeDecoderSCA, AllUnexpectedAnswers)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    // TODO How log the errors of wdb
    ASSERT_TRUE(result); // TODO: When is it true, when is it false?
    ASSERT_TRUE(event->getBool("/wdb/result").value());
}

TEST(summaryTypeDecoderSCA, FindScanInfoOkFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_different_hash some_old_scan_id");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca update_scan_info_start "
                     "some_policy_id|19920710|20220808|404|314|42|8|420|4|some_hash");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindScanInfoOkNotFoundFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_scan_info "
                     "19920710|20220808|404|some_policy_id|314|42|8|420|4|some_hash");
        testSendMsg(clientRemoteFD, "ok This answer is always ignored.");
        close(clientRemoteFD);

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindScanInfoOkNotFoundNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca insert_scan_info "
                     "19920710|20220808|404|some_policy_id|314|42|8|420|4|some_hash");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindPolicyInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // SavePolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg =
            "agent 007 sca insert_policy some_name|some_file|some_policy_id|Some "
            "description|Some references|some_hash_file";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok This answer is always ignored.");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256UnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok found this_is_ignored_if_exists");
        close(clientRemoteFD);

        // FindPolicySHA256
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg = "agent 007 sca query_policy_sha256 some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok found this_is_ignored_if_exists");
        close(clientRemoteFD);

        // FindPolicySHA256
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg = "agent 007 sca query_policy_sha256 some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundSameHashFile)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok found this_is_ignored_if_exists");
        close(clientRemoteFD);

        // FindPolicySHA256
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg = "agent 007 sca query_policy_sha256 some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok found some_hash_file");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA,
     FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok found this_is_ignored_if_exists");
        close(clientRemoteFD);

        // FindPolicySHA256
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg = "agent 007 sca query_policy_sha256 some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok found different_hash_file");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        expectedMsg = "agent 007 sca delete_policy some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyErr)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok found this_is_ignored_if_exists");
        close(clientRemoteFD);

        // FindPolicySHA256
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg = "agent 007 sca query_policy_sha256 some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok found different_hash_file");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        expectedMsg = "agent 007 sca delete_policy some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyOk)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policy some_policy_id");
        testSendMsg(clientRemoteFD, "ok found this_is_ignored_if_exists");
        close(clientRemoteFD);

        // FindPolicySHA256
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        auto expectedMsg = "agent 007 sca query_policy_sha256 some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok found different_hash_file");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        expectedMsg = "agent 007 sca delete_policy some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        expectedMsg = "agent 007 sca delete_check some_policy_id";
        ASSERT_STREQ(clientMessage.data(), expectedMsg);
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindCheckResultsOkNotFoundFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindCheckResultsOkNotFoundNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindCheckResultsOkFoundSameHash)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindCheckResultsOkFoundDifferentHashFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_different_hash");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(summaryTypeDecoderSCA, FindCheckResultsOkFoundDifferentHashNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        ignoreCodeSection(
            FuncName::FindScanInfo, serverSocketFD, "007", "some_policy_id");

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_different_hash");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

/* ************************************************************************************ */
//  Type: "policies"
/* ************************************************************************************ */

TEST(policiesTypeDecoderSCA, missingFields)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "policies"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsUnexpectedAnswer)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkNotFound)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundSamePolicy)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found some_policy");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundSamePolicies)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy1", "some_policy2", "some_policyN" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found some_policyN,some_policy1,some_policy2");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyError)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found some_different_policy");
        close(clientRemoteFD);

        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_policy some_different_policy");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyUnexpectedAnswer)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found some_different_policy");
        close(clientRemoteFD);

        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_policy some_different_policy");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyOkDeletePolicyCheck)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "some_policy" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found some_different_policy");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_policy some_different_policy");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check some_different_policy");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckI)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "policyI", "policyIII" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found policyI,policyIII,policyII");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_policy policyII");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_check policyII");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckII)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "policyI", "policyII", "policyIII" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found policyI,policyIII,policyIV");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_policy policyIV");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_check policyIV");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckIII)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "policyI", "policyIII" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindCheckResults
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_policies ");
        testSendMsg(clientRemoteFD, "ok found policyII,policyIII,policyIV");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_policy policyII");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_check policyII");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_policy policyIV");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca delete_check policyIV");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

/* ************************************************************************************ */
//  Type: "dump_end"
/* ************************************************************************************ */

/*
    Mandatory fields are:
        "type": str,
        "policy_id": str,
        "elements_sent": int,
        "scan_id": int
*/

const auto dumpEndTypeEvent {
    R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "policy_id": "some_policy_id",
                    "elements_sent": 0,
                    "scan_id": 404
                }
            }
        })"};

TEST(dumpEndTypeDecoderSCA, missingFields)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end"
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(dumpEndTypeDecoderSCA, missingPolicyIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": 0,
                    "scan_id": 404
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(dumpEndTypeDecoderSCA, missingElementsSentField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "policy_id": "some_policy_id",
                    "scan_id": 404
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(dumpEndTypeDecoderSCA, missingScanIDField)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "policy_id": "some_policy_id",
                    "elements_sent": 0
                }
            }
        })")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
}

TEST(dumpEndTypeDecoderSCA,
     DeletePolicyCheckDistinctUnexpectedAnswerFindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA,
     DeletePolicyCheckDistinctUnexpectedAnswerFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA,
     DeletePolicyCheckDistinctUnexpectedAnswerFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA,
     DeletePolicyCheckDistinctUnexpectedAnswerFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerStrcmpIsNotZero)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_distinct_hash_id");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrStrcmpIsNotZero)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_distinct_hash_id");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkStrcmpIsNotZero)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // DeletePolicyCheckDistinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca delete_check_distinct some_policy_id|404");
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckResults
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_results some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash_id");
        close(clientRemoteFD);

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_distinct_hash_id");
        close(clientRemoteFD);
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

/* ************************************************************************************ */

TEST(opBuilderSCAdecoder, handleDumpHashEmpty)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "dump_end",
                    "elements_sent": 2,
                    "policy_id": "cis_centos8_linux",
                    "scan_id": 4602802
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Check Distinct
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload");
        close(clientRemoteFD);

        // Check Result
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_GT(clientRemoteFD, 0);
        testSendMsg(clientRemoteFD, "ok found RandomHash");
        close(clientRemoteFD);

        // Scan Info
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_GT(clientRemoteFD, 0);
        testSendMsg(clientRemoteFD, "ok found");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_FALSE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleCheckResultNotFoundEvent)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "check",
                    "id": 1858775963,
                    "policy": "CIS Benchmark for CentOS Linux 8",
                    "policy_id": "cis_centos8_linux",
                    "check":
                    {
                        "id": 6529,
                        "title": "Ensure bootloader password is set",
                        "description": "Setting the boot loader password .",
                        "rationale": "Requiring a boot password upon execution",
                        "compliance":
                        {
                            "cis": "1.5.2",
                            "tsc": "CC5.2"
                        },
                        "rules": [ "f:/boot/grub2/user.cfg ->r:^GRUB2_PASSWORD\\s*=\\.+" ],
                        "condition": "all",
                        "file": "/boot/grub2/user.cfg",
                        "status": "Not applicable",
                        "reason": "Could not open file '/boot/grub2/user.cfg'"
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // Find event
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);

        // Save event
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // Save compliance
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload1");
        close(clientRemoteFD);

        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload2");
        close(clientRemoteFD);

        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok payload3");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleEventInfo)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "summary",
                    "scan_id": 1858775963,
                    "name": "CIS Benchmark for CentOS Linux 8",
                    "policy_id": "cis_centos8_linux",
                    "file": "cis_centos8_linux.yml",
                    "description": "This document provides prescriptive guidance",
                    "references": "https://www.cisecurity.org/cis-benchmarks/",
                    "passed": 89,
                    "failed": 95,
                    "invalid": 2,
                    "total_checks": 186,
                    "score": 48.369564056396484,
                    "start_time": 1654518796,
                    "end_time": 1654518800,
                    "hash": "eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4",
                    "hash_file": "2dd71c1696661dba6f1c6a409dc9e4a303028ba9d20c0e13b962ffe435490988",
                    "force_alert": "1"
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindScanInfo
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(
            clientRemoteFD,
            "ok found eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4 "
            "eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d0");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindPolicyInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found");
        close(clientRemoteFD);

        // FindPolicySHA
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(
            clientRemoteFD,
            "ok found 2dd71c1696661dba6f1c6a409dc9e4a303028ba9d20c0e13b962ffe435490988");
        close(clientRemoteFD);

        // DeletePolicy
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeletePolicyCheck
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // FindCheckRes
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(
            clientRemoteFD,
            "ok found eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4");
        close(clientRemoteFD);
    });

    const int clientDgramFD = testBindUnixSocket(CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);
    close(clientDgramFD);
    unlink(CFGARQUEUE);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handleCheckResult)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "message":
                    {
                        "type": "check",
                        "id": 634609468,
                        "policy": "CIS Benchmark for CentOS Linux 8",
                        "policy_id": "cis_centos8_linux",
                        "check":
                        {
                            "id": 6663,
                            "title": "Ensure password reuse is limited",
                            "description": "The /etc/security/opasswd file stores",
                            "compliance":
                            {
                                "cis": "5.4.3",
                                "cis_csc": "16",
                                "pci_dss": "8.2.5",
                                "tsc": "CC6.1"
                            },
                            "rules": [ "f:/etc/pam.d/system-auth -> r:^\\s*password\\.+requisite\\.+pam_pwquality\\.so\\.+ && n:remember=(\\d+) compare >= 5","f:/etc/pam.d/system-auth -> r:^\\s*password\\.+sufficient\\.+pam_unix\\.so\\.+ && n:remember=(\\d+) compare >= 5" ],
                            "condition": "all",
                            "file": "/etc/pam.d/system-auth",
                            "result": "failed"
                        }
                    }
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEvent
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found");
        close(clientRemoteFD);

        // SaveEvent
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok found_failed");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST(opBuilderSCAdecoder, handlePolicies)
{
    GTEST_SKIP();

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "type": "policies",
                    "policies": [ "a", "b", "c", "cis_centos8_linux" ]
                }
            }
        })")};

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD,
                    "ok found cis_centos8,cis_centos7_linux,cis_centos8_linux");
        close(clientRemoteFD);

        // Delete_0
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeleteCheck_0
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // Delete_1
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);

        // DeleteCheck_1
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        testRecvString(clientRemoteFD, SOCK_STREAM);
        testSendMsg(clientRemoteFD, "ok");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}
