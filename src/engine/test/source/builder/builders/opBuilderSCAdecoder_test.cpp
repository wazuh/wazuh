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

class opBuilderSCAdecoder_Functions : public ::testing::Test
{
protected:
    std::shared_ptr<wazuhdb::WazuhDB> wdb {};
    std::shared_ptr<base::utils::socketInterface::unixDatagram> cfg {};
    std::unordered_map<sca::field::Name, std::string> fieldSource {};
    std::unordered_map<sca::field::Name, std::string> fieldDest {};

    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));

        wdb = std::make_shared<wazuhdb::WazuhDB>(WDB_SOCK_PATH);
        cfg = std::make_shared<base::utils::socketInterface::unixDatagram>(
            CFG_AR_SOCK_PATH);

        for (sca::field::Name field = sca::field::Name::A_BEGIN;
             field != sca::field::Name::A_END;
             ++field)
        {
            fieldSource.insert(
                {field, "/event/original" + sca::field::getRealtivePath(field)});
            fieldDest.insert(
                {field, std::string {"/sca"} + sca::field::getRealtivePath(field)});
        }
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

class opBuilderSCAdecoderInit : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

class checkTypeDecoderSCA : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

class summaryTypeDecoderSCA : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

class policiesTypeDecoderSCA : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

class dumpEndTypeDecoderSCA : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

// Result true, only mandatory fields present
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_OnlyMandatoryFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_TRUE(sca::isValidCheckEvent(state));
}

// Result false, not containing policy_id fields
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_NotContainingMandatoryFieldPolicyId)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// Result false, not containing check_id field
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_NotContainingMandatoryFieldCheckId)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// Result false, not containing check field
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_NotContainingMandatoryCheckField)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// Result false, not containing result fields
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_NotContainingMandatoryResultPolicyId)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// Result true, all fields present including not neccesary
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_AllFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_TRUE(sca::isValidCheckEvent(state));
}

// Result false, status and result both not present
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_FailedNotPresentStatusAndResult)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// Result false, status present but reason not
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_FailedtStatusPresentAndReasonNot)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// Result false, only mandatory fields but id is a string
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_IdFieldString)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_FALSE(sca::isValidCheckEvent(state));
}

// TODO: should we check an empty field?
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_policyFieldEmpty)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_TRUE(sca::isValidCheckEvent(state));
}

// Map only mandatory fields present
TEST_F(opBuilderSCAdecoder_Functions, FillCheckEventJSON_OnlyMandatoryFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    sca::fillCheckEvent(state, "Applicable");

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
TEST_F(opBuilderSCAdecoder_Functions,
       FillCheckEventJSON_OnlyMandatoryFieldsResultVariation)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    sca::fillCheckEvent(state, "Applicable");

    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "failed");
}

// Map csv Fields To arrays
// TODO: there's an issue on converting strings to arrays
TEST_F(opBuilderSCAdecoder_Functions, FillCheckEventJSON_CsvFields)
{

    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    sca::fillCheckEvent(state, "Applicable");

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
TEST_F(opBuilderSCAdecoder_Functions, CheckDumpJSON_MandatoryField)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [checkError, policyId, scanId] = sca::isValidDumpEvent(state);

    ASSERT_FALSE(checkError.has_value());
    ASSERT_STREQ(policyId.c_str(), "cis_centos8_linux");
    ASSERT_EQ(scanId, 4602802);
}

// Result false, not containing scan_id mandatory fields present
TEST_F(opBuilderSCAdecoder_Functions, CheckDumpJSON_FailedMandatoryFieldScan_id)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    auto [checkError, policyId, scanId] = sca::isValidDumpEvent(state);

    ASSERT_TRUE(checkError.has_value());
}

// Result false, not containing elements_sent mandatory fields present
TEST_F(opBuilderSCAdecoder_Functions, CheckDumpJSON_FailedMandatoryFieldElementsSent)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
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

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [checkError, policyId, scanId] = sca::isValidDumpEvent(state);

    ASSERT_TRUE(checkError.has_value());
}

// Result false, not containing policy_id mandatory fields present
TEST_F(opBuilderSCAdecoder_Functions, CheckDumpJSON_FailedMandatoryFieldPolicy_id)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "elements_sent": 2,
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [checkError, policyId, scanId] = sca::isValidDumpEvent(state);

    ASSERT_TRUE(checkError.has_value());
}

// Result true, Executes Query and responds OK
TEST_F(opBuilderSCAdecoder_Functions, DeletePolicyCheckDistinct_ResultOk)
{
    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent 007 sca delete_check_distinct cis_centos8_linux|4602802");
        testSendMsg(clientRemoteFD, "ok ");
        close(clientRemoteFD);
    });

    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "policy_id": "cis_centos8_linux",
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    sca::deletePolicyCheckDistinct(state, "cis_centos8_linux", 4602802);

    t.join();
    close(serverSocketFD);
}

// Result true, Executes Query and responds Err
TEST_F(opBuilderSCAdecoder_Functions, DeletePolicyCheckDistinct_ResultTrueWithQueryError)
{
    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent 007 sca delete_check_distinct cis_centos8_linux|4602802");
        testSendMsg(clientRemoteFD, "err ");
        close(clientRemoteFD);
    });

    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "policy_id": "cis_centos8_linux",
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    sca::deletePolicyCheckDistinct(state, "cis_centos8_linux", 4602802);

    t.join();
    close(serverSocketFD);
}

// Result false, Executes Query and responds with anything besides regular options
TEST_F(opBuilderSCAdecoder_Functions,
       DeletePolicyCheckDistinct_ResultFalseWithRandomAnswer)
{
    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent 007 sca delete_check_distinct cis_centos8_linux|4602802");
        testSendMsg(clientRemoteFD, "anything_else ");
        close(clientRemoteFD);
    });

    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "policy_id": "cis_centos8_linux",
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    sca::deletePolicyCheckDistinct(state, "cis_centos8_linux", 4602802);

    t.join();
    close(serverSocketFD);
}

// Result true, Executes Query and responds OK found paylod
TEST_F(opBuilderSCAdecoder_Functions, FindCheckResults_ResultOkFound)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "policy_id": "cis_centos8_linux",
                "elements_sent": 2,
                "scan_id": 4602802
            }
        }
    })")};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent 007 sca query_results cis_centos8_linux");
        testSendMsg(clientRemoteFD, "ok found payload");
        close(clientRemoteFD);
    });

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [resultCode, hashCheckResults] =
        sca::findCheckResults(state, "cis_centos8_linux");

    ASSERT_EQ(resultCode, sca::SearchResult::FOUND);
    ASSERT_STREQ(hashCheckResults.c_str(), "payload");

    t.join();
    close(serverSocketFD);
}

// Result false, Executes Query and responds OK not found
TEST_F(opBuilderSCAdecoder_Functions, FindCheckResults_ResultOkNotFound)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "policy_id": "cis_centos8_linux",
                "elements_sent": 2,
                "scan_id": 4602802
            }
        }
    })")};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent 007 sca query_results cis_centos8_linux");
        testSendMsg(clientRemoteFD, "ok not found");
        close(clientRemoteFD);
    });

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [resultCode, hashCheckResults] =
        sca::findCheckResults(state, "cis_centos8_linux");

    ASSERT_EQ(resultCode, sca::SearchResult::NOT_FOUND);
    ASSERT_TRUE(hashCheckResults.empty());

    t.join();
    close(serverSocketFD);
}

// Result false, Executes Query and responds anything else outside available options
TEST_F(opBuilderSCAdecoder_Functions, FindCheckResults_ResultError)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "agent":
        {
            "id":"007"
        },
        "event":
        {
            "original":
            {
                "type": "dump_end",
                "policy_id": "cis_centos8_linux",
                "elements_sent": 2,
                "scan_id": 4602802
            }
        }
    })")};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        ASSERT_STREQ(testRecvString(clientRemoteFD, SOCK_STREAM).c_str(),
                     "agent 007 sca query_results cis_centos8_linux");
        testSendMsg(clientRemoteFD, "err not_found");
        close(clientRemoteFD);
    });

    const sca::DecodeCxt& state =
        sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [resultCode, hashCheckResults] =
        sca::findCheckResults(state, "cis_centos8_linux");

    ASSERT_EQ(resultCode, sca::SearchResult::ERROR);
    ASSERT_STREQ(hashCheckResults.c_str(), "");

    t.join();
    close(serverSocketFD);
}

TEST_F(opBuilderSCAdecoder_Functions, IsValidScanInfo_OnlyMandatoryFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "policy_id": "some_policy_id",
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

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    ASSERT_TRUE(sca::isValidScanInfoEvent(state));
}

TEST_F(opBuilderSCAdecoder_Functions, IsValidScanInfo_NotPresentPolicyID)
{
    auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
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
                    "description": "Some description",
                    "references": "Some references",
                    "name": "some_name"
                }
            }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    ASSERT_FALSE(sca::isValidScanInfoEvent(state));
}

TEST_F(opBuilderSCAdecoder_Functions, IsValidScanInfo_WrongTypeField)
{
    auto event {std::make_shared<json::Json>(
        R"({
            "agent":
            {
                "id": "007"
            },
            "event":
            {
                "original":
                {
                    "policy_id": "some_policy_id",
                    "scan_id": "404",
                    "start_time": "19920710",
                    "end_time": "20220808",
                    "passed": 314,
                    "failed": 42,
                    "invalid": 8,
                    "total_checks": 420,
                    "score": 4,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "file": "some_file",
                    "description": "Some description",
                    "references": "Some references",
                    "name": "some_name"
                }
            }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    ASSERT_FALSE(sca::isValidScanInfoEvent(state));
}

TEST_F(opBuilderSCAdecoder_Functions, FillScanInfo_AllCopiedFields)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "event":
        {
            "original":
            {
                "name": "some_name",
                "scan_id": 404,
                "description": "Some description",
                "policy_id": "some_policy_id",
                "passed": 314,
                "failed": 42,
                "invalid": 8,
                "total_checks": 420,
                "score": 4,
                "file": "some_file"
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    sca::FillScanInfo(state);

    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(),
                 "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getInt("/sca/score").value(), 4);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(opBuilderSCAdecoder_Functions, FillScanInfo_OnlyNameFieldPresent)
{
    auto event {std::make_shared<json::Json>(
        R"({
        "event":
        {
            "original":
            {
                "name": "some_name"
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    sca::FillScanInfo(state);

    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_FALSE(event->exists("/sca/scan_id"));
    ASSERT_FALSE(event->exists("/sca/description"));
    ASSERT_FALSE(event->exists("/sca/policy_id"));
    ASSERT_FALSE(event->exists("/sca/passed"));
    ASSERT_FALSE(event->exists("/sca/failed"));
    ASSERT_FALSE(event->exists("/sca/invalid"));
    ASSERT_FALSE(event->exists("/sca/total_checks"));
    ASSERT_FALSE(event->exists("/sca/score"));
    ASSERT_FALSE(event->exists("/sca/file"));
}

TEST_F(opBuilderSCAdecoderInit, BuildSimplest)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    ASSERT_NO_THROW(opBuilderSCAdecoder(tuple));
}

TEST_F(opBuilderSCAdecoderInit, checkWrongQttyParams)
{
    const std::vector<string> arguments {"$event.original"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderSCAdecoder(tuple), std::runtime_error);
}

TEST_F(opBuilderSCAdecoderInit, checkNoParams)
{
    const std::vector<string> arguments {};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderSCAdecoder(tuple), std::runtime_error);
}

TEST_F(opBuilderSCAdecoderInit, gettingEmptyReference)
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

TEST_F(opBuilderSCAdecoderInit, gettingNonExistingReference)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(R"({"$_not_event_json": "event"})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_FALSE(result.payload().get()->getBool("/wdb/result").value());
}

TEST_F(opBuilderSCAdecoderInit, unexpectedType)
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
    ASSERT_TRUE(result.payload().get()->exists("/wdb/result"));
    ASSERT_FALSE(result.payload().get()->getBool("/wdb/result").value());
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

TEST_F(checkTypeDecoderSCA, missingFields)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingIDField)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingPolicyField)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingPolicyIDField)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingCheckField)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingCheckIDField)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingCheckTitleField)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, missingCheckResultAndStatusFields)
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, FindEventcheckUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, FindEventcheckOkFoundWithoutComplianceNorRules)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok found payload");
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
    ASSERT_EQ(event->getInt("/sca/id").value(), 404);
    ASSERT_EQ(event->getInt("/sca/check/id").value(), 911);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "Some Policy");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_Policy_ID");
    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(), "Some Title");
    ASSERT_STREQ(event->getString("/sca/check/previous_result").value().c_str(),
                 "payload");
    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "Some Result");
    ASSERT_FALSE(event->exists("/sca/check/compliance"));
    ASSERT_FALSE(event->exists("/sca/check/status"));
    ASSERT_FALSE(event->exists("/sca/check/reason"));
}

// It won't fill event check Result Exists and Response from DB is equal to result
TEST_F(checkTypeDecoderSCA, FindEventcheckOkFoundWithResultEqualResponse)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok found Some Result");
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

// It won't fill event check Result doesn't exists and Response from DB is equal to status
TEST_F(checkTypeDecoderSCA, FindEventcheckOkFoundWithoutResultAndStatusEqualResponse)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto checkTypeEvtWithoutResult {
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
                    "status": "Some Status",
                    "reason": "Could not open file"
                }
            }
        }
    })"};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithoutResult)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindEventcheck
        auto clientRemoteFD {testAcceptConnection(serverSocketFD)};
        ASSERT_GT(clientRemoteFD, 0);
        auto clientMessage {testRecvString(clientRemoteFD, SOCK_STREAM)};
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query 911");
        testSendMsg(clientRemoteFD, "ok found Some Status");
        close(clientRemoteFD);

        // SaveEventcheck update (exists)
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca update 911||Some Status|Could not open file|404");
        testSendMsg(clientRemoteFD, "This answer is always ignored.");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, FindEventcheckOkNotFoundWithoutComplianceNorRules)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_EQ(event->getInt("/sca/id").value(), 404);
    ASSERT_EQ(event->getInt("/sca/check/id").value(), 911);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "Some Policy");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_Policy_ID");
    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(), "Some Title");
    ASSERT_FALSE(event->exists("/sca/check/previous_result"));
}

TEST_F(checkTypeDecoderSCA, SaveACompliance)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_EQ(event->getInt("/sca/id").value(), 404);
    ASSERT_EQ(event->getInt("/sca/check/id").value(), 911);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "Some Policy");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_Policy_ID");
    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(), "Some Title");
    ASSERT_STREQ(event->getString("/sca/check/compliance/keyI").value().c_str(),
                 "valueI");
    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "Some Result");
    ASSERT_FALSE(event->exists("/sca/check/description"));
    ASSERT_FALSE(event->exists("/sca/check/rationale"));
    ASSERT_FALSE(event->exists("/sca/check/remediation"));
    ASSERT_FALSE(event->exists("/sca/check/references"));
    ASSERT_FALSE(event->exists("/sca/check/status"));
    ASSERT_FALSE(event->exists("/sca/check/reason"));
}

TEST_F(checkTypeDecoderSCA, SaveCompliances)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveFileRule)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveDirectoryRule)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveRegistryRule)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveCommandRule)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveProcessRule)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveNumericRule)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, InvalidRules)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(checkTypeDecoderSCA, SaveRules)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(summaryTypeDecoderSCA, missingFields)
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

TEST_F(summaryTypeDecoderSCA, missingFieldPolicyId)
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

TEST_F(summaryTypeDecoderSCA, missingFieldScanId)
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

TEST_F(summaryTypeDecoderSCA, missingFieldStartTime)
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

TEST_F(summaryTypeDecoderSCA, missingFieldEndTime)
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

TEST_F(summaryTypeDecoderSCA, missingFieldPassed)
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

TEST_F(summaryTypeDecoderSCA, missingFieldFailed)
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

TEST_F(summaryTypeDecoderSCA, missingFieldInvalid)
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

TEST_F(summaryTypeDecoderSCA, missingFieldTotalChecks)
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

TEST_F(summaryTypeDecoderSCA, missingFieldScore)
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

TEST_F(summaryTypeDecoderSCA, missingFieldHash)
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

TEST_F(summaryTypeDecoderSCA, missingFieldHashFile)
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

TEST_F(summaryTypeDecoderSCA, missingFieldFile)
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

TEST_F(summaryTypeDecoderSCA, missingFieldName)
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

TEST_F(summaryTypeDecoderSCA, AllUnexpectedAnswers)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
        testSendMsg(clientRemoteFD, "ok This payload is always ignored.");
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
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(),
                 "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getInt("/sca/score").value(), 4);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkFoundSameHashNoForced)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto notFirstScanNoForceSummaryEvt {
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
                    "file": "some_file"
                }
            }
        })"};

    const auto event {std::make_shared<json::Json>(notFirstScanNoForceSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        int clientRemoteFD {-1};
        string clientMessage;

        // FindScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(), "agent 007 sca query_scan some_policy_id");
        testSendMsg(clientRemoteFD, "ok found some_hash some_old_scan_id");
        close(clientRemoteFD);

        // SaveScanInfo
        clientRemoteFD = testAcceptConnection(serverSocketFD);
        ASSERT_GT(clientRemoteFD, 0);
        clientMessage = testRecvString(clientRemoteFD, SOCK_STREAM);
        ASSERT_STREQ(clientMessage.data(),
                     "agent 007 sca update_scan_info_start "
                     "some_policy_id|19920710|20220808|404|314|42|8|420|4|some_hash");
        testSendMsg(clientRemoteFD, "ok This payload is always ignored.");
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkNotFoundFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
        testSendMsg(clientRemoteFD, "ok This payload is always ignored.");
        close(clientRemoteFD);

        // FindPolicyInfo
        ignoreCodeSection(
            FuncName::FindPolicyInfo, serverSocketFD, "007", "some_policy_id");

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    // PushDumpRequest socket
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(),
                 "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getInt("/sca/score").value(), 4);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkNotFoundNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(),
                 "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getInt("/sca/score").value(), 4);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
        testSendMsg(clientRemoteFD, "ok This payload is always ignored.");
        close(clientRemoteFD);

        // FindCheckResults
        ignoreCodeSection(
            FuncName::FindCheckResults, serverSocketFD, "007", "some_policy_id");
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256UnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundSameHashFile)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA,
       FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyErr)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyOk)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkNotFoundFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkNotFoundNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkFoundSameHash)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkFoundDifferentHashFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:1");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkFoundDifferentHashNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

/* ************************************************************************************ */
//  Type: "policies"
/* ************************************************************************************ */

TEST_F(policiesTypeDecoderSCA, missingFields)
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsUnexpectedAnswer)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkNotFound)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundSamePolicy)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundSamePolicies)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyError)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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
        testSendMsg(clientRemoteFD, "err");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyUnexpectedAnswer)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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
        testSendMsg(clientRemoteFD, "unexpected answer");
        close(clientRemoteFD);
    });

    result::Result<Event> result {op(event)};

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyOkDeletePolicyCheck)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckI)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckII)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(policiesTypeDecoderSCA,
       FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckIII)
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

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        // FindPoliciesIds
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

TEST_F(dumpEndTypeDecoderSCA, missingFields)
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

TEST_F(dumpEndTypeDecoderSCA, missingPolicyIDField)
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

TEST_F(dumpEndTypeDecoderSCA, missingElementsSentField)
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

TEST_F(dumpEndTypeDecoderSCA, missingScanIDField)
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

TEST_F(dumpEndTypeDecoderSCA,
       DeletePolicyCheckDistinctUnexpectedAnswerFindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA,
       DeletePolicyCheckDistinctUnexpectedAnswerFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA,
       DeletePolicyCheckDistinctUnexpectedAnswerFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA,
       DeletePolicyCheckDistinctUnexpectedAnswerFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerStrcmpIsNotZero)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrStrcmpIsNotZero)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkStrcmpIsNotZero)
{

    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    const auto op {opBuilderSCAdecoder(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    const int serverSocketFD = testBindUnixSocket(WDB_SOCK_PATH, SOCK_STREAM);
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
    const int clientDgramFD = testBindUnixSocket(CFG_AR_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientDgramFD, 0);

    result::Result<Event> result {op(event)};

    // PushDumpRequest
    auto receivedMessage {testRecvString(clientDgramFD, SOCK_DGRAM)};
    ASSERT_STREQ(receivedMessage.c_str(), "007:sca-dump:some_policy_id:0");
    close(clientDgramFD);
    unlink(CFG_AR_SOCK_PATH.data());

    t.join();
    close(serverSocketFD);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField).value());
}
