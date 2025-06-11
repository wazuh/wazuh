#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <base/baseTypes.hpp>
#include <base/logging.hpp>
#include <defs/failDef.hpp>
#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>
#include <wdb/mockWdbHandler.hpp>
#include <wdb/mockWdbManager.hpp>

#include "builders/baseBuilders_test.hpp"
#include "builders/optransform/sca.hpp"

using namespace base;
using namespace wazuhdb::mocks;
using namespace sockiface::mocks;
using namespace builder::builders::optransform;
using namespace builder::builders;
using namespace builder::builders::mocks;

using std::string;

namespace
{
const Reference targetField {"wdb.result"};
const std::vector<OpArg> commonArguments {makeRef("event.original"), makeRef("agent.id")};
} // namespace

class opBuilderSCAdecoder_Functions : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbHandler> wdb {};
    std::shared_ptr<MockSockHandler> cfg {};
    std::unordered_map<sca::field::Name, std::string> fieldSource {};
    std::unordered_map<sca::field::Name, std::string> fieldDest {};

    void SetUp() override
    {
        logging::testInit();

        wdb = std::make_shared<MockWdbHandler>();
        cfg = std::make_shared<MockSockHandler>();

        for (sca::field::Name field = sca::field::Name::A_BEGIN; field != sca::field::Name::A_END; ++field)
        {
            fieldSource.insert({field, "/event/original" + sca::field::getRealtivePath(field)});
            fieldDest.insert({field, std::string {"/sca"} + sca::field::getRealtivePath(field)});
        }
    }

    void TearDown() override {}
};

class opBuilderSCAdecoderInit : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbManager> wdbManager {};
    std::shared_ptr<MockWdbHandler> wdb {};
    std::shared_ptr<MockSockFactory> sockFactory {};
    std::shared_ptr<MockSockHandler> cfg {};
    std::shared_ptr<const MockBuildCtx> ctx {};
    std::shared_ptr<const RunState> runState;
    Context context {"test", "test", "test", "test"};

    void SetUp() override
    {
        logging::testInit();

        wdbManager = std::make_shared<MockWdbManager>();
        wdb = std::make_shared<MockWdbHandler>();
        sockFactory = std::make_shared<MockSockFactory>();
        cfg = std::make_shared<MockSockHandler>();
        ctx = std::make_shared<const MockBuildCtx>();
        runState = std::make_shared<const RunState>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdb));
        ON_CALL(*sockFactory, getHandler(testing::_, testing::_)).WillByDefault(testing::Return(cfg));
        ON_CALL(*ctx, context()).WillByDefault(testing::ReturnRef(context));
        ON_CALL(*ctx, runState()).WillByDefault(testing::Return(runState));
    }

    void TearDown() override {}
};

class checkTypeDecoderSCA : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbManager> wdbManager {};
    std::shared_ptr<MockWdbHandler> wdb {};
    std::shared_ptr<MockSockFactory> sockFactory {};
    std::shared_ptr<MockSockHandler> cfg {};
    std::shared_ptr<const MockBuildCtx> ctx {};
    std::shared_ptr<const RunState> runState;
    Context context {"test", "test", "test", "test"};

    void SetUp() override
    {
        logging::testInit();
        wdbManager = std::make_shared<MockWdbManager>();
        wdb = std::make_shared<MockWdbHandler>();
        sockFactory = std::make_shared<MockSockFactory>();
        cfg = std::make_shared<MockSockHandler>();
        ctx = std::make_shared<const MockBuildCtx>();
        runState = std::make_shared<const RunState>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdb));
        ON_CALL(*sockFactory, getHandler(testing::_, testing::_)).WillByDefault(testing::Return(cfg));
        ON_CALL(*ctx, context()).WillByDefault(testing::ReturnRef(context));
        ON_CALL(*ctx, runState()).WillByDefault(testing::Return(runState));
    }

    void TearDown() override {}
};

class summaryTypeDecoderSCA : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbManager> wdbManager {};
    std::shared_ptr<MockWdbHandler> wdb {};
    std::shared_ptr<MockSockFactory> sockFactory {};
    std::shared_ptr<MockSockHandler> cfg {};
    std::shared_ptr<const MockBuildCtx> ctx {};
    std::shared_ptr<const RunState> runState;
    Context context {"test", "test", "test", "test"};

    void SetUp() override
    {
        logging::testInit();
        wdbManager = std::make_shared<MockWdbManager>();
        wdb = std::make_shared<MockWdbHandler>();
        sockFactory = std::make_shared<MockSockFactory>();
        cfg = std::make_shared<MockSockHandler>();
        ctx = std::make_shared<const MockBuildCtx>();
        runState = std::make_shared<const RunState>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdb));
        ON_CALL(*sockFactory, getHandler(testing::_, testing::_)).WillByDefault(testing::Return(cfg));
        ON_CALL(*ctx, context()).WillByDefault(testing::ReturnRef(context));
        ON_CALL(*ctx, runState()).WillByDefault(testing::Return(runState));
    }

    void TearDown() override {}
};

class policiesTypeDecoderSCA : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbManager> wdbManager {};
    std::shared_ptr<MockWdbHandler> wdb {};
    std::shared_ptr<MockSockFactory> sockFactory {};
    std::shared_ptr<MockSockHandler> cfg {};
    std::shared_ptr<const MockBuildCtx> ctx {};
    std::shared_ptr<const RunState> runState;
    Context context {"test", "test", "test", "test"};

    void SetUp() override
    {
        logging::testInit();
        wdbManager = std::make_shared<MockWdbManager>();
        wdb = std::make_shared<MockWdbHandler>();
        sockFactory = std::make_shared<MockSockFactory>();
        cfg = std::make_shared<MockSockHandler>();
        ctx = std::make_shared<const MockBuildCtx>();
        runState = std::make_shared<const RunState>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdb));
        ON_CALL(*sockFactory, getHandler(testing::_, testing::_)).WillByDefault(testing::Return(cfg));
        ON_CALL(*ctx, context()).WillByDefault(testing::ReturnRef(context));
        ON_CALL(*ctx, runState()).WillByDefault(testing::Return(runState));
    }

    void TearDown() override {}
};

class dumpEndTypeDecoderSCA : public ::testing::Test
{
protected:
    std::shared_ptr<MockWdbManager> wdbManager {};
    std::shared_ptr<MockWdbHandler> wdb {};
    std::shared_ptr<MockSockFactory> sockFactory {};
    std::shared_ptr<MockSockHandler> cfg {};
    std::shared_ptr<const MockBuildCtx> ctx {};
    std::shared_ptr<const RunState> runState;
    Context context {"test", "test", "test", "test"};

    void SetUp() override
    {
        logging::testInit();
        wdbManager = std::make_shared<MockWdbManager>();
        wdb = std::make_shared<MockWdbHandler>();
        sockFactory = std::make_shared<MockSockFactory>();
        cfg = std::make_shared<MockSockHandler>();
        ctx = std::make_shared<const MockBuildCtx>();
        runState = std::make_shared<const RunState>();

        ON_CALL(*wdbManager, connection()).WillByDefault(testing::Return(wdb));
        ON_CALL(*sockFactory, getHandler(testing::_, testing::_)).WillByDefault(testing::Return(cfg));
        ON_CALL(*ctx, context()).WillByDefault(testing::ReturnRef(context));
        ON_CALL(*ctx, runState()).WillByDefault(testing::Return(runState));
    }

    void TearDown() override {}
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
                    "result": "failed",
                    "reason": "Could not open file '/boot/grub2/user.cfg'"
                }
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_TRUE(sca::isValidCheckEvent(state));
}

TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_SuccessNotPresentResult)
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

    ASSERT_TRUE(sca::isValidCheckEvent(state));
}

// Result true and result field filled
TEST_F(opBuilderSCAdecoder_Functions, CheckEventJSON_FailedtReasonNotPresent)
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
                    "title": "Ensure mounting of cramfs"
                }
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_TRUE(sca::isValidCheckEvent(state));
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
                    "title": "Ensure mounting of cramfs"
                }
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    ASSERT_TRUE(sca::isValidCheckEvent(state));
    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "not applicable");
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
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "CIS Benchmark for CentOS Linux 8");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "cis_centos8_linux");

    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(), "Ensure mounting of cramfs");
    ASSERT_STREQ(event->getString("/sca/check/description").value().c_str(), "The cramfs filesystem type is ...");
    ASSERT_STREQ(event->getString("/sca/check/rationale").value().c_str(),
                 "Removing support for unneeded filesystem...");
    ASSERT_STREQ(event->getString("/sca/check/remediation").value().c_str(), "Edit or create a file in the /etc/mod.d");
    ASSERT_STREQ(event->getString("/sca/check/compliance/cis").value().c_str(), "1.1.1.1");
    ASSERT_STREQ(event->getString("/sca/check/references").value().c_str(),
                 "https://www.cisecurity.org/cis-benchmarks/");
    ASSERT_STREQ(event->getString("/sca/check/reason").value().c_str(), "Could not open file '/boot/grub2/user.cfg'");
}

// Map only mandatory fields present, result variation
TEST_F(opBuilderSCAdecoder_Functions, FillCheckEventJSON_OnlyMandatoryFieldsResultVariation)
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
                    "reason": "passed"
                }
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    sca::fillCheckEvent(state, "Applicable");

    ASSERT_STREQ(event->getString("/sca/check/file/0").value().c_str(), "/usr/lib/systemd/system/rescue.service");
    ASSERT_STREQ(event->getString("/sca/check/file/1").value().c_str(), "/usr/lib/systemd/system/emergency.service");
    ASSERT_STREQ(event->getString("/sca/check/command/0").value().c_str(), "sysctl net.ipv4.ip_forward");
    ASSERT_STREQ(event->getString("/sca/check/command/1").value().c_str(), "sysctl net.ipv6.conf.all.forwarding");
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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    auto [checkError, policyId, scanId] = sca::isValidDumpEvent(state);

    ASSERT_TRUE(checkError.has_value());
}

// Result true, Executes Query and responds OK
TEST_F(opBuilderSCAdecoder_Functions, DeletePolicyCheckDistinct_ResultOk)
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
                "policy_id": "cis_centos8_linux",
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct cis_centos8_linux|4602802"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    ASSERT_NO_THROW(sca::deletePolicyCheckDistinct(state, "cis_centos8_linux", 4602802));
}

// Result true, Executes Query and responds Err
TEST_F(opBuilderSCAdecoder_Functions, DeletePolicyCheckDistinct_ResultTrueWithQueryError)
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
                "policy_id": "cis_centos8_linux",
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct cis_centos8_linux|4602802"),
                                       testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    ASSERT_NO_THROW(sca::deletePolicyCheckDistinct(state, "cis_centos8_linux", 4602802));
}

// Result false, Executes Query and responds with anything besides regular options
TEST_F(opBuilderSCAdecoder_Functions, DeletePolicyCheckDistinct_ResultFalseWithRandomAnswer)
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
                "policy_id": "cis_centos8_linux",
                "scan_id": 4602802
            }
        }
    })")};

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct cis_centos8_linux|4602802"),
                                       testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    ASSERT_NO_THROW(sca::deletePolicyCheckDistinct(state, "cis_centos8_linux", 4602802));
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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results cis_centos8_linux"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found check")));

    auto [resultCode, hashCheckResults] = sca::findCheckResults(state, "cis_centos8_linux");

    ASSERT_EQ(resultCode, sca::SearchResult::FOUND);
    ASSERT_EQ(hashCheckResults, "check");
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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results cis_centos8_linux"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    auto [resultCode, hashCheckResults] = sca::findCheckResults(state, "cis_centos8_linux");

    ASSERT_EQ(resultCode, sca::SearchResult::NOT_FOUND);
    ASSERT_TRUE(hashCheckResults.empty());
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

    const sca::DecodeCxt& state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};

    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results cis_centos8_linux"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    auto [resultCode, hashCheckResults] = sca::findCheckResults(state, "cis_centos8_linux");

    ASSERT_EQ(resultCode, sca::SearchResult::ERROR);
    ASSERT_STREQ(hashCheckResults.c_str(), "");
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
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(), "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getNumberAsDouble("/sca/score").value(), 4.0);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(opBuilderSCAdecoder_Functions, scoreFloatFillScanInfo_AllCopiedFields)
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
                "score": 69.007,
                "file": "some_file"
            }
        }
    })")};

    auto state = sca::DecodeCxt {event, "007", wdb, cfg, fieldSource, fieldDest};
    sca::FillScanInfo(state);

    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(), "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getNumberAsDouble("/sca/score").value(), 69.007);
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

TEST_F(opBuilderSCAdecoderInit, gettingEmptyReference)
{
    const std::vector<OpArg> arguments {makeRef("_event_json"), makeRef("agent.id")};

    const auto tuple {std::make_tuple(targetField, arguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(R"({"_event_json": ""})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));
}

TEST_F(opBuilderSCAdecoderInit, gettingNonExistingReference)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(R"({"$_not_event_json": "event"})")};

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));
}

TEST_F(opBuilderSCAdecoderInit, unexpectedType)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    ASSERT_FALSE(result.payload().get()->exists("/wdb/result"));
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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

TEST_F(checkTypeDecoderSCA, missingCheckResultField)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, FindEventcheckUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_FALSE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, FindEventcheckOkFoundWithoutComplianceNorRules)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found check")));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca update 911|Some Result||404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_EQ(event->getInt("/sca/id").value(), 404);
    ASSERT_EQ(event->getInt("/sca/check/id").value(), 911);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "Some Policy");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_Policy_ID");
    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(), "Some Title");
    ASSERT_STREQ(event->getString("/sca/check/previous_result").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "Some Result");
    ASSERT_FALSE(event->exists("/sca/check/compliance"));
    ASSERT_FALSE(event->exists("/sca/check/reason"));
}

// It won't fill event check Result Exists and Response from DB is equal to result
TEST_F(checkTypeDecoderSCA, FindEventcheckOkFoundWithResultEqualResponse)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found Some Result")));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca update 911|Some Result||404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

// It won't fill event check Result doesn't exists
TEST_F(checkTypeDecoderSCA, FindEventcheckOkFoundWithoutResult)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
                    "reason": "Could not open file"
                }
            }
        }
    })"};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithoutResult)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found ")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca update 911||Could not open file|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(checkTypeDecoderSCA, FindEventcheckOkNotFoundWithoutComplianceNorRules)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(checkTypeEvtWithMandatoryFields)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_compliance 911|keyI|valueI"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_EQ(event->getInt("/sca/id").value(), 404);
    ASSERT_EQ(event->getInt("/sca/check/id").value(), 911);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "check");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "Some Policy");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_Policy_ID");
    ASSERT_STREQ(event->getString("/sca/check/title").value().c_str(), "Some Title");
    ASSERT_STREQ(event->getString("/sca/check/compliance/keyI").value().c_str(), "valueI");
    ASSERT_STREQ(event->getString("/sca/check/result").value().c_str(), "Some Result");
    ASSERT_FALSE(event->exists("/sca/check/description"));
    ASSERT_FALSE(event->exists("/sca/check/rationale"));
    ASSERT_FALSE(event->exists("/sca/check/remediation"));
    ASSERT_FALSE(event->exists("/sca/check/references"));
    ASSERT_FALSE(event->exists("/sca/check/reason"));
}

TEST_F(checkTypeDecoderSCA, SaveCompliances)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_compliance 911|keyI|valueI"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_compliance 911|keyII|2"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_compliance 911|keyIII|3.0"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveFileRule)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|file|f:some_file_rule"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveDirectoryRule)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|directory|d:some_directory_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveRegistryRule)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|registry|r:some_registry_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveCommandRule)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|command|c:some_command_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveProcessRule)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|process|p:some_process_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveNumericRule)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|numeric|n:some_numeric_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, InvalidRules)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(checkTypeDecoderSCA, SaveRules)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query 911"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(
            testing::StrEq("agent 007 sca insert " + event->str("/event/original").value_or("error")), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|file|f:some_file_rule"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|directory|d:some_directory_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|registry|r:some_registry_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|command|c:some_command_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|process|p:some_process_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_rules 911|numeric|n:some_numeric_rule"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    result::Result<Event> result {op(event)};

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
        "score": int/float,
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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

const static std::map<FuncName, string> Function2Operation = {{FuncName::FindScanInfo, "query_scan"},
                                                              {FuncName::FindPolicyInfo, "query_policy"},
                                                              {FuncName::FindCheckResults, "query_results"}};

static inline void ignoreCodeSection(const FuncName function,
                                     const string& agentID,
                                     const string& policyID,
                                     std::shared_ptr<MockWdbHandler> wdb)
{
    string operation {Function2Operation.find(function)->second};
    auto expectedMsg = string("agent ") + agentID + " sca " + operation + " " + policyID;

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq(expectedMsg), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));
}

TEST_F(summaryTypeDecoderSCA, AllUnexpectedAnswers)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    // TODO How log the errors of wdb
    ASSERT_TRUE(result); // TODO: When is it true, when is it false?
    ASSERT_TRUE(event->getBool("/wdb/result").value());
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_hash some_old_scan_id")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca update_scan_info_start "
                                                      "some_policy_id|19920710|20220808|404|314|42|8|420|4|some_hash"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(), "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getNumberAsDouble("/sca/score").value(), 4.0);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, scoreFloatFindScanInfoOkFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
                    "score": 69.007,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "name": "some_name",
                    "file": "some_file",
                    "first_scan": true,
                    "force_alert": "Some force_alert"
                }
            }
        })"};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_hash some_old_scan_id")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca update_scan_info_start "
                                              "some_policy_id|19920710|20220808|404|314|42|8|420|69.007|some_hash"),
                               testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(), "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getNumberAsDouble("/sca/score").value(), 69.007);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkFoundSameHashNoForced)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash some_old_scan_id")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca update_scan_info_start "
                                                      "some_policy_id|19920710|20220808|404|314|42|8|420|4|some_hash"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, scoreFloatFindScanInfoOkFoundSameHashNoForced)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
                    "score": 69.007,
                    "hash": "some_hash",
                    "hash_file": "some_hash_file",
                    "name": "some_name",
                    "file": "some_file"
                }
            }
        })"};

    const auto event {std::make_shared<json::Json>(notFirstScanNoForceSummaryEvt)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash some_old_scan_id")));
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca update_scan_info_start "
                                              "some_policy_id|19920710|20220808|404|314|42|8|420|69.007|some_hash"),
                               testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkNotFoundFirstScan)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_scan_info "
                                                      "19920710|20220808|404|some_policy_id|314|42|8|420|4|some_hash"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    // PushDumpRequest socket
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:1")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(), "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getNumberAsDouble("/sca/score").value(), 4.0);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, FindScanInfoOkNotFoundNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_scan_info "
                                                      "19920710|20220808|404|some_policy_id|314|42|8|420|4|some_hash"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_STREQ(event->getString("/sca/type").value().c_str(), "summary");
    ASSERT_STREQ(event->getString("/sca/policy").value().c_str(), "some_name");
    ASSERT_EQ(event->getInt("/sca/scan_id").value(), 404);
    ASSERT_STREQ(event->getString("/sca/description").value().c_str(), "Some description");
    ASSERT_STREQ(event->getString("/sca/policy_id").value().c_str(), "some_policy_id");
    ASSERT_EQ(event->getInt("/sca/passed").value(), 314);
    ASSERT_EQ(event->getInt("/sca/failed").value(), 42);
    ASSERT_EQ(event->getInt("/sca/invalid").value(), 8);
    ASSERT_EQ(event->getInt("/sca/total_checks").value(), 420);
    ASSERT_EQ(event->getNumberAsDouble("/sca/score").value(), 4.0);
    ASSERT_STREQ(event->getString("/sca/file").value().c_str(), "some_file");
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca insert_policy some_name|some_file|"
                                                      "some_policy_id|Some description|Some references|"
                                                      "some_hash_file"),
                                       testing::_))
        .WillOnce(testing::Return(okQueryRes("This payload is always ignored.")));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256UnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found this_is_ignored_if_exists")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy_sha256 some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("unexpected answer")));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found this_is_ignored_if_exists")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy_sha256 some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundSameHashFile)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found this_is_ignored_if_exists")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy_sha256 some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_file")));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found this_is_ignored_if_exists")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy_sha256 some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found different_hash_file")));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("unexpected answer")));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("unexpected answer")));

    // Dump
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:1")))
        .WillOnce(testing::Return(successSendMsgRes()));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyErr)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found this_is_ignored_if_exists")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy_sha256 some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found different_hash_file")));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindPolicyInfoOkFoundFindPolicySHA256OkFoundDeletePolicyOk)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found this_is_ignored_if_exists")));
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policy_sha256 some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found different_hash_file")));
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // DeletePolicyCheck
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    ignoreCodeSection(FuncName::FindCheckResults, "007", "some_policy_id", wdb);

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:1")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkNotFoundFirstScan)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:1")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkNotFoundNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:0")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkFoundSameHash)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkFoundDifferentHashFirstScan)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(firstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_hash")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:1")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

TEST_F(summaryTypeDecoderSCA, FindCheckResultsOkFoundDifferentHashNotFirstScan)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(notFirstScanSummaryEvt)};

    // FindScanInfo
    ignoreCodeSection(FuncName::FindScanInfo, "007", "some_policy_id", wdb);

    // FindPolicyInfo
    ignoreCodeSection(FuncName::FindPolicyInfo, "007", "some_policy_id", wdb);

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_hash")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:0")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_FALSE(event->exists("/sca/type"));
}

/* ************************************************************************************ */
//  Type: "policies"
/* ************************************************************************************ */

TEST_F(policiesTypeDecoderSCA, missingFields)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkNotFound)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundSamePolicy)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_policy")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundSamePolicies)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_policyN,some_policy1,some_policy2")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyError)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_policy")));

    // DeletePolicy
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy some_different_policy"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyUnexpectedAnswer)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_policy")));

    // DeletePolicy
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy some_different_policy"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPolicyOkDeletePolicyCheck)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_different_policy")));

    // DeletePolicy
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy some_different_policy"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // DeletePolicyCheck
    EXPECT_CALL(*wdb,
                tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check some_different_policy"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckI)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found policyI,policyIII,policyII")));

    // DeletePolicy
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy policyII"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // DeletePolicyCheck
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check policyII"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckII)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found policyI,policyIII,policyIV")));

    // DeletePolicy
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy policyIV"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // DeletePolicyCheck
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check policyIV"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
}

TEST_F(policiesTypeDecoderSCA, FindPoliciesIdsOkFoundDifferentPoliciesDeletePolicyCheckIII)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

    // FindPoliciesIds
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_policies "), testing::_))
        .WillOnce(testing::Return(okQueryRes("found policyII,policyIII,policyIV")));

    // DeletePolicy
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy policyII"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // DeletePolicyCheck
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check policyII"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // DeletePolicy
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_policy policyIV"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // DeletePolicyCheck
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check policyIV"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

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

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerFindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindCheckResultsUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindCheckResultsOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindScanInfoOkNotFound)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("not found")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkFindScanInfoUnexpectedAnswer)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkStrcmpIsZero)
{
    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctUnexpectedAnswerStrcmpIsNotZero)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(unknownQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_distinct_hash_id")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:0")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctErrStrcmpIsNotZero)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(errorQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_distinct_hash_id")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:0")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}

TEST_F(dumpEndTypeDecoderSCA, DeletePolicyCheckDistinctOkStrcmpIsNotZero)
{

    const auto tuple {std::make_tuple(targetField, commonArguments, ctx)};

    EXPECT_CALL(*wdbManager, connection());
    EXPECT_CALL(*sockFactory, getHandler(testing::_, testing::_));

    const auto op {std::apply(getBuilderSCAdecoder(wdbManager, sockFactory), tuple)};

    const auto event {std::make_shared<json::Json>(dumpEndTypeEvent)};

    // DeletePolicyCheckDistinct
    EXPECT_CALL(
        *wdb,
        tryQueryAndParseResult(testing::StrEq("agent 007 sca delete_check_distinct some_policy_id|404"), testing::_))
        .WillOnce(testing::Return(okQueryRes()));

    // FindCheckResults
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_results some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_hash_id")));

    // FindScanInfo
    EXPECT_CALL(*wdb, tryQueryAndParseResult(testing::StrEq("agent 007 sca query_scan some_policy_id"), testing::_))
        .WillOnce(testing::Return(okQueryRes("found some_distinct_hash_id")));

    // PushDumpRequest
    EXPECT_CALL(*cfg, isConnected()).WillOnce(testing::Return(true));
    EXPECT_CALL(*cfg, sendMsg(testing::StrEq("007:sca-dump:some_policy_id:0")))
        .WillOnce(testing::Return(successSendMsgRes()));

    result::Result<Event> result {op(event)};

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField.jsonPath()));
    ASSERT_TRUE(result.payload()->getBool(targetField.jsonPath()).value());
}
