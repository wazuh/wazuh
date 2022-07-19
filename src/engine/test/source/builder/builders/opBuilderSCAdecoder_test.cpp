/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"
#include "opBuilderHelperMap.hpp"
#include "opBuilderMapValue.hpp"
#include "opBuilderSCAdecoder.hpp"
#include "opBuilderWdbSync.hpp"
#include "socketAuxiliarFunctions.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "testUtils.hpp"
#include "wdb/wdb.hpp"

namespace
{

using namespace base;
using namespace wazuhdb;
namespace bld = builder::internals::builders;
namespace unixStream = base::utils::socketInterface;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

class opBuilderSCAdecoderTest : public ::testing::Test
{

protected:
    // Per-test-suite set-up.
    // Called before the first test in this test suite.
    static void SetUpTestSuite()
    {
        Registry::registerBuilder("helper.s_concat", bld::opBuilderHelperStringConcat);
        Registry::registerBuilder("check", bld::stageBuilderCheck);
        Registry::registerBuilder("condition", bld::opBuilderCondition);
        Registry::registerBuilder("middle.condition", bld::middleBuilderCondition);
        Registry::registerBuilder("middle.helper.exists", bld::opBuilderHelperExists);
        Registry::registerBuilder("combinator.chain", bld::combinatorBuilderChain);
        Registry::registerBuilder("map.value", bld::opBuilderMapValue);
        Registry::registerBuilder("helper.wdb_query", bld::opBuilderWdbSyncQuery);
        Registry::registerBuilder("helper.sca_decoder", bld::opBuilderSCAdecoder);
    }

    // Per-test-suite tear-down.
    // Called after the last test in this test suite.
    static void TearDownTestSuite() { return; }
};

// Build ok
TEST_F(opBuilderSCAdecoderTest, BuildSimplest)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "wdb.result": "+sca_decoder"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::opBuilderSCAdecoder(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderSCAdecoderTest, typeMissmatch)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(
        R"({"event":{"original":{"message":{"type":"not_available"}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_FALSE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handleDumpFailingCheckResultFinding)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemoteDPCheckDistinct = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteDPCheckDistinct, SOCK_STREAM);
        testSendMsg(clientRemoteDPCheckDistinct, "err payload");
        close(clientRemoteDPCheckDistinct);

        const int clientRemoteFindCheckRes = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindCheckRes, SOCK_STREAM);
        testSendMsg(clientRemoteFindCheckRes, "err");
        close(clientRemoteFindCheckRes);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"dump_end","elements_sent":2,"policy_id":"cis_centos8_linux","scan_id":4602802}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_FALSE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handleDumpHashMissmatch)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemoteDPCheckDistinct = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteDPCheckDistinct, SOCK_STREAM);
        testSendMsg(clientRemoteDPCheckDistinct, "ok payload");
        close(clientRemoteDPCheckDistinct);

        const int clientRemoteFindCheckRes = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindCheckRes, SOCK_STREAM);
        testSendMsg(clientRemoteFindCheckRes, "ok found RandomHash");
        close(clientRemoteFindCheckRes);

        const int clientRemoteFindScanInfo = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindScanInfo, SOCK_STREAM);
        testSendMsg(clientRemoteFindScanInfo, "ok found NotRandomHash");
        close(clientRemoteFindScanInfo);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"dump_end","elements_sent":2,"policy_id":"cis_centos8_linux","scan_id":4602802}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handleDumpHashEmpty)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemoteDPCheckDistinct = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteDPCheckDistinct, SOCK_STREAM);
        testSendMsg(clientRemoteDPCheckDistinct, "ok payload");
        close(clientRemoteDPCheckDistinct);

        const int clientRemoteFindCheckRes = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindCheckRes, SOCK_STREAM);
        testSendMsg(clientRemoteFindCheckRes, "ok found RandomHash");
        close(clientRemoteFindCheckRes);

        const int clientRemoteFindScanInfo = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindScanInfo, SOCK_STREAM);
        testSendMsg(clientRemoteFindScanInfo, "ok found");
        close(clientRemoteFindScanInfo);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"dump_end","elements_sent":2,"policy_id":"cis_centos8_linux","scan_id":4602802}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_FALSE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handleDumpHappyPath)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientRemoteDPCheckDistinct = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteDPCheckDistinct, SOCK_STREAM);
        testSendMsg(clientRemoteDPCheckDistinct, "ok payload");
        close(clientRemoteDPCheckDistinct);

        const int clientRemoteFindCheckRes = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindCheckRes, SOCK_STREAM);
        testSendMsg(clientRemoteFindCheckRes, "ok found hash");
        close(clientRemoteFindCheckRes);

        const int clientRemoteFindScanInfo = testAcceptConnection(serverSocketFD);
        testRecvString(clientRemoteFindScanInfo, SOCK_STREAM);
        testSendMsg(clientRemoteFindScanInfo, "ok found hash");
        close(clientRemoteFindScanInfo);
    });

    const int serverSocketScaFd = testBindUnixSocket(bld::CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(serverSocketScaFd, 0);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"dump_end","elements_sent":2,"policy_id":"cis_centos8_linux","scan_id":4602802}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_STREQ(testRecvString(serverSocketScaFd, SOCK_DGRAM).c_str(),
                 "vm-centos8:sca-dump:cis_centos8_linux:0");
    ASSERT_TRUE(expected[0]->getEvent()->get("/sca_result").GetBool());

    close(serverSocketScaFd);
    unlink(bld::CFGARQUEUE);
}

TEST_F(opBuilderSCAdecoderTest, handleCheckResultNotFoundEvent)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocket_FD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocket_FD, 0);

    std::thread t([&]() {
        const int clientFindEventQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientFindEventQ, SOCK_STREAM);
        testSendMsg(clientFindEventQ, "ok not found");
        close(clientFindEventQ);

        const int clientSaveEventQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientSaveEventQ, SOCK_STREAM);
        testSendMsg(clientSaveEventQ, "ok");
        close(clientSaveEventQ);

        const int clientSaveComplianceQ_1 = testAcceptConnection(serverSocket_FD);
        testRecvString(clientSaveComplianceQ_1, SOCK_STREAM);
        testSendMsg(clientSaveComplianceQ_1, "ok payload1");
        close(clientSaveComplianceQ_1);

        const int clientSaveComplianceQ_2 = testAcceptConnection(serverSocket_FD);
        testRecvString(clientSaveComplianceQ_2, SOCK_STREAM);
        testSendMsg(clientSaveComplianceQ_2, "ok  payload2");
        close(clientSaveComplianceQ_2);

        const int clientSaveRulesQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientSaveRulesQ, SOCK_STREAM);
        testSendMsg(clientSaveRulesQ, "ok  payload3");
        close(clientSaveRulesQ);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObject = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"check","id":1858775963,"policy":"CIS Benchmark for CentOS Linux 8","policy_id":"cis_centos8_linux","check":{"id":6529,"title":"Ensure bootloader password is set","description":"Setting the boot loader password .","rationale":"Requiring a boot password upon execution","compliance":{"cis":"1.5.2","tsc":"CC5.2"},"rules":["f:/boot/grub2/user.cfg -> r:^GRUB2_PASSWORD\\s*=\\.+"],"condition":"all","file":"/boot/grub2/user.cfg","status":"Not applicable","reason":"Could not open file '/boot/grub2/user.cfg'"}}}}})");

    inputSubject.get_subscriber().on_next(inputObject);

    t.join();
    close(serverSocket_FD);


    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handleEventInfo)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocket_FD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocket_FD, 0);

    std::thread t([&]() {
        const int clientFindScanInfoQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientFindScanInfoQ, SOCK_STREAM);
        testSendMsg(clientFindScanInfoQ, "ok foundeab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4 eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d0");
        close(clientFindScanInfoQ);

        const int clientSaveScanInfoQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientSaveScanInfoQ, SOCK_STREAM);
        testSendMsg(clientSaveScanInfoQ, "ok");
        close(clientSaveScanInfoQ);

        const int clientFindPolicyInfoQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientFindPolicyInfoQ, SOCK_STREAM);
        testSendMsg(clientFindPolicyInfoQ, "ok found");
        close(clientFindPolicyInfoQ);

        const int clientFindPolicySHAQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientFindPolicySHAQ, SOCK_STREAM);
        testSendMsg(clientFindPolicySHAQ, "ok found2dd71c1696661dba6f1c6a409dc9e4a303028ba9d20c0e13b962ffe435490988");
        close(clientFindPolicySHAQ);

        const int clientDeletePolicyQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientDeletePolicyQ, SOCK_STREAM);
        testSendMsg(clientDeletePolicyQ, "ok");
        close(clientDeletePolicyQ);

        const int clientDeletePolicyCheckQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientDeletePolicyCheckQ, SOCK_STREAM);
        testSendMsg(clientDeletePolicyCheckQ, "ok");
        close(clientDeletePolicyCheckQ);

        const int clientFindCheckResQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientFindCheckResQ, SOCK_STREAM);
        testSendMsg(clientFindCheckResQ, "ok foundeab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4");
        close(clientFindCheckResQ);
    });

    const int serverSocketScaFd = testBindUnixSocket(bld::CFGARQUEUE, SOCK_DGRAM);
    ASSERT_GT(serverSocketScaFd, 0);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObject = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"summary","scan_id":1858775963,"name":"CIS Benchmark for CentOS Linux 8","policy_id":"cis_centos8_linux","file":"cis_centos8_linux.yml","description":"This document provides prescriptive guidance","references":"https://www.cisecurity.org/cis-benchmarks/","passed":89,"failed":95,"invalid":2,"total_checks":186,"score":48.369564056396484,"start_time":1654518796,"end_time":1654518800,"hash":"eab79bb8419c85a74057e4f51bc7021e81132c273ff9bd7b243cc1f891d1c3d4","hash_file":"2dd71c1696661dba6f1c6a409dc9e4a303028ba9d20c0e13b962ffe435490988","force_alert":"1"}}}})");

    inputSubject.get_subscriber().on_next(inputObject);

    t.join();
    close(serverSocket_FD);
    close(serverSocketScaFd);
    unlink(bld::CFGARQUEUE);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handleCheckResult)
{
    GTEST_SKIP(); //FIXME: Can't make ir work alongside previous test
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    std::thread t([&]() {
        const int clientFindEvent = testAcceptConnection(serverSocketFD);
        testRecvString(clientFindEvent, SOCK_STREAM);
        testSendMsg(clientFindEvent, "ok found");
        close(clientFindEvent);

        const int clientSaveEvent = testAcceptConnection(serverSocketFD);
        testRecvString(clientSaveEvent, SOCK_STREAM);
        testSendMsg(clientSaveEvent, "ok found_failed");
        close(clientSaveEvent);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"check","id":634609468,"policy":"CIS Benchmark for CentOS Linux 8","policy_id":"cis_centos8_linux","check":{"id":6663,"title":"Ensure password reuse is limited","description":"The /etc/security/opasswd file stores","compliance":{"cis":"5.4.3","cis_csc":"16","pci_dss":"8.2.5","tsc":"CC6.1"},"rules":["f:/etc/pam.d/system-auth -> r:^\\s*password\\.+requisite\\.+pam_pwquality\\.so\\.+ && n:remember=(\\d+) compare >= 5","f:/etc/pam.d/system-auth -> r:^\\s*password\\.+sufficient\\.+pam_unix\\.so\\.+ && n:remember=(\\d+) compare >= 5"],"condition":"all","file":"/etc/pam.d/system-auth","result":"failed"}}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    t.join();
    close(serverSocketFD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

TEST_F(opBuilderSCAdecoderTest, handlePolicies)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    const int serverSocket_FD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocket_FD, 0);

    std::thread t([&]() {
        const int clientFindPoliciesIdsQ = testAcceptConnection(serverSocket_FD);
        testRecvString(clientFindPoliciesIdsQ, SOCK_STREAM);
        testSendMsg(clientFindPoliciesIdsQ, "ok foundcis_centos8,cis_centos7_linux,cis_centos8_linux");
        close(clientFindPoliciesIdsQ);

        const int clientDelete_0_Q = testAcceptConnection(serverSocket_FD);
        testRecvString(clientDelete_0_Q, SOCK_STREAM);
        testSendMsg(clientDelete_0_Q, "ok");
        close(clientDelete_0_Q);

        const int clientDeleteCheck_0_Q = testAcceptConnection(serverSocket_FD);
        testRecvString(clientDeleteCheck_0_Q, SOCK_STREAM);
        testSendMsg(clientDeleteCheck_0_Q, "ok");
        close(clientDeleteCheck_0_Q);

        const int clientDelete_1_Q = testAcceptConnection(serverSocket_FD);
        testRecvString(clientDelete_1_Q, SOCK_STREAM);
        testSendMsg(clientDelete_1_Q, "ok");
        close(clientDelete_1_Q);

        const int clientDeleteCheck_1_Q = testAcceptConnection(serverSocket_FD);
        testRecvString(clientDeleteCheck_1_Q, SOCK_STREAM);
        testSendMsg(clientDeleteCheck_1_Q, "ok");
        close(clientDeleteCheck_1_Q);
    });

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObject = createSharedEvent(
        R"({"agent":{"id":"vm-centos8"},"event":{"original":{"message":{"type":"policies","policies":["a","b","c","cis_centos8_linux"]}}}})");

    inputSubject.get_subscriber().on_next(inputObject);

    t.join();
    close(serverSocket_FD);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_TRUE(expected[0]->getEvent()->get("/sca_result").GetBool());
}

} // namespace
