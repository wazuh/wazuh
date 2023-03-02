/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * March 10, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <sstream>
#include <unistd.h>

#include "sysInfoSolarisProcesses_test.h"
#include "processes/processFamilyDataFactory.h"

void SysInfoSolarisProcessesTest::SetUp() {};
void SysInfoSolarisProcessesTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

class sysInfoProcessSolarisWrapperMock : public IProcessInterfaceWrapper
{
    public:
        sysInfoProcessSolarisWrapperMock(const psinfo_t& psinfo, const pstatus_t status, const prcred_t cred) {}
        virtual ~sysInfoProcessSolarisWrapperMock() = default;
        MOCK_METHOD(std::string, pid, (), (const, override));
        MOCK_METHOD(std::string, name, (), (const, override));
        MOCK_METHOD(std::string, state, (), (const, override));
        MOCK_METHOD(int, ppid, (), (const, override));
        MOCK_METHOD(unsigned long long, utime, (), (const, override));
        MOCK_METHOD(unsigned long long, stime, (), (const, override));
        MOCK_METHOD(std::string, cmd, (), (const, override));
        MOCK_METHOD(std::string, argvs, (), (const, override));
        MOCK_METHOD(std::string, euser, (), (const, override));
        MOCK_METHOD(std::string, ruser, (), (const, override));
        MOCK_METHOD(std::string, suser, (), (const, override));
        MOCK_METHOD(std::string, egroup, (), (const, override));
        MOCK_METHOD(std::string, rgroup, (), (const, override));
        MOCK_METHOD(std::string, sgroup, (), (const, override));
        MOCK_METHOD(std::string, fgroup, (), (const, override));
        MOCK_METHOD(long, priority, (), (const, override));
        MOCK_METHOD(long, nice, (), (const, override));
        MOCK_METHOD(long, size, (), (const, override));
        MOCK_METHOD(unsigned long, vm_size, (), (const, override));
        MOCK_METHOD(long, resident, (), (const, override));
        MOCK_METHOD(long, share, (), (const, override));
        MOCK_METHOD(unsigned long long, startTime, (), (const, override));
        MOCK_METHOD(int, pgrp, (), (const, override));
        MOCK_METHOD(int, session, (), (const, override));
        MOCK_METHOD(int, nlwp, (), (const, override));
        MOCK_METHOD(int, tgid, (), (const, override));
        MOCK_METHOD(int, tty, (), (const, override));
        MOCK_METHOD(int, processor, (), (const, override));
};

/**
 * @brief Test success from ttymon Solaris process
 *
 */

ACTION_P(getCmd, fullCmdLine)
{
    std::string retVal(fullCmdLine);
    const auto spacePos = retVal.find(' ');

    if (spacePos != std::string::npos)
    {
        retVal = retVal.substr(0, spacePos);
    }

    return retVal;
}

ACTION_P(getArgvs, fullCmdLine)
{
    std::string retVal;
    std::string argsString(fullCmdLine);
    const auto spacePos = argsString.find(' ');

    if (spacePos != std::string::npos)
    {
        retVal = argsString.substr(spacePos + 1);
    }

    return retVal;
}

TEST_F(SysInfoSolarisProcessesTest, TestSuccessData1)
{
    nlohmann::json Processes{};
    psinfo_t psinfo;
    pstatus_t status;
    prcred_t cred;

    // the injected data was extracted from a real solaris terminal
    std::memcpy(&psinfo, psinfo985.data(), sizeof psinfo);
    std::memcpy(&status, status985.data(), sizeof status);
    std::memcpy(&cred, cred985.data(), sizeof cred);

    const auto mock{std::make_shared<sysInfoProcessSolarisWrapperMock>(psinfo, status, cred)};

    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(std::to_string(psinfo.pr_pid)));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return(std::string(psinfo.pr_fname)));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::string(1, psinfo.pr_lwp.pr_sname)));
    EXPECT_CALL(*mock, ppid()).Times(1).WillOnce(Return(psinfo.pr_ppid));
    EXPECT_CALL(*mock, utime()).Times(1).WillOnce(Return(status.pr_utime.tv_sec));
    EXPECT_CALL(*mock, stime()).Times(1).WillOnce(Return(status.pr_stime.tv_sec));
    EXPECT_CALL(*mock, cmd()).Times(1).WillOnce(getCmd(psinfo.pr_psargs));
    EXPECT_CALL(*mock, argvs()).Times(1).WillOnce(getArgvs(psinfo.pr_psargs));
    EXPECT_CALL(*mock, euser()).Times(1).WillOnce(Return(std::to_string(cred.pr_euid)));
    EXPECT_CALL(*mock, ruser()).Times(1).WillOnce(Return(std::to_string(cred.pr_ruid)));
    EXPECT_CALL(*mock, suser()).Times(1).WillOnce(Return(std::to_string(cred.pr_suid)));
    EXPECT_CALL(*mock, egroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_egid)));
    EXPECT_CALL(*mock, rgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_rgid)));
    EXPECT_CALL(*mock, sgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, fgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, priority()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z') ? psinfo.pr_lwp.pr_pri : -1L));
    EXPECT_CALL(*mock, nice()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z' && psinfo.pr_lwp.pr_oldpri != 0) ? psinfo.pr_lwp.pr_nice : -1L));
    EXPECT_CALL(*mock, size()).Times(1).WillOnce(Return(psinfo.pr_size / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, vm_size()).Times(1).WillOnce(Return(psinfo.pr_size));
    EXPECT_CALL(*mock, resident()).Times(1).WillOnce(Return(psinfo.pr_rssize / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, share()).Times(1).WillOnce(Return(-1L));
    EXPECT_CALL(*mock, startTime()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_start.tv_sec));
    EXPECT_CALL(*mock, pgrp()).Times(1).WillOnce(Return(psinfo.pr_pgid));
    EXPECT_CALL(*mock, session()).Times(1).WillOnce(Return(psinfo.pr_sid));
    EXPECT_CALL(*mock, nlwp()).Times(1).WillOnce(Return(psinfo.pr_nlwp + psinfo.pr_nzomb));
    EXPECT_CALL(*mock, tgid()).Times(1).WillOnce(Return(psinfo.pr_taskid));
    EXPECT_CALL(*mock, tty()).Times(1).WillOnce(Return(psinfo.pr_ttydev == PRNODEV ? 0 : psinfo.pr_ttydev));
    EXPECT_CALL(*mock, processor()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_cpu));

    EXPECT_NO_THROW(FactoryProcessFamilyCreator<OSType::SOLARIS>::create(mock)->buildProcessData(Processes));

    EXPECT_EQ("985", Processes.at("pid").get_ref<const std::string&>());
    EXPECT_EQ("ttymon", Processes.at("name").get_ref<const std::string&>());
    EXPECT_EQ("S", Processes.at("state").get_ref<const std::string&>());
    EXPECT_EQ(13, Processes.at("ppid").get<const int>());
    EXPECT_EQ(0, Processes.at("utime").get<const unsigned long long>());
    EXPECT_EQ(0, Processes.at("stime").get<const unsigned long long>());
    EXPECT_EQ("/usr/sbin/ttymon", Processes.at("cmd").get_ref<const std::string&>());
    EXPECT_EQ("-g -d /dev/vt/5 -l console -m ldterm,ttcompat -h -p solaris vt",
              Processes.at("argvs").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("euser").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("ruser").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("suser").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("egroup").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("rgroup").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("sgroup").get_ref<const std::string&>());
    EXPECT_EQ("0", Processes.at("fgroup").get_ref<const std::string&>());
    EXPECT_EQ(985, Processes.at("pgrp").get<const int>());
    EXPECT_EQ(59, Processes.at("priority").get<const long>());
    EXPECT_EQ(0, Processes.at("processor").get<const int>());
    EXPECT_EQ(2, Processes.at("resident").get<const long>());
    EXPECT_EQ(985, Processes.at("session").get<const int>());
    EXPECT_EQ(-1, Processes.at("share").get<const long>());
    EXPECT_EQ(691, Processes.at("size").get<const long>());
    EXPECT_EQ(1678705551, Processes.at("start_time").get<const long>());
    EXPECT_EQ(148, Processes.at("tgid").get<const int>());
    EXPECT_EQ(71041029, Processes.at("tty").get<const int>());
    EXPECT_EQ(2764, Processes.at("vm_size").get<unsigned long>());
}

/**
 * @brief Test success from wazuh-agentd Solaris process
 *
 */
TEST_F(SysInfoSolarisProcessesTest, TestSuccessData2)
{
    nlohmann::json Processes{};
    psinfo_t psinfo;
    pstatus_t status;
    prcred_t cred;

    // the injected data was extracted from a real solaris terminal
    std::memcpy(&psinfo, psinfo1395.data(), sizeof psinfo);
    std::memcpy(&status, status1395.data(), sizeof status);
    std::memcpy(&cred, cred1395.data(), sizeof cred);

    const auto mock{std::make_shared<sysInfoProcessSolarisWrapperMock>(psinfo, status, cred)};

    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(std::to_string(psinfo.pr_pid)));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return(std::string(psinfo.pr_fname)));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::string(1, psinfo.pr_lwp.pr_sname)));
    EXPECT_CALL(*mock, ppid()).Times(1).WillOnce(Return(psinfo.pr_ppid));
    EXPECT_CALL(*mock, utime()).Times(1).WillOnce(Return(status.pr_utime.tv_sec));
    EXPECT_CALL(*mock, stime()).Times(1).WillOnce(Return(status.pr_stime.tv_sec));
    EXPECT_CALL(*mock, cmd()).Times(1).WillOnce(getCmd(psinfo.pr_psargs));
    EXPECT_CALL(*mock, argvs()).Times(1).WillOnce(getArgvs(psinfo.pr_psargs));
    EXPECT_CALL(*mock, euser()).Times(1).WillOnce(Return(std::to_string(cred.pr_euid)));
    EXPECT_CALL(*mock, ruser()).Times(1).WillOnce(Return(std::to_string(cred.pr_ruid)));
    EXPECT_CALL(*mock, suser()).Times(1).WillOnce(Return(std::to_string(cred.pr_suid)));
    EXPECT_CALL(*mock, egroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_egid)));
    EXPECT_CALL(*mock, rgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_rgid)));
    EXPECT_CALL(*mock, sgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, fgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, priority()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z') ? psinfo.pr_lwp.pr_pri : -1L));
    EXPECT_CALL(*mock, nice()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z' && psinfo.pr_lwp.pr_oldpri != 0) ? psinfo.pr_lwp.pr_nice : -1L));
    EXPECT_CALL(*mock, size()).Times(1).WillOnce(Return(psinfo.pr_size / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, vm_size()).Times(1).WillOnce(Return(psinfo.pr_size));
    EXPECT_CALL(*mock, resident()).Times(1).WillOnce(Return(psinfo.pr_rssize / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, share()).Times(1).WillOnce(Return(-1L));
    EXPECT_CALL(*mock, startTime()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_start.tv_sec));
    EXPECT_CALL(*mock, pgrp()).Times(1).WillOnce(Return(psinfo.pr_pgid));
    EXPECT_CALL(*mock, session()).Times(1).WillOnce(Return(psinfo.pr_sid));
    EXPECT_CALL(*mock, nlwp()).Times(1).WillOnce(Return(psinfo.pr_nlwp + psinfo.pr_nzomb));
    EXPECT_CALL(*mock, tgid()).Times(1).WillOnce(Return(psinfo.pr_taskid));
    EXPECT_CALL(*mock, tty()).Times(1).WillOnce(Return(psinfo.pr_ttydev == PRNODEV ? 0 : psinfo.pr_ttydev));
    EXPECT_CALL(*mock, processor()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_cpu));

    EXPECT_NO_THROW(FactoryProcessFamilyCreator<OSType::SOLARIS>::create(mock)->buildProcessData(Processes));

    EXPECT_EQ("1395", Processes.at("pid").get_ref<const std::string&>());
    EXPECT_EQ("wazuh-agentd", Processes.at("name").get_ref<const std::string&>());
    EXPECT_EQ("S", Processes.at("state").get_ref<const std::string&>());
    EXPECT_EQ(1, Processes.at("ppid").get<const int>());
    EXPECT_EQ(1, Processes.at("utime").get<const unsigned long long>());
    EXPECT_EQ(2, Processes.at("stime").get<const unsigned long long>());
    EXPECT_EQ("/var/ossec/bin/wazuh-agentd", Processes.at("cmd").get_ref<const std::string&>());
    EXPECT_EQ("", Processes.at("argvs").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("egroup").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("fgroup").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("sgroup").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("rgroup").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("euser").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("suser").get_ref<const std::string&>());
    EXPECT_EQ("100", Processes.at("ruser").get_ref<const std::string&>());
    EXPECT_EQ(1394, Processes.at("pgrp").get<const int>());
    EXPECT_EQ(59, Processes.at("priority").get<const long>());
    EXPECT_EQ(0, Processes.at("processor").get<const int>());
    EXPECT_EQ(724, Processes.at("resident").get<const long>());
    EXPECT_EQ(1394, Processes.at("session").get<const int>());
    EXPECT_EQ(-1, Processes.at("share").get<const long>());
    EXPECT_EQ(2993, Processes.at("size").get<const long>());
    EXPECT_EQ(1678705582, Processes.at("start_time").get<const long>());
    EXPECT_EQ(135, Processes.at("tgid").get<const int>());
    EXPECT_EQ(0, Processes.at("tty").get<const int>());
    EXPECT_EQ(11972, Processes.at("vm_size").get<unsigned long>());
}

/**
 * @brief Test success no data available
 *
 */
TEST_F(SysInfoSolarisProcessesTest, TestSuccessNoData)
{
    nlohmann::json Processes{};
    psinfo_t psinfo {};
    pstatus_t status {};
    prcred_t cred {};

    const auto EMPTY_PROCCESSES =
        R"({"argvs":"","cmd":"","egroup":"0","euser":"0","fgroup":"0","name":"","nice":-1,
        "nlwp":0,"pgrp":0,"pid":"0","ppid":0,"priority":0,"processor":0,"resident":0,
        "rgroup":"0","ruser":"0","session":0,"sgroup":"0","share":-1,"size":0,
        "start_time":0,"state":"\u0000","stime":0,"suser":"0","tgid":0,"tty":0,"utime":0,"vm_size":0})"_json;

    const auto mock{std::make_shared<sysInfoProcessSolarisWrapperMock>(psinfo, status, cred)};

    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(std::to_string(psinfo.pr_pid)));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return(std::string(psinfo.pr_fname)));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::string(1, psinfo.pr_lwp.pr_sname)));
    EXPECT_CALL(*mock, ppid()).Times(1).WillOnce(Return(psinfo.pr_ppid));
    EXPECT_CALL(*mock, utime()).Times(1).WillOnce(Return(status.pr_utime.tv_sec));
    EXPECT_CALL(*mock, stime()).Times(1).WillOnce(Return(status.pr_stime.tv_sec));
    EXPECT_CALL(*mock, cmd()).Times(1).WillOnce(getCmd(psinfo.pr_psargs));
    EXPECT_CALL(*mock, argvs()).Times(1).WillOnce(getArgvs(psinfo.pr_psargs));
    EXPECT_CALL(*mock, euser()).Times(1).WillOnce(Return(std::to_string(cred.pr_euid)));
    EXPECT_CALL(*mock, ruser()).Times(1).WillOnce(Return(std::to_string(cred.pr_ruid)));
    EXPECT_CALL(*mock, suser()).Times(1).WillOnce(Return(std::to_string(cred.pr_suid)));
    EXPECT_CALL(*mock, egroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_egid)));
    EXPECT_CALL(*mock, rgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_rgid)));
    EXPECT_CALL(*mock, sgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, fgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, priority()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z') ? psinfo.pr_lwp.pr_pri : -1L));
    EXPECT_CALL(*mock, nice()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z' && psinfo.pr_lwp.pr_oldpri != 0) ? psinfo.pr_lwp.pr_nice : -1L));
    EXPECT_CALL(*mock, size()).Times(1).WillOnce(Return(psinfo.pr_size / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, vm_size()).Times(1).WillOnce(Return(psinfo.pr_size));
    EXPECT_CALL(*mock, resident()).Times(1).WillOnce(Return(psinfo.pr_rssize / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, share()).Times(1).WillOnce(Return(-1L));
    EXPECT_CALL(*mock, startTime()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_start.tv_sec));
    EXPECT_CALL(*mock, pgrp()).Times(1).WillOnce(Return(psinfo.pr_pgid));
    EXPECT_CALL(*mock, session()).Times(1).WillOnce(Return(psinfo.pr_sid));
    EXPECT_CALL(*mock, nlwp()).Times(1).WillOnce(Return(psinfo.pr_nlwp + psinfo.pr_nzomb));
    EXPECT_CALL(*mock, tgid()).Times(1).WillOnce(Return(psinfo.pr_taskid));
    EXPECT_CALL(*mock, tty()).Times(1).WillOnce(Return(psinfo.pr_ttydev == PRNODEV ? 0 : psinfo.pr_ttydev));
    EXPECT_CALL(*mock, processor()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_cpu));

    EXPECT_NO_THROW(FactoryProcessFamilyCreator<OSType::SOLARIS>::create(mock)->buildProcessData(Processes));

    EXPECT_EQ(EMPTY_PROCCESSES, Processes);
}

/**
* @brief Test wrong data
*
*/
TEST_F(SysInfoSolarisProcessesTest, TestNullPtr)
{
    nlohmann::json Processes{};
    EXPECT_ANY_THROW(FactoryProcessFamilyCreator<OSType::SOLARIS>::create(nullptr)->buildProcessData(Processes));
}

/**
* @brief Test wrong data
*
*/
TEST_F(SysInfoSolarisProcessesTest, TestUnspectedNice)
{
    nlohmann::json Processes{};
    psinfo_t psinfo {};
    pstatus_t status {};
    prcred_t cred {};

    const auto EMPTY_PROCCESSES =
        R"({"argvs":"","cmd":"","egroup":"0","euser":"0","fgroup":"0","name":"","nice":-1,
        "nlwp":0,"pgrp":0,"pid":"0","ppid":0,"priority":0,"processor":0,"resident":0,
        "rgroup":"0","ruser":"0","session":0,"sgroup":"0","share":-1,"size":0,
        "start_time":0,"state":"\u0000","stime":0,"suser":"0","tgid":0,"tty":0,"utime":0,"vm_size":0})"_json;

    const auto mock{std::make_shared<sysInfoProcessSolarisWrapperMock>(psinfo, status, cred)};

    EXPECT_CALL(*mock, share()).Times(1).WillOnce(Return(0L));

    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(std::to_string(psinfo.pr_pid)));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return(std::string(psinfo.pr_fname)));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::string(1, psinfo.pr_lwp.pr_sname)));
    EXPECT_CALL(*mock, ppid()).Times(1).WillOnce(Return(psinfo.pr_ppid));
    EXPECT_CALL(*mock, utime()).Times(1).WillOnce(Return(status.pr_utime.tv_sec));
    EXPECT_CALL(*mock, stime()).Times(1).WillOnce(Return(status.pr_stime.tv_sec));
    EXPECT_CALL(*mock, cmd()).Times(1).WillOnce(getCmd(psinfo.pr_psargs));
    EXPECT_CALL(*mock, argvs()).Times(1).WillOnce(getArgvs(psinfo.pr_psargs));
    EXPECT_CALL(*mock, euser()).Times(1).WillOnce(Return(std::to_string(cred.pr_euid)));
    EXPECT_CALL(*mock, ruser()).Times(1).WillOnce(Return(std::to_string(cred.pr_ruid)));
    EXPECT_CALL(*mock, suser()).Times(1).WillOnce(Return(std::to_string(cred.pr_suid)));
    EXPECT_CALL(*mock, egroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_egid)));
    EXPECT_CALL(*mock, rgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_rgid)));
    EXPECT_CALL(*mock, sgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, fgroup()).Times(1).WillOnce(Return(std::to_string(cred.pr_sgid)));
    EXPECT_CALL(*mock, priority()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z') ? psinfo.pr_lwp.pr_pri : -1L));
    EXPECT_CALL(*mock, nice()).Times(1).WillOnce(Return((psinfo.pr_lwp.pr_sname != 'Z' && psinfo.pr_lwp.pr_oldpri != 0) ? psinfo.pr_lwp.pr_nice : -1L));
    EXPECT_CALL(*mock, size()).Times(1).WillOnce(Return(psinfo.pr_size / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, vm_size()).Times(1).WillOnce(Return(psinfo.pr_size));
    EXPECT_CALL(*mock, resident()).Times(1).WillOnce(Return(psinfo.pr_rssize / KBYTES_PER_PAGE));
    EXPECT_CALL(*mock, startTime()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_start.tv_sec));
    EXPECT_CALL(*mock, pgrp()).Times(1).WillOnce(Return(psinfo.pr_pgid));
    EXPECT_CALL(*mock, session()).Times(1).WillOnce(Return(psinfo.pr_sid));
    EXPECT_CALL(*mock, nlwp()).Times(1).WillOnce(Return(psinfo.pr_nlwp + psinfo.pr_nzomb));
    EXPECT_CALL(*mock, tgid()).Times(1).WillOnce(Return(psinfo.pr_taskid));
    EXPECT_CALL(*mock, tty()).Times(1).WillOnce(Return(psinfo.pr_ttydev == PRNODEV ? 0 : psinfo.pr_ttydev));
    EXPECT_CALL(*mock, processor()).Times(1).WillOnce(Return(psinfo.pr_lwp.pr_cpu));

    EXPECT_NO_THROW(FactoryProcessFamilyCreator<OSType::SOLARIS>::create(mock)->buildProcessData(Processes));

    EXPECT_NE(EMPTY_PROCCESSES, Processes);
}
