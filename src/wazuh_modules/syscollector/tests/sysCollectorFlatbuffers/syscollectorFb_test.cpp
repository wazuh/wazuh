/*
 * Wazuh SyscollectorFlatbuffers
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollectorFb_test.h"

const std::string syscollector_message {SCHEMA_ROOT_PATH "syscollector_synchronization.fbs"};
const char* INCLUDE_DIRECTORIES[] = { SCHEMA_ROOT_PATH, nullptr };

void SyscollectorFbTest::SetUp() {};

void SyscollectorFbTest::TearDown() {};

TEST(SyscollectorFbTest, JSONParsePackageUnix)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_packages\",\n    attributes: {\n      architecture: \"amd64\",\n      checksum: \"409378153d05da4d49900316be982e575cb2586b\",\n      description: \"GNU C++ compiler for MinGW-w64 targeting Win64\",\n      type: \"deb\",\n      category: \"devel\",\n      name: \"g++-mingw-w64-x86-64\",\n      priority: \"optional\",\n      size: 155993,\n      source: \"gcc-mingw-w64 (22~exp1ubuntu4)\",\n      vendor: \"Stephen Kitt <skitt@debian.org>\",\n      version: \"9.3.0-7ubuntu1+22~exp1ubuntu4\"\n    },\n    index: \"65a25b9b9fe7cb173aa5cc36dc437d9875af8a8e\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParsePackageWin)
{
    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_packages\",\n    attributes: {\n      checksum: \"9141d4744f95aad5db1cf8cf17c33c2f7dffed40\",\n      type: \"win\",\n      installed: \"20230804\",\n      path: \"C:\\\\Users\\\\winuser\\\\AppData\\\\Local\\\\Microsoft\\\\Amazing\\\\Application\",\n      name: \"Microsoft Application Amazing Runtime\",\n      vendor: \"Microsoft Application Amazing\",\n      version: \"110.110.110.10.10\"\n    },\n    index: \"e8cc756531b3adaae0e8a51c6800a681f4e903aa\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseHotfix)
{
    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_hotfixes\",\n    attributes: {\n      checksum: \"5cfcee837ce896ef9229da1064b2844439ff3cc6\",\n      hotfix_name: \"KB5026037\",\n    },\n    index: \"KB5026037\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseProcessUnix)
{
    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_processes\",\n    attributes: {\n      checksum: \"bc425a0d5337df58bd60e54fdb889fbf370d425a\",\n      name: \"writeback\",\n      pid: \"39\",\n      parent_pid: 2,\n      start: 1691513206,\n      state: \"I\",\n    },\n    index: \"39\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseProcessWin)
{
    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_processes\",\n    attributes: {\n      checksum: \"62abb948062c25a4065b35b17746ae2442e850d1\",\n      command_line: \"C:\\\\Windows\\\\System32\\\\svchost.exe\",\n      name: \"svchost.exe\",\n      pid: \"1328\",\n      parent_pid: 680,\n      start: 1686590435,\n    },\n    index: \"1328\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParsePortsUnix)
{
    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_ports\",\n    attributes: {\n      checksum: \"02d4570c4cf94ba0f79c34e8a52216fddf73a39a\",\n      file_inode: 42468,\n      source_ip: \"192.168.0.10\",\n      source_port: 37990,\n      network_transport: \"udp\",\n      destination_ip: \"192.168.0.30\",\n      destination_port: 1514,\n    },\n    index: \"cb8f094adf3aeb9630f2f51d1beeb5472eb0a8fb\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParsePortsWin)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_ports\",\n    attributes: {\n      checksum: \"02d4570c4cf94ba0f79c34e8a52216fddf73a39a\",\n      file_inode: 42468,\n      source_ip: \"192.168.0.10\",\n      source_port: 37990,\n      network_transport: \"udp\",\n      destination_ip: \"192.168.0.30\",\n      destination_port: 1514,\n      interface_state: \"\"\n    },\n    index: \"cb8f094adf3aeb9630f2f51d1beeb5472eb0a8fb\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseHwInfo)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_hwinfo\",\n    attributes: {\n      serial_number: \"0\",\n      checksum: \"5675de235c09762beb0357a54024987ed0c70fd6\",\n      cpu_cores: 4,\n      cpu_speed: 24970.0,\n      cpu_name: \"Amazing(R) Core(TM) i45-10000H CPU @ 25.00GHz\",\n      memory_free: 33603480,\n      memory_total: 40133680,\n    },\n    index: \"0\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseOsInfo)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_osinfo\",\n    attributes: {\n      checksum: \"1691513227478039559\",\n      hostname: \"Supercomputer\",\n      os_codename: \"focal\",\n      os_major: \"200\",\n      os_minor: \"000\",\n      os_name: \"Wazuh OS\",\n      os_patch: \"2\",\n      os_platform: \"bsd\",\n      os_version: \"200.000.2\",\n      os_kernel_release: \"5.4.0-153-generic\",\n      os_kernel_name: \"Linux\",\n      os_kernel_version: \"#170-WazuhOS SMP Fri Jun 16 13:43:31 UTC 2023\"\n    },\n    index: \"WazuhOS\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseNetAddr)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_network_address\",\n    attributes: {\n      network_ip: \"192.168.0.1\",\n      network_broadcast: \"192.168.0.255\",\n      checksum: \"c3794bf303c6229bcb40d4070b9820ac4902bd07\",\n      interface_name: \"enp0s3\",\n      network_netmask: \"255.255.255.0\",\n    },\n    index: \"b79437e85675afeeea2b4e141aca26b27cdcc959\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseNetItf)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_network_iface\",\n    attributes: {\n      checksum: \"92a69b6285431e7d67da91e5006d23246628f13c\",\n      host_mac: \"XX:XX:XX:XX:XX:XX\",\n      interface_mtu: 1500,\n      interface_name: \"enp0s3\",\n      host_network_ingress_bytes: 255555,\n      host_network_ingress_drops: 255555,\n      host_network_ingress_errors: 255555,\n      host_network_ingress_packages: 255555,\n      interface_state: \"up\",\n      host_network_egress_bytes: 255555,\n      host_network_egress_drops: 255555,\n      host_network_egress_errors: 255555,\n      host_network_egress_packages: 255555,\n      interface_type: \"quantic_fiber\"\n    },\n    index: \"7a60750dd3c25c53f21ff7f44b4743664ddbb66a\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONParseNetItfNegativeValues)
{
    // Syscollector network interface_name can send negative values for some fields. This test is to avoid reverting the changes in the flatbuffer schema.
    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"state\",\n  data: {\n    attributes_type: \"syscollector_network_iface\",\n    attributes: {\n      checksum: \"92a69b6285431e7d67da91e5006d23246628f13c\",\n      host_mac: \"XX:XX:XX:XX:XX:XX\",\n      interface_mtu: -1,\n      interface_name: \"enp0s3\",\n      host_network_ingress_bytes: -255555,\n      host_network_ingress_drops: -255555,\n      host_network_ingress_errors: -255555,\n      host_network_ingress_packages: -255555,\n      interface_state: \"up\",\n      host_network_egress_bytes: -255555,\n      host_network_egress_drops: -255555,\n      host_network_egress_errors: -255555,\n      host_network_egress_packages: -255555,\n      interface_type: \"quantic_fiber\"\n    },\n    index: \"7a60750dd3c25c53f21ff7f44b4743664ddbb66a\",\n    timestamp: \"\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONIntegrityGlobal)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"integrity_check_left\",\n  data: {\n    attributes_type: \"syscollector_network_iface\",\n    id: 123456789,\n    begin: \"73fe1533b96d4e81b56e13df4f25a0684b473de7\",\n    end: \"73fe1533b96d4e81b56e13df4f25a0684b473de7\",\n    checksum: \"92a69b6285431e7d67da91e5006d23246628f13c\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONIntegrityRight)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"integrity_check_right\",\n  data: {\n    attributes_type: \"syscollector_network_iface\",\n    id: 123456789,\n    begin: \"73fe1533b96d4e81b56e13df4f25a0684b473de7\",\n    end: \"73fe1533b96d4e81b56e13df4f25a0684b473de7\",\n    checksum: \"92a69b6285431e7d67da91e5006d23246628f13c\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, JSONIntegrityLeft)
{

    const std::string alert_json =
        "{\n  agent_info: {\n    agent_id: \"001\"\n  },\n  data_type: \"integrity_check_left\",\n  data: {\n    attributes_type: \"syscollector_network_iface\",\n    id: 123456789,\n    begin: \"73fe1533b96d4e81b56e13df4f25a0684b473de7\",\n    end: \"73fe1533b96d4e81b56e13df4f25a0684b473de7\",\n    tail: \"92a69b6285431e7d67da91e5006d23246628f13c\",\n    checksum: \"92a69b6285431e7d67da91e5006d23246628f13c\"\n  }\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(syscollector_message.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str(), INCLUDE_DIRECTORIES) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}
