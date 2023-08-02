/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollectorFb_test.h"

constexpr auto SYNC_HMSG_TEST_PATH {"sync_hmsg.mom"};
constexpr auto SYNC_PMSG_TEST_PATH {"sync_pmsg.mom"};

constexpr auto COMPONENT {"syscollector"};
constexpr auto TYPE {"state"};

void SyscollectorFbTest::SetUp() {};

void SyscollectorFbTest::TearDown() {};

TEST(SyscollectorFbTest, createBinaryHotfix)
{
  flatbuffers::FlatBufferBuilder builder;

  auto component = builder.CreateString(COMPONENT);
  auto type = builder.CreateString(TYPE);

  auto checksum = builder.CreateString("md5sha1md5sha1");
  auto hotfix = builder.CreateString("KBXXXXX");
  auto scan_time = builder.CreateString("00");

  auto data = CreateHotfixAttribute(builder, checksum, hotfix, scan_time);

  auto index = builder.CreateString("00");
  auto timestamp = builder.CreateString("00/00/0000T00:00:00.000");

  auto hotfixData = CreateHotfixData(builder, data, index, timestamp);


  auto sync_msg = CreateSyncMsg(builder, component, Data_HotfixData, hotfixData.Union() , type);

  builder.Finish(sync_msg);

  uint8_t *buf = builder.GetBufferPointer();
  int size = builder.GetSize();

  std::ofstream ofile(SYNC_HMSG_TEST_PATH, std::ios::binary);
  ofile.write((char *)buf, size);
  ofile.close();
}

TEST(SyscollectorFbTest, readBinaryHotfix)
{
  std::ifstream infile;
	infile.open(SYNC_HMSG_TEST_PATH, std::ios::binary | std::ios::in);
	infile.seekg(0, std::ios::end);
	int length = infile.tellg();
	infile.seekg(0, std::ios::beg);
	char* raw_data = new char[length];
	infile.read(raw_data, length);
	infile.close();

  auto sync_msg = GetSyncMsg(raw_data);

  EXPECT_STREQ(sync_msg->component()->c_str(),COMPONENT);
  EXPECT_STREQ(sync_msg->type()->c_str(),TYPE);
  EXPECT_EQ(sync_msg->data_type(),Data_HotfixData);

  auto data = static_cast<const HotfixData*>(sync_msg->data());

  EXPECT_STREQ(data->index()->c_str(),"00");
  EXPECT_STREQ(data->timestamp()->c_str(),"00/00/0000T00:00:00.000");
  EXPECT_STREQ(data->data()->checksum()->c_str(),"md5sha1md5sha1");
  EXPECT_STREQ(data->data()->hotfix()->c_str(),"KBXXXXX");
  EXPECT_STREQ(data->data()->scan_time()->c_str(),"00");

  std::remove(SYNC_HMSG_TEST_PATH);
}

TEST(SyscollectorFbTest, createBinaryPackageUnix)
{
  flatbuffers::FlatBufferBuilder builder;

  auto component = builder.CreateString(COMPONENT);
  auto type = builder.CreateString(TYPE);

  auto architecture = builder.CreateString("x86");
  auto checksum = builder.CreateString("md5sha1md5sha1");
  auto description = builder.CreateString("Nice");
  auto format = builder.CreateString("UTF-8");
  auto install_time = builder.CreateString(nullptr,0);
  auto groups = builder.CreateString("wazuh");
  auto item_id = builder.CreateString("00");
  auto multiarch = builder.CreateString("yes");
  auto name = builder.CreateString("NicePackage");
  auto location = builder.CreateString("\\home");
  auto priority = builder.CreateString("01");
  auto scan_time = builder.CreateString("00/00/0000T00:00:00.000");
  auto size_attr = 1;
  auto source = builder.CreateString("wazuh");
  auto vendor = builder.CreateString("wazuh");
  auto version = builder.CreateString("v1");

  auto data = CreatePackageAttribute(
                                      builder,
                                      architecture,
                                      checksum,
                                      description,
                                      format,
                                      install_time,
                                      groups,
                                      item_id,
                                      multiarch,
                                      name,
                                      location,
                                      priority,
                                      scan_time,
                                      size_attr,
                                      source,
                                      vendor,
                                      version);

  auto index = builder.CreateString("00");
  auto timestamp = builder.CreateString("00/00/0000T00:00:00.000");

  auto packageData = CreatePackageData(builder, data, index, timestamp);

  auto sync_msg = CreateSyncMsg(builder, component, Data_PackageData, packageData.Union() , type);

  builder.Finish(sync_msg);

  uint8_t *buf = builder.GetBufferPointer();
  int size = builder.GetSize();

  std::ofstream ofile(SYNC_PMSG_TEST_PATH, std::ios::binary);
  ofile.write((char *)buf, size);
  ofile.close();
}

TEST(SyscollectorFbTest, readBinaryPackageUnix)
{
  std::ifstream infile;
	infile.open(SYNC_PMSG_TEST_PATH, std::ios::binary | std::ios::in);
	infile.seekg(0, std::ios::end);
	int length = infile.tellg();
	infile.seekg(0, std::ios::beg);
	char* raw_data = new char[length];
	infile.read(raw_data, length);
	infile.close();

  auto sync_msg = GetSyncMsg(raw_data);

  EXPECT_STREQ(sync_msg->component()->c_str(),COMPONENT);
  EXPECT_STREQ(sync_msg->type()->c_str(),TYPE);
  EXPECT_EQ(sync_msg->data_type(),Data_PackageData);

  auto data = static_cast<const PackageData*>(sync_msg->data());

  EXPECT_STREQ(data->index()->c_str(),"00");
  EXPECT_STREQ(data->timestamp()->c_str(),"00/00/0000T00:00:00.000");
  EXPECT_STREQ(data->data()->architecture()->c_str(),"x86");
  EXPECT_STREQ(data->data()->checksum()->c_str(),"md5sha1md5sha1");
  EXPECT_STREQ(data->data()->description()->c_str(),"Nice");
  EXPECT_STREQ(data->data()->format()->c_str(),"UTF-8");
  EXPECT_STREQ(data->data()->install_time()->c_str(),"");
  EXPECT_STREQ(data->data()->groups()->c_str(),"wazuh");
  EXPECT_STREQ(data->data()->item_id()->c_str(),"00");
  EXPECT_STREQ(data->data()->multiarch()->c_str(),"yes");
  EXPECT_STREQ(data->data()->name()->c_str(),"NicePackage");
  EXPECT_STREQ(data->data()->location()->c_str(),"\\home");
  EXPECT_STREQ(data->data()->priority()->c_str(),"01");
  EXPECT_STREQ(data->data()->scan_time()->c_str(),"00/00/0000T00:00:00.000");
  EXPECT_EQ(data->data()->size(),1);
  EXPECT_STREQ(data->data()->source()->c_str(),"wazuh");
  EXPECT_STREQ(data->data()->vendor()->c_str(),"wazuh");
  EXPECT_STREQ(data->data()->version()->c_str(),"v1");

  std::remove(SYNC_PMSG_TEST_PATH);
}

TEST(SyscollectorFbTest, createBinaryPackageWindows)
{
  flatbuffers::FlatBufferBuilder builder;

  auto component = builder.CreateString(COMPONENT);
  auto type = builder.CreateString(TYPE);

  auto architecture = builder.CreateString("x86");
  auto checksum = builder.CreateString("md5sha1md5sha1");
  auto description = builder.CreateString(nullptr,0);
  auto format = builder.CreateString("UTF-8");
  auto install_time = builder.CreateString("00/00/0000T00:00:00.000");
  auto groups = builder.CreateString(nullptr,0);
  auto item_id = builder.CreateString("00");
  auto multiarch = builder.CreateString(nullptr,0);
  auto name = builder.CreateString("NicePackage");
  auto location = builder.CreateString("\\home");
  auto priority = builder.CreateString(nullptr,0);
  auto scan_time = builder.CreateString("00/00/0000T00:00:00.000");
  auto size_attr = 0;
  auto source = builder.CreateString("wazuh");
  auto vendor = builder.CreateString("wazuh");
  auto version = builder.CreateString("v1");

  auto data = CreatePackageAttribute(
                                      builder,
                                      architecture,
                                      checksum,
                                      description,
                                      format,
                                      install_time,
                                      groups,
                                      item_id,
                                      multiarch,
                                      name,
                                      location,
                                      priority,
                                      scan_time,
                                      size_attr,
                                      source,
                                      vendor,
                                      version);

  auto index = builder.CreateString("00");
  auto timestamp = builder.CreateString("00/00/0000T00:00:00.000");

  auto packageData = CreatePackageData(builder, data, index, timestamp);

  auto sync_msg = CreateSyncMsg(builder, component, Data_PackageData, packageData.Union() , type);

  builder.Finish(sync_msg);

  uint8_t *buf = builder.GetBufferPointer();
  int size = builder.GetSize();

  std::ofstream ofile(SYNC_PMSG_TEST_PATH, std::ios::binary);
  ofile.write((char *)buf, size);
  ofile.close();
}

TEST(SyscollectorFbTest, readBinaryPackageWindows)
{
  std::ifstream infile;
	infile.open(SYNC_PMSG_TEST_PATH, std::ios::binary | std::ios::in);
	infile.seekg(0, std::ios::end);
	int length = infile.tellg();
	infile.seekg(0, std::ios::beg);
	char* raw_data = new char[length];
	infile.read(raw_data, length);
	infile.close();

  auto sync_msg = GetSyncMsg(raw_data);

  EXPECT_STREQ(sync_msg->component()->c_str(),COMPONENT);
  EXPECT_STREQ(sync_msg->type()->c_str(),TYPE);
  EXPECT_EQ(sync_msg->data_type(),Data_PackageData);

  auto data = static_cast<const PackageData*>(sync_msg->data());

  EXPECT_STREQ(data->index()->c_str(),"00");
  EXPECT_STREQ(data->timestamp()->c_str(),"00/00/0000T00:00:00.000");
  EXPECT_STREQ(data->data()->architecture()->c_str(),"x86");
  EXPECT_STREQ(data->data()->checksum()->c_str(),"md5sha1md5sha1");
  EXPECT_STREQ(data->data()->description()->c_str(),"");
  EXPECT_STREQ(data->data()->format()->c_str(),"UTF-8");
  EXPECT_STREQ(data->data()->install_time()->c_str(),"00/00/0000T00:00:00.000");
  EXPECT_STREQ(data->data()->groups()->c_str(),"");
  EXPECT_STREQ(data->data()->item_id()->c_str(),"00");
  EXPECT_STREQ(data->data()->multiarch()->c_str(),"");
  EXPECT_STREQ(data->data()->name()->c_str(),"NicePackage");
  EXPECT_STREQ(data->data()->location()->c_str(),"\\home");
  EXPECT_STREQ(data->data()->priority()->c_str(),"");
  EXPECT_STREQ(data->data()->scan_time()->c_str(),"00/00/0000T00:00:00.000");
  EXPECT_EQ(data->data()->size(),0);
  EXPECT_STREQ(data->data()->source()->c_str(),"wazuh");
  EXPECT_STREQ(data->data()->vendor()->c_str(),"wazuh");
  EXPECT_STREQ(data->data()->version()->c_str(),"v1");

  std::remove(SYNC_PMSG_TEST_PATH);
}

