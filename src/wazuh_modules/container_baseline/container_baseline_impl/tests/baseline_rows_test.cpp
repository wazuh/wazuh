#include "baseline_rows.hpp"

#include <json.hpp>

#include <gtest/gtest.h>

using namespace wazuh::container_baseline;

TEST(ApplyIdentity, StampsAllContainerContextFieldsOntoFileRow)
{
    FileBaselineRow row;
    ContainerIdentity id;
    id.container_id   = "abc123";
    id.pod_uid        = "pod-uid";
    id.pod_name       = "nginx-0";
    id.k8s_namespace  = "default";
    id.container_name = "nginx";
    id.image          = "nginx:1.25";

    ApplyIdentity(row, id);

    EXPECT_EQ(row.container_id, "abc123");
    EXPECT_EQ(row.pod_uid, "pod-uid");
    EXPECT_EQ(row.pod_name, "nginx-0");
    EXPECT_EQ(row.k8s_namespace, "default");
    EXPECT_EQ(row.container_name, "nginx");
    EXPECT_EQ(row.image, "nginx:1.25");
}

TEST(BuildFimFileJson, ProducesExpectedShapeAndStableId)
{
    FileBaselineRow row;
    row.path          = "/etc/passwd";
    row.permissions   = "0644";
    row.uid           = "0";
    row.gid           = "0";
    row.mtime         = 1700000000;
    row.size          = 1234;
    row.inode         = 5678;
    row.device        = 9;
    row.hash_md5      = "d41d8cd98f00b204e9800998ecf8427e";
    row.hash_sha1     = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    row.hash_sha256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    row.container_id  = "cid1";
    row.k8s_namespace = "default";

    const auto [id, json_str] = BuildFimFileJson(row);
    EXPECT_EQ(id, "cid1:/etc/passwd");

    const auto j = nlohmann::json::parse(json_str);
    EXPECT_EQ(j.at("path"), "/etc/passwd");
    EXPECT_EQ(j.at("permissions"), "0644");
    EXPECT_EQ(j.at("hash_md5"), row.hash_md5);
    EXPECT_EQ(j.at("hash_sha1"), row.hash_sha1);
    EXPECT_EQ(j.at("hash_sha256"), row.hash_sha256);
    EXPECT_EQ(j.at("baseline"), true);
    ASSERT_TRUE(j.contains("kubernetes"));
    EXPECT_EQ(j.at("kubernetes").at("container_id"), "cid1");
    EXPECT_EQ(j.at("kubernetes").at("namespace"), "default");
}

TEST(BuildFimFileJson, OmitsEmptyHashesForSymlinks)
{
    FileBaselineRow row;
    row.path         = "/etc/link";
    row.is_symlink   = true;
    row.container_id = "cid1";

    const auto [id, json_str] = BuildFimFileJson(row);
    (void)id;
    const auto j = nlohmann::json::parse(json_str);
    EXPECT_FALSE(j.contains("hash_md5"));
    EXPECT_TRUE(j.at("is_symlink").get<bool>());
}

TEST(BuildProcessJson, ProducesExpectedShapeAndStableId)
{
    ProcessBaselineRow row;
    row.pid          = "42";
    row.name         = "nginx";
    row.state        = "sleeping";
    row.parent_pid   = 1;
    row.command_line = "nginx";
    row.args         = "-g daemon off;";
    row.args_count   = 3;
    row.container_id = "cid2";

    const auto [id, json_str] = BuildProcessJson(row);
    EXPECT_EQ(id, "cid2:42");

    const auto j = nlohmann::json::parse(json_str);
    EXPECT_EQ(j.at("process").at("pid"), "42");
    EXPECT_EQ(j.at("process").at("name"), "nginx");
    EXPECT_EQ(j.at("process").at("parent").at("pid"), 1);
    EXPECT_EQ(j.at("container").at("container_id"), "cid2");
}

TEST(BuildPortJson, ProducesExpectedShapeAndStableId)
{
    PortBaselineRow row;
    row.network_transport = "tcp";
    row.source_ip          = "10.0.0.5";
    row.source_port        = 8080;
    row.destination_ip     = "0.0.0.0";
    row.destination_port   = 0;
    row.interface_state    = "listen";
    row.file_inode          = 123456;
    row.process_pid         = 7;
    row.process_name        = "nginx";
    row.container_id        = "cid3";

    const auto [id, json_str] = BuildPortJson(row);
    EXPECT_EQ(id, "cid3:tcp:10.0.0.5:8080:123456");

    const auto j = nlohmann::json::parse(json_str);
    EXPECT_EQ(j.at("network").at("transport"), "tcp");
    EXPECT_EQ(j.at("source").at("ip"), "10.0.0.5");
    EXPECT_EQ(j.at("source").at("port"), 8080);
    EXPECT_EQ(j.at("interface_state"), "listen");
    EXPECT_EQ(j.at("process").at("name"), "nginx");
}

TEST(BuildPortJson, OmitsProcessBlockWhenUnattributed)
{
    PortBaselineRow row;
    row.network_transport = "udp";
    row.source_ip          = "127.0.0.1";
    row.source_port        = 53;
    row.file_inode          = 1;
    row.process_pid         = 0; // unattributed
    row.container_id        = "cid4";

    const auto [id, json_str] = BuildPortJson(row);
    (void)id;
    const auto j = nlohmann::json::parse(json_str);
    EXPECT_FALSE(j.contains("process"));
}
