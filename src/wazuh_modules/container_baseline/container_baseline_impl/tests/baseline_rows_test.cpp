#include "baseline_rows.hpp"

#include <json.hpp>

#include <gtest/gtest.h>

using namespace wazuh::container_baseline;

namespace {

ContainerContextPtr MakeDockerContext()
{
    auto ctx = std::make_shared<ContainerContext>();
    ctx->runtime       = "docker";
    ctx->name          = "my-nginx";
    ctx->image         = "nginx";
    ctx->image_digest  = "sha256:abc";
    ctx->restart_count = 2;
    ctx->labels        = {{"team", "qa"}};
    ctx->network        = {{"bridge", "172.17.0.2"}};
    ctx->oci_mounts     = {{"/host/data", "/data", true}};
    return ctx;
}

ContainerContextPtr MakeKubernetesContext()
{
    auto ctx = std::make_shared<ContainerContext>();
    ctx->runtime = "kubernetes";
    ctx->name    = "nginx";
    ctx->image   = "nginx:1.25";

    KubernetesContext k8s;
    k8s.pod_uid       = "pod-uid";
    k8s.pod_name      = "nginx-0";
    k8s.k8s_namespace = "default";
    k8s.node_name     = "worker-1";
    ctx->kubernetes   = std::move(k8s);
    return ctx;
}

} // namespace

TEST(ApplyIdentity, StampsContainerIdAndSharedContextOntoFileRow)
{
    FileBaselineRow row;
    ContainerIdentity id;
    id.container_id = "abc123";
    id.context       = MakeKubernetesContext();

    ApplyIdentity(row, id);

    EXPECT_EQ(row.container_id, "abc123");
    ASSERT_TRUE(row.container != nullptr);
    EXPECT_EQ(row.container->name, "nginx");
    ASSERT_TRUE(row.container->kubernetes.has_value());
    EXPECT_EQ(row.container->kubernetes->pod_name, "nginx-0");
    EXPECT_EQ(row.container->kubernetes->k8s_namespace, "default");
}

TEST(BuildFimFileJson, ProducesExpectedShapeAndStableId)
{
    FileBaselineRow row;
    row.path        = "/etc/passwd";
    row.permissions = "0644";
    row.uid         = "0";
    row.gid         = "0";
    row.mtime       = 1700000000;
    row.size        = 1234;
    row.inode       = 5678;
    row.device      = 9;
    row.hash_md5    = "d41d8cd98f00b204e9800998ecf8427e";
    row.hash_sha1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    row.hash_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    row.container_id = "cid1";
    row.container     = MakeKubernetesContext();

    const auto [id, json_str] = BuildFimFileJson(row);
    EXPECT_EQ(id, "cid1:/etc/passwd");

    const auto j = nlohmann::json::parse(json_str);
    EXPECT_EQ(j.at("path"), "/etc/passwd");
    EXPECT_EQ(j.at("permissions"), "0644");
    EXPECT_EQ(j.at("hash_md5"), row.hash_md5);
    EXPECT_EQ(j.at("hash_sha1"), row.hash_sha1);
    EXPECT_EQ(j.at("hash_sha256"), row.hash_sha256);
    EXPECT_EQ(j.at("baseline"), true);

    ASSERT_TRUE(j.contains("container"));
    EXPECT_EQ(j.at("container").at("id"), "cid1");
    EXPECT_EQ(j.at("container").at("name"), "nginx");
    EXPECT_EQ(j.at("container").at("runtime"), "kubernetes");
    EXPECT_EQ(j.at("container").at("image").at("name"), "nginx:1.25");

    ASSERT_TRUE(j.contains("kubernetes"));
    EXPECT_EQ(j.at("kubernetes").at("namespace"), "default");
    EXPECT_EQ(j.at("kubernetes").at("pod").at("uid"), "pod-uid");
    EXPECT_EQ(j.at("kubernetes").at("pod").at("name"), "nginx-0");
    EXPECT_EQ(j.at("kubernetes").at("node").at("name"), "worker-1");
}

TEST(BuildFimFileJson, DockerRowGetsContainerBlockButNoKubernetesBlock)
{
    FileBaselineRow row;
    row.path         = "/test_dir/test.txt";
    row.container_id = "cid-docker";
    row.container     = MakeDockerContext();

    const auto [id, json_str] = BuildFimFileJson(row);
    (void)id;
    const auto j = nlohmann::json::parse(json_str);

    ASSERT_TRUE(j.contains("container"));
    EXPECT_EQ(j.at("container").at("id"), "cid-docker");
    EXPECT_EQ(j.at("container").at("runtime"), "docker");
    EXPECT_EQ(j.at("container").at("image").at("name"), "nginx");
    EXPECT_EQ(j.at("container").at("image").at("digest"), "sha256:abc");
    EXPECT_EQ(j.at("container").at("labels").at("team"), "qa");
    EXPECT_EQ(j.at("container").at("restart_count"), 2);
    EXPECT_EQ(j.at("container").at("network")[0].at("ip"), "172.17.0.2");
    EXPECT_EQ(j.at("container").at("oci_mounts")[0].at("destination"), "/data");

    EXPECT_FALSE(j.contains("kubernetes"));
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
    EXPECT_EQ(j.at("container").at("id"), "cid2");
    EXPECT_FALSE(j.contains("kubernetes"));
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
