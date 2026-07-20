#include "agent_info.h"

#include <string>

// Configurable mock values for cluster_name and cluster_node
static std::string g_mock_cluster_name = "test_cluster";
static std::string g_mock_cluster_node = "test_node";

void mock_set_cluster_name(const std::string& name)
{
    g_mock_cluster_name = name;
}

void mock_set_cluster_node(const std::string& node)
{
    g_mock_cluster_node = node;
}

const char* agent_info_get_cluster_name()
{
    return g_mock_cluster_name.c_str();
}

const char* agent_info_get_cluster_node()
{
    return g_mock_cluster_node.c_str();
}

const char* agent_info_get_agent_groups()
{
    // Return empty string so tests fall back to reading groups from merged.mg,
    // This preserves the original test behavior
    return "";
}

void agent_info_clear_agent_groups()
{
    // No-op mock implementation
}
