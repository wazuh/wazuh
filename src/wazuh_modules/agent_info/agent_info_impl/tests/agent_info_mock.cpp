#include "agent_info.h"

#include <string>

// Configurable mock value for cluster_name
static std::string g_mock_cluster_name = "test_cluster";

void mock_set_cluster_name(const std::string& name)
{
    g_mock_cluster_name = name;
}

const char* agent_info_get_cluster_name()
{
    return g_mock_cluster_name.c_str();
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
