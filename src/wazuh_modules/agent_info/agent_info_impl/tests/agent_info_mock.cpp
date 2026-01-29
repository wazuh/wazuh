#include "agent_info.h"

const char* agent_info_get_cluster_name()
{
    return "test_cluster";
}

const char* agent_info_get_cluster_node()
{
    return "test_node";
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
