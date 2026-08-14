#include <base/libwazuhshared.hpp>

#include <dlfcn.h>
#include <fmt/format.h>
#include <stdexcept>
#include <string>

namespace
{
void* g_libPtr = nullptr;
}

namespace base::libwazuhshared
{
void init()
{
    if (!g_libPtr)
    {
        g_libPtr = dlopen("libwazuhshared.so", RTLD_NOW | RTLD_GLOBAL);
        if (!g_libPtr)
        {
            throw std::runtime_error(std::string("dlopen libwazuhshared.so failed: ") + dlerror());
        }
    }
}

void shutdown()
{
    if (g_libPtr)
    {
        dlclose(g_libPtr);
        g_libPtr = nullptr;
    }
}

void* getLibPtr()
{
    return g_libPtr;
}

// Wrapper for OS_SetName
void setLoggerTag(std::string_view tag)
{
    using SetNameFnType = void (*)(const char*);
    const auto setNameFn = getFunction<SetNameFnType>("OS_SetName");
    if (!setNameFn)
    {
        throw std::runtime_error("Failed to get OS_SetName function pointer.");
    }
    setNameFn(tag.data());
}

// Wrapper for get_indexer_cnf
std::string getJsonIndexerCnf()
{
    using ReadEngineCnfFnType = char* (*)(const char*, char*, size_t);
    const auto readEngineCnfFn = getFunction<ReadEngineCnfFnType>("get_indexer_cnf");

    char errBuf[1024] = {0};
    char* result = readEngineCnfFn("etc/wazuh-manager.conf", errBuf, sizeof(errBuf));
    if (!result)
    {
        throw std::runtime_error(fmt::format("get_indexer_cnf failed: {}", errBuf));
    }

    std::string jsonCnf(result);
    free(result);
    return jsonCnf;
}

std::pair<std::string, std::string> getClusterNameAndNodeName()
{
    using GetClusterNameFnType = char* (*)();
    const auto getClusterNameFn = getFunction<GetClusterNameFnType>("get_cluster_name");
    using GetClusterNodeNameFnType = char* (*)();
    const auto getClusterNodeNameFn = getFunction<GetClusterNodeNameFnType>("get_node_name");

    if (!getClusterNameFn)
    {
        throw std::runtime_error("Failed to get get_cluster_name function pointer.");
    }

    if (!getClusterNodeNameFn)
    {
        throw std::runtime_error("Failed to get get_node_name function pointer.");
    }

    char* result = getClusterNameFn();
    if (!result)
    {
        throw std::runtime_error("get_cluster_name returned null.");
    }
    std::string clusterName(result);
    free(result);

    result = getClusterNodeNameFn();
    if (!result)
    {
        throw std::runtime_error("get_node_name returned null.");
    }
    std::string nodeName(result);
    free(result);
    return std::make_pair(clusterName, nodeName);
}

} // namespace base::libwazuhshared
