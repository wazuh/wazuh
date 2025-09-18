#include <base/libwazuhshared.hpp>

#include <dlfcn.h>
#include <stdexcept>
#include <string>
#include <fmt/format.h>


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
    char* result = readEngineCnfFn("etc/ossec.conf", errBuf, sizeof(errBuf));
    if (!result)
    {
        throw std::runtime_error(fmt::format("get_indexer_cnf failed: {}", errBuf));
    }

    std::string jsonCnf(result);
    free(result);
    return jsonCnf;
}
}
