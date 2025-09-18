#include <base/libwazuhshared.hpp>

#include <dlfcn.h>
#include <stdexcept>
#include <string>
#include <fmt/format.h>


static void* libptr = nullptr;

namespace base::libwazuhshared
{
void init()
{
    if (!libptr)
    {
        libptr = dlopen("libwazuhshared.so", RTLD_NOW | RTLD_GLOBAL);
        if (!libptr)
        {
            throw std::runtime_error(fmt::format("dlopen libwazuhshared.so failed: {}", dlerror()));
        }
    }
}

void shutdown()
{
    if (libptr)
    {
        dlclose(libptr);
        libptr = nullptr;
    }
}

void* getLibPtr()
{
    return libptr;
}

// Set the logger tag in wazuh-shared
void setLoggerTag(std::string_view tag)
{
    using SetNameFnType = void (*)(const char*);
    const auto setNameFn = getFunction<SetNameFnType>("OS_SetName");
    setNameFn(tag.data());
}

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
