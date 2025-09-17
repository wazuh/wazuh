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
    auto* setNameFn = getFunction<SetNameFnType>("OS_SetName");
    setNameFn(tag.data());
}

}
