#ifndef _WPROFILE_H
#define _WPROFILE_H
#ifndef WAZUH_PROFILING_ENABLED

#define WAZUH_TRACE_FUNCTION
#define WAZUH_TRACE_FUNCTION_S(n)
#define WAZUH_TRACE_SCOPE(name)
#define WAZUH_PROFILE_THREAD_NAME(name)

#else
#include <Tracy.hpp>

#define WAZUH_TRACE_FUNCTION            ZoneScoped;
#define WAZUH_TRACE_FUNCTION_S(n)       ZoneScopedS(n);
#define WAZUH_TRACE_SCOPE(name)         ZoneScopedN(name);
#define WAZUH_PROFILE_THREAD_NAME(name) tracy::SetThreadName(name);

#endif
#endif
