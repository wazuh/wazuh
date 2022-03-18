#include <Tracy.hpp>

#ifndef WAZUH_PROFILING_ENABLED

#define WAZUH_TRACE_FUNCTION
#define WAZUH_TRACE_SCOPE(name)

#else

#define WAZUH_TRACE_FUNCTION ZoneScoped;
#define WAZUH_TRACE_FUNCTION_S(n) ZoneScopedS(n);
#define WAZUH_TRACE_SCOPE(name) ZoneScopedN(name);

#endif
