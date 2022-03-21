#ifndef _WPROFILE_H
#define _WPROFILE_H
#ifndef WAZUH_PROFILING_ENABLED

#define WAZUH_TRACE_FUNCTION
#define WAZUH_TRACE_FUNCTION_S(n)
#define WAZUH_TRACE_SCOPE(name)

#else
#include <Tracy.hpp>

#define WAZUH_TRACE_FUNCTION      ZoneScoped;
#define WAZUH_TRACE_FUNCTION_S(n) ZoneScopedS(n);
#define WAZUH_TRACE_SCOPE(name)   ZoneScopedN(name);

#endif
#endif
