#include "baseMacros.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#if WAZUH_ASSERT_WITH_SYM
#include <cxxabi.h> //Gcc specific
#include <dlfcn.h>
#include <unwind.h> //Gcc specific
#endif

#include <signal.h>

#include <logging/logging.hpp>

#if WAZUH_ASSERT_WITH_SYM
struct BtState
{
    int skip;
    int count;
    std::vector<_Unwind_Word> addrs;
};

constexpr int kMaxStackTraceDepth = 7;
// This only works on unix and if we compile with -rdynamic
// because we use the dladdr function to get the symbol names
// wich needs the symbols to be in the dyn table
static std::string getBacktrace()
{
    auto tracer = [](_Unwind_Context* ctx, void* s)
    {
        auto* state = static_cast<BtState*>(s);
        if (state->count == state->addrs.size())
        {
            return _URC_END_OF_STACK;
        }
        auto ip = _Unwind_GetIP(ctx);
        if (ip)
        {
            if (!state->skip)
            {
                state->addrs.push_back(ip);
            }
            else
            {
                state->skip--;
            }
        }
        return _URC_NO_REASON;
    };

    BtState s;
    s.skip = 2;
    s.count = kMaxStackTraceDepth;
    _Unwind_Backtrace(tracer, &s);

    int i = 0;
    std::string ret;
    for (auto f : s.addrs)
    {
        Dl_info info;
        if (dladdr((void*)f, &info))
        {
            char* demangled = NULL;
            int ok;
            demangled = abi::__cxa_demangle(info.dli_sname, NULL, 0, &ok);
            if (ok == 0)
            {
                ret += fmt::format("{}) {}\n", i++, demangled);
                free(demangled);
            }
        }
    }

    return ret;
}
#else
static std::string getBacktrace()
{
    return {};
}
#endif

void wazuhAssertImpl(const char* expr, const char* file, const char* func, int line)
{
    LOG_ERROR("Engine base: ASSERT FAILED ({}): {}::{}::{}: {}", expr, file, func, line, getBacktrace());

    // Only for unix
    raise(SIGTRAP);
    // CRASH
    //*((volatile int *)0) = 0xDEADBEEF;
}

void wazuhAssertMsgImpl(
    const char* expr, const char* file, const char* func, int line, const char* fmt, ...)
{
    const int largeEnough {2048};
    char output[largeEnough + 1] = {};
    char fmtMsg[largeEnough + 1] = {};

    va_list args;
    va_start(args, fmt);

    const int len {vsnprintf(fmtMsg, largeEnough, fmt, args)};
    LOG_ERROR("Engine base: ASSERT FAILED ({}): {}::{}::{}: {}: {}", expr, file, func, line, fmtMsg, getBacktrace());

    // Only for unix
    raise(SIGTRAP);
    // CRASH
    //*((volatile int *)0) = 0xDEADBEEF;
}
