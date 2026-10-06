#ifndef _BASE_TEST_ADDRESS_SPACE_CAP_HPP
#define _BASE_TEST_ADDRESS_SPACE_CAP_HPP

#include <cstdlib>
#include <fstream>
#include <functional>
#include <string>

#include <sys/resource.h>

#include <gtest/gtest.h>

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
constexpr bool UNDER_SANITIZER = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
constexpr bool UNDER_SANITIZER = true;
#else
constexpr bool UNDER_SANITIZER = false;
#endif
#else
constexpr bool UNDER_SANITIZER = false;
#endif

// Current virtual size of this process in bytes, from /proc/self/status (0 if it cannot be read)
inline rlim_t currentVirtualSize()
{
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
    {
        if (line.rfind("VmSize:", 0) == 0)
        {
            return static_cast<rlim_t>(std::strtoull(line.c_str() + 7, nullptr, 10)) * 1024;
        }
    }
    return 0;
}

// True when the hard RLIMIT_AS of this process leaves room for a cap of `headroom` above its current size (a host
// that already limits the address space below that makes the capped child exit 2: skip instead of failing)
inline bool addressSpaceCapFits(rlim_t headroom)
{
    rlimit current {};
    if (::getrlimit(RLIMIT_AS, &current) != 0)
    {
        return false;
    }
    return current.rlim_max == RLIM_INFINITY || current.rlim_max >= currentVirtualSize() + headroom;
}

// Death-test body: caps the address space of this (child) process at its current size plus `headroom`, runs `body`
// and exits 0 if it returns true, 1 if it returns false, 2 if the cap cannot be set and 3 if `body` throws (e.g.
// std::bad_alloc under the cap). A body that allocates far beyond the headroom fails instead of exhausting the host.
[[noreturn]] inline void exitUnderAddressSpaceCap(rlim_t headroom, const std::function<bool()>& body)
{
    const auto vsize = currentVirtualSize();
    const rlimit limit {vsize + headroom, vsize + headroom};
    if (vsize == 0 || ::setrlimit(RLIMIT_AS, &limit) != 0)
    {
        std::_Exit(2);
    }

    bool ok = false;
    try
    {
        ok = body();
    }
    catch (...)
    {
        // Never let gtest catch an exception inside the child
        std::_Exit(3);
    }
    std::_Exit(ok ? 0 : 1);
}

// Sets the death test style for the lifetime of the guard and restores the previous one
class DeathTestStyleGuard
{
public:
    explicit DeathTestStyleGuard(const char* style)
        : m_previous {::testing::FLAGS_gtest_death_test_style}
    {
        ::testing::FLAGS_gtest_death_test_style = style;
    }
    ~DeathTestStyleGuard() { ::testing::FLAGS_gtest_death_test_style = m_previous; }
    DeathTestStyleGuard(const DeathTestStyleGuard&) = delete;
    DeathTestStyleGuard& operator=(const DeathTestStyleGuard&) = delete;

private:
    std::string m_previous;
};

// The cap conflicts with the shadow memory that ASAN and TSAN reserve
#define SKIP_UNDER_SANITIZER()                                                                                         \
    if (UNDER_SANITIZER)                                                                                               \
    {                                                                                                                  \
        GTEST_SKIP() << "RLIMIT_AS conflicts with the sanitizer shadow memory reservation";                            \
    }

#endif // _BASE_TEST_ADDRESS_SPACE_CAP_HPP
