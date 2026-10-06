#ifndef _HLP_TEST_ADDRESS_SPACE_CAP_HPP
#define _HLP_TEST_ADDRESS_SPACE_CAP_HPP

#include <cstdlib>
#include <fstream>
#include <functional>
#include <string>

#include <sys/resource.h>

#include <gtest/gtest.h>

// Address space headroom of a capped child: far below what a numeric key taken as an array index reserves
// (16 bytes per element: 1.6 GB for 99999999)
constexpr rlim_t ADDRESS_SPACE_HEADROOM = rlim_t {512} << 20;

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

// Death-test body: caps the address space of this (child) process at its current size plus the headroom, runs
// `body` and exits 0 if it returns true, 1 if it returns false and 2 if the cap cannot be set. A body that allocates
// in proportion to a numeric key dies instead of exhausting the host.
[[noreturn]] inline void exitUnderAddressSpaceCap(const std::function<bool()>& body)
{
    const auto vsize = currentVirtualSize();
    const rlimit limit {vsize + ADDRESS_SPACE_HEADROOM, vsize + ADDRESS_SPACE_HEADROOM};
    if (vsize == 0 || ::setrlimit(RLIMIT_AS, &limit) != 0)
    {
        std::_Exit(2);
    }
    std::_Exit(body() ? 0 : 1);
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

#endif // _HLP_TEST_ADDRESS_SPACE_CAP_HPP
