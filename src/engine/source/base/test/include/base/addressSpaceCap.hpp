#ifndef _BASE_TEST_ADDRESSSPACECAP_HPP
#define _BASE_TEST_ADDRESSSPACECAP_HPP

#include <cstdlib>
#include <fstream>
#include <functional>
#include <string>

#include <sys/resource.h>

#include <gtest/gtest.h>

namespace base::test
{

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

// Room a capped child needs before the cap is set, in multiples of the JSON text it builds: the re-executed child
// rebuilds the text and parses it (and, in builder tests, builds the operation) between the parent's check and
// setrlimit; measured 1.1-2.2 x the text, so 8 x leaves a wide margin.
constexpr rlim_t SETUP_ALLOWANCE_FACTOR = 8;

// Exit code of a capped child whose body succeeded. Not 0: a child that never reached the cap (e.g. one that skipped
// before it) exits 0 and must not count as a pass.
constexpr int CAPPED_SUCCESS = 10;

// True when the hard RLIMIT_AS of this process leaves room for what the capped child will request: its current size,
// plus `setupBytes` for whatever the child builds before setting the cap (the parsed source, the event), plus
// `headroom`. A host that already limits the address space below that makes the child exit 2: skip instead of failing.
inline bool addressSpaceCapFits(rlim_t headroom, rlim_t setupBytes)
{
    rlimit current {};
    if (::getrlimit(RLIMIT_AS, &current) != 0)
    {
        return false;
    }
    return current.rlim_max == RLIM_INFINITY || current.rlim_max >= currentVirtualSize() + setupBytes + headroom;
}

// Death-test body: caps the address space of this (child) process at its current size plus `headroom`, runs `body`
// and exits CAPPED_SUCCESS if it returns true, 1 if it returns false, 2 if the cap cannot be set and 3 if `body` throws
// (e.g. std::bad_alloc under the cap). A body that allocates far beyond the headroom fails instead of exhausting the
// host. A child that dies does not leave a core dump behind.
[[noreturn]] inline void exitUnderAddressSpaceCap(rlim_t headroom, const std::function<bool()>& body)
{
    const rlimit noCore {0, 0};
    ::setrlimit(RLIMIT_CORE, &noCore);

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
    std::_Exit(ok ? CAPPED_SUCCESS : 1);
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

} // namespace base::test

// The cap conflicts with the shadow memory that ASAN and TSAN reserve
#define SKIP_UNDER_SANITIZER()                                                                                         \
    if (base::test::UNDER_SANITIZER)                                                                                   \
    {                                                                                                                  \
        GTEST_SKIP() << "RLIMIT_AS conflicts with the sanitizer shadow memory reservation";                            \
    }

#endif // _BASE_TEST_ADDRESSSPACECAP_HPP
