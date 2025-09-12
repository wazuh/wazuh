#ifndef _BASE_TEST_FUNCTIONEXECUTOR_HPP
#define _BASE_TEST_FUNCTIONEXECUTOR_HPP

#include <atomic>
#include <functional>
#include <random>
#include <vector>

namespace base::test
{
class FunctionExecutor
{
private:
    std::vector<std::function<void()>> m_functions;

    // Random number generator
    std::random_device m_rd;
    std::mt19937 m_gen;
    std::uniform_int_distribution<> m_dis;

    // Atomic round-robin m_index
    std::atomic<uint> m_index;

    size_t getRandomIndex()
    {
        return [gen = m_gen, dis = m_dis]() mutable
        {
            return dis(gen);
        }();
    }

public:
    template<typename... Funcs>
    explicit FunctionExecutor(Funcs&&... funcs)
        : m_functions({std::forward<Funcs>(funcs)...})
        , m_gen(m_rd())
        , m_dis(0, m_functions.size() - 1)
        , m_index(0)
    {
    }

    void executeRandomFunction()
    {
        if (m_functions.empty())
        {
            return;
        }

        m_functions[getRandomIndex()]();
    }

    void executeRoundRobinFunction()
    {
        if (m_functions.empty())
        {
            return;
        }

        // Round-robin select and execute one function
        auto roundRobinIndex = m_index.fetch_add(1, std::memory_order_relaxed);
        m_functions[roundRobinIndex % m_functions.size()]();
    }
};

} // namespace base::test

#endif // _BASE_TEST_FUNCTIONEXECUTOR_HPP
