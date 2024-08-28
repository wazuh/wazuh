#ifndef _BASE_TIMER_HPP
#define _BASE_TIMER_HPP

#include <chrono>

namespace base::chrono
{

class Timer
{
private:
    decltype(std::chrono::high_resolution_clock::now()) m_start; ///< Start time of the timer

public:
    /**
     * @brief Construct a new Timer, this starts the timer immediately
     */
    Timer()
        : m_start {std::chrono::high_resolution_clock::now()}
    {
    }

    /**
     * @brief Get the elapsed time
     *
     * This function is used to get the elapsed time since the timer was started.
     * @return T Elapsed time
     */
    template<typename T = std::chrono::milliseconds>
    auto elapsed() const
    {
        return std::chrono::duration_cast<T>(std::chrono::high_resolution_clock::now() - m_start).count();
    }
};

} // namespace base::chrono

#endif // _BASE_TIMER_HPP
