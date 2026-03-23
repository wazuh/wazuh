#ifndef _BASE_TIMER_HPP
#define _BASE_TIMER_HPP

#include <chrono>

namespace base::chrono
{

/**
 * @brief Simple high-resolution timer for measuring elapsed time.
 *
 * Starts counting on construction. Call elapsed() to retrieve the duration.
 */
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
     * @brief Get the elapsed time since construction.
     *
     * @tparam T Duration type (default: std::chrono::milliseconds).
     * @return The elapsed time count in the given duration type.
     */
    template<typename T = std::chrono::milliseconds>
    auto elapsed() const
    {
        return std::chrono::duration_cast<T>(std::chrono::high_resolution_clock::now() - m_start).count();
    }
};

} // namespace base::chrono

#endif // _BASE_TIMER_HPP
