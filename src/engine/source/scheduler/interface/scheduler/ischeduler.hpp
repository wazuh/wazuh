#ifndef _ISCHEDULER_HPP
#define _ISCHEDULER_HPP

#include <functional>
#include <string_view>

namespace scheduler
{

struct TaskConfig
{
    std::size_t interval;               // in seconds, 0 means run once
    int CPUPriority;                    // niceValue, lower means more priority (-20 to 19)
    int timeout;                        // in seconds, 0 means no timeout, for future use.
    std::function<void()> taskFunction; // The function to run
};

class IScheduler
{
public:
    virtual ~IScheduler() = default;

    // Task injection interface
    virtual void scheduleTask(std::string_view taskName, TaskConfig&& config) = 0;
    virtual void removeTask(std::string_view taskName) = 0;

    // Statistics interface
    virtual std::size_t getActiveTasksCount() const = 0;
    virtual std::size_t getThreadCount() const = 0;
};

} // namespace scheduler

#endif // _ISCHEDULER_HPP
