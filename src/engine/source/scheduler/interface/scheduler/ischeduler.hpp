#ifndef _ISCHEDULER_HPP
#define _ISCHEDULER_HPP

#include <functional>
#include <string_view>

namespace scheduler
{

/**
 * @brief Configuration structure for scheduled tasks
 * @details Contains all the necessary parameters to configure a task's execution behavior,
 *          including timing, priority, and the function to execute.
 */
struct TaskConfig
{
    std::size_t interval;               ///< Execution interval in seconds. 0 means run once (one-time task)
    int CPUPriority;                    ///< Process nice value for CPU priority. Range: -20 (highest) to 19 (lowest)
    int timeout;                        ///< Task timeout in seconds. 0 means no timeout (reserved for future use)
    std::function<void()> taskFunction; ///< The callable function/lambda to execute when the task runs
};

/**
 * @brief Abstract interface for task schedulers
 * @details Defines the contract that all scheduler implementations must follow.
 *          Provides methods for task management (scheduling/removal) and statistics.
 *
 * The scheduler manages tasks with different execution patterns:
 * - One-time tasks (interval = 0): Execute once and are automatically removed
 * - Recurring tasks (interval > 0): Execute periodically at the specified interval
 *
 * @note All implementations must be thread-safe as multiple threads may interact
 *       with the scheduler simultaneously.
 */
class IScheduler
{
public:
    /**
     * @brief Virtual destructor
     * @details Ensures proper cleanup of derived scheduler implementations
     */
    virtual ~IScheduler() = default;

    // Task injection interface

    /**
     * @brief Schedule a new task for execution
     * @details Adds a new task to the scheduler. The task will be executed according
     *          to its configuration. One-time tasks run immediately, recurring tasks
     *          are scheduled for their first execution after the specified interval.
     *
     * @param taskName Unique identifier for the task
     * @param config Task configuration including function, interval, and priority
     *
     * @throws std::invalid_argument if taskFunction is null
     * @throws std::runtime_error if a task with the same name already exists
     *
     * @note Tasks can be scheduled even when the scheduler is stopped, but they
     *       won't execute until start() is called
     * @note This method is thread-safe
     */
    virtual void scheduleTask(std::string_view taskName, TaskConfig&& config) = 0;

    /**
     * @brief Remove a scheduled task
     * @details Removes the specified task from the scheduler. If the task is currently
     *          executing, it will complete but won't be rescheduled.
     *
     * @param taskName Name of the task to remove
     *
     * @note Removing a non-existent task is safe and has no effect
     * @note This method is thread-safe
     */
    virtual void removeTask(std::string_view taskName) = 0;

    // Statistics interface

    /**
     * @brief Returns the current count of tasks managed by the scheduler. Includes both pending and executing tasks.
     * @return Number of active tasks
     * @note This method is thread-safe
     */

    virtual std::size_t getActiveTasksCount() const = 0;

    /**
     * @brief Returns the number of worker threads configured for this scheduler.
     * @return Number of worker threads
     * @note This value remains constant throughout the scheduler's lifetime
     */
    virtual std::size_t getThreadCount() const = 0;
};

} // namespace scheduler

#endif // _ISCHEDULER_HPP
