#ifndef _BASE_TEST_THREADSYNCHRONIZER_HPP
#define _BASE_TEST_THREADSYNCHRONIZER_HPP

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>

namespace base::test
{
class ThreadSynchronizer
{
private:
    int totalThreads;
    std::atomic_uint waitingThreads;
    std::atomic_bool condition;
    std::condition_variable cv;
    std::mutex cvMtx;

public:
    explicit ThreadSynchronizer(int totalThreads)
        : totalThreads(totalThreads)
        , waitingThreads(0)
        , condition(false)
    {
    }

    // Method to wait for all threads to be ready
    void waitForAll(std::chrono::milliseconds timeout = std::chrono::milliseconds(1000))
    {
        waitingThreads.fetch_add(1, std::memory_order_relaxed);
        std::unique_lock<std::mutex> lock(cvMtx);

        // Handle spurious wake-ups with
        cv.wait(lock, [&]() { return condition.load(std::memory_order_relaxed); });
    }

    // Reset the condition for the next phase of synchronization
    void reset()
    {
        std::unique_lock<std::mutex> lock(cvMtx);
        condition.store(false, std::memory_order_relaxed);
        waitingThreads.store(0, std::memory_order_relaxed);
    }

    // Notify all threads once the condition is met
    void notifyAll()
    {
        std::lock_guard<std::mutex> lock(cvMtx);
        condition.store(true, std::memory_order_relaxed);
        cv.notify_all();
    }

    void waitNotifyAll(std::function<void()> preReleaseTask = nullptr)
    {
        while (waitingThreads.load(std::memory_order_relaxed) < totalThreads)
        {
            std::this_thread::yield();
        }

        if (preReleaseTask)
        {
            preReleaseTask();
        }

        waitingThreads.store(0, std::memory_order_relaxed);
        notifyAll();
    }
};

} // namespace base::test

#endif // _BASE_TEST_THREADSYNCHRONIZER_HPP
