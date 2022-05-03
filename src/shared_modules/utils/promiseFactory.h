#include <future>
#include <thread>

enum PromiseType
{
    NORMAL,
    SLEEP
};

template <PromiseType osType>
class PromiseFactory final
{
    public:
        static void set_value(std::promise<void>& promise) {
            promise.set_value();

        }

        static void wait(std::promise<void>& promise)
        {
            promise.get_future().wait();

        }
};

template <>
class PromiseFactory<PromiseType::SLEEP> final
{
    public:
        static void set_value(__attribute__((unused)) std::promise<void>& promise) {}

        static void wait(__attribute__((unused)) std::promise<void>& promise)
        {
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }
};
