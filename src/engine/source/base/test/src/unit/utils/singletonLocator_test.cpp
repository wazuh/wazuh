#include "base/mockSingletonManager.hpp"
#include "base/utils/singletonLocator.hpp"

#include <thread>

#include <gtest/gtest.h>

namespace singletonlocatortest
{
template<typename T>
class TestInstance
{
private:
    T value;

public:
    TestInstance() = default;

    void set(T val) { value = val; }
    T get() { return value; }
};

template<typename T>
class TestSingletonManager : public ISingletonManager<T>
{
private:
    T testInstance;

public:
    TestSingletonManager()
        : testInstance()
    {
    }

    T& instance() override { return testInstance; }
};

/*******************************************************************************
 * !!!!!!!!
 * Important: Use unique instance types in each test to allow parallel execution
 * Defining the same struct inside the test should suffice
 * ¡¡¡¡¡¡¡¡
 ******************************************************************************/

TEST(SingletonLocatorTest, RegisterUnregister)
{
    struct Test
    {
    };

    auto registerManager = []()
    {
        SingletonLocator::registerManager<Test, TestSingletonManager<Test>>();
    };

    EXPECT_NO_THROW(registerManager());
    EXPECT_THROW(registerManager(), std::logic_error); // Should throw because already registered

    // This should not compile
    // Not default constructible
    // SingletonLocator::registerManager<TestInstance<int&>, TestSingletonManager<TestInstance<int&>>>;
    // Not same Instance type
    // SingletonLocator::registerManager<TestInstance<int>, TestSingletonManager<TestInstance<float>>>();
    // Not derived from ISingletonManager
    // SingletonLocator::registerManager<TestInstance<int>, TestInstance<int>>();

    auto unregisterManager = []()
    {
        SingletonLocator::unregisterManager<Test>();
    };

    EXPECT_NO_THROW(unregisterManager());
    EXPECT_THROW(unregisterManager(), std::logic_error); // Should throw because already unregistered
    EXPECT_NO_THROW(registerManager());                  // Should be able to register again after unregistering
    EXPECT_NO_THROW(unregisterManager());                // Should be able to unregister again
}

TEST(SingletonLocatorTest, Instance)
{
    struct IntTest
    {
        int value;
    };
    SingletonLocator::registerManager<IntTest, TestSingletonManager<IntTest>>();
    auto& intInstance = SingletonLocator::instance<IntTest>();
    EXPECT_NO_THROW(intInstance.value = 1);
    EXPECT_EQ(intInstance.value, 1);

    struct FloatTest
    {
        float value;
    };
    SingletonLocator::registerManager<FloatTest, TestSingletonManager<FloatTest>>();
    auto& floatInstance = SingletonLocator::instance<FloatTest>();
    EXPECT_NO_THROW(floatInstance.value = 3.14f);
    EXPECT_EQ(floatInstance.value, 3.14f);

    SingletonLocator::unregisterManager<IntTest>();
    SingletonLocator::unregisterManager<FloatTest>();
}

TEST(SingletonLocatorTest, Manager)
{
    struct Instance
    {
    };

    auto getManager = []() -> ISingletonManager<Instance>&
    {
        return SingletonLocator::manager<Instance>();
    };

    EXPECT_THROW(getManager(), std::logic_error); // Should throw because no manager registered

    SingletonLocator::registerManager<Instance, TestSingletonManager<Instance>>();

    EXPECT_NO_THROW(getManager()); // Should not throw now

    SingletonLocator::unregisterManager<Instance>();

    EXPECT_THROW(getManager(), std::logic_error); // Should throw again because manager unregistered
}

TEST(SingletonLocatorTest, ParallelRegister)
{
    struct Instance
    {
    };

    for (size_t runs = 0; runs < 100; ++runs)
    {
        std::shared_ptr<std::vector<bool>> results = std::make_shared<std::vector<bool>>(10);
        std::vector<std::thread> threads;
        for (size_t i = 0; i < 10; ++i)
        {
            auto registerManager = [results, i]()
            {
                try
                {
                    SingletonLocator::registerManager<Instance, TestSingletonManager<Instance>>();
                }
                catch (...)
                {
                    (*results)[i] = false;
                    return;
                }

                (*results)[i] = true;
            };
            threads.emplace_back(registerManager);
        }

        for (auto& thread : threads)
        {
            thread.join();
        }

        EXPECT_EQ(std::count(results->begin(), results->end(), true), 1);
        ASSERT_NO_THROW(SingletonLocator::unregisterManager<Instance>());
    }
}

TEST(SingletonLocatorTest, ParallelUnregister)
{
    struct Instance
    {
    };

    SingletonLocator::registerManager<Instance, TestSingletonManager<Instance>>();

    for (size_t runs = 0; runs < 100; ++runs)
    {
        std::shared_ptr<std::vector<bool>> results = std::make_shared<std::vector<bool>>(10);
        std::vector<std::thread> threads;
        for (size_t i = 0; i < 10; ++i)
        {
            auto unregisterManager = [results, i]()
            {
                try
                {
                    SingletonLocator::unregisterManager<Instance>();
                }
                catch (...)
                {
                    (*results)[i] = false;
                    return;
                }

                (*results)[i] = true;
            };
            threads.emplace_back(unregisterManager);
        }

        for (auto& thread : threads)
        {
            thread.join();
        }

        EXPECT_EQ(std::count(results->begin(), results->end(), true), 1);
        // Re-register to allow next run
        auto registerManager = []()
        {
            SingletonLocator::registerManager<Instance, TestSingletonManager<Instance>>();
        };
        ASSERT_NO_THROW(registerManager());
    }

    ASSERT_NO_THROW(SingletonLocator::unregisterManager<Instance>());
}

TEST(SingletonLocatorTest, Clear)
{
    struct Instance
    {
    };

    SingletonLocator::registerManager<std::shared_ptr<Instance>, TestSingletonManager<std::shared_ptr<Instance>>>();
    SingletonLocator::instance<std::shared_ptr<Instance>>() = std::make_shared<Instance>();
    auto instance1 = SingletonLocator::instance<std::shared_ptr<Instance>>();
    auto instance2 = SingletonLocator::instance<std::shared_ptr<Instance>>();
    ASSERT_EQ(instance1.get(), instance2.get());
    ASSERT_EQ(instance1.use_count(), 3);

    SingletonLocator::clear();
    ASSERT_EQ(instance1.use_count(), 2);

    SingletonLocator::registerManager<std::shared_ptr<Instance>, TestSingletonManager<std::shared_ptr<Instance>>>();
    SingletonLocator::instance<std::shared_ptr<Instance>>() = std::make_shared<Instance>();

    auto instance3 = SingletonLocator::instance<std::shared_ptr<Instance>>();
    ASSERT_NE(instance1.get(), instance3.get());
    ASSERT_NE(instance2.get(), instance3.get());

    ASSERT_EQ(instance3.use_count(), 2);
    ASSERT_EQ(instance1.use_count(), 2);

    SingletonLocator::clear();

    ASSERT_EQ(instance1.use_count(), 2);
    ASSERT_EQ(instance2.use_count(), 2);
    ASSERT_EQ(instance3.use_count(), 1);
}

TEST(MockSingletonManagerTest, Test)
{
    struct Instance
    {
    };
    SingletonLocator::registerManager<Instance, base::test::MockSingletonManager<Instance>>();

    Instance instance;
    auto& manager = static_cast<base::test::MockSingletonManager<Instance>&>(SingletonLocator::manager<Instance>());
    EXPECT_CALL(manager, instance()).Times(10).WillRepeatedly(testing::ReturnRef(instance));

    std::vector<Instance*> gatheredInstances;
    gatheredInstances.reserve(10);
    for (auto i = 0; i < 10; ++i)
    {
        gatheredInstances[i] = &SingletonLocator::instance<Instance>();
    }

    // Check that all instances are different
    for (size_t i = 0; i < gatheredInstances.size(); ++i)
    {
        for (size_t j = 0; j < i; ++j)
        {

            EXPECT_EQ(gatheredInstances[i], gatheredInstances[j]);
        }
    }

    SingletonLocator::unregisterManager<Instance>();
}

} // namespace singletonlocatortest
