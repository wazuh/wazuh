#include <gtest/gtest.h>

#include <queue/concurrentQueue.hpp>

#include "fakeMetric.hpp" // TODO Remove after implementing metrics mocks

using namespace base::queue;

// Dummy class for testing ConcurrentQueue
class Dummy
{
public:
    int value;

    Dummy(int v)
        : value(v)
    {
    }

    std::string str() const { return "Dummy: " + std::to_string(value); }
};

class ConcurrentQueueTest : public ::testing::Test
{
protected:
    ConcurrentQueueTest() {}

    ~ConcurrentQueueTest() {}

    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};
TEST(FloodingFileTest, CanOpenAndWriteToFile)
{
    std::string filename = "testfile.txt";
    {
        FloodingFile ff(filename);
        ASSERT_FALSE(ff.getError().has_value());
        ASSERT_TRUE(ff.write("This is a test message"));
    }
    std::ifstream testfile(filename);
    std::string line;
    std::getline(testfile, line);
    ASSERT_EQ(line, "This is a test message");
    testfile.close();
    std::filesystem::remove(filename);
}

TEST(FloodingFileTest, CannotOpenFile)
{
    std::string invalid_path = "/nonexistent_dir/nonexistent_file.txt";
    FloodingFile ff(invalid_path);
    ASSERT_TRUE(ff.getError().has_value());
    ASSERT_FALSE(ff.write("This should fail"));
}

TEST_F(ConcurrentQueueTest, CanConstruct)
{
    auto metricManager = std::make_shared<FakeMetricManager>();

    ConcurrentQueue<std::shared_ptr<Dummy>> cq(
        2, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}

TEST_F(ConcurrentQueueTest, errorConstructor)
{
    ASSERT_THROW(ConcurrentQueue<std::shared_ptr<Dummy>> cq(1,
                                                            std::make_shared<FakeMetricScope>(),
                                                            std::make_shared<FakeMetricScope>(),
                                                            "/nonexistent_dir/nonexistent_file.txt"),
                 std::runtime_error);
}

TEST_F(ConcurrentQueueTest, CanPushAndPop)
{
    ConcurrentQueue<std::shared_ptr<Dummy>> cq(
        2, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
    ASSERT_TRUE(cq.empty());
    cq.push(std::make_shared<Dummy>(1));
    ASSERT_FALSE(cq.empty());
    ASSERT_EQ(cq.size(), 1);
    auto d = std::make_shared<Dummy>(0);
    ASSERT_TRUE(cq.waitPop(d));
    ASSERT_EQ(d->value, 1);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}

TEST_F(ConcurrentQueueTest, FloodsWhenFull)
{
    std::string flood_file = "floodfile.txt";
    // 32 is the size of one block in the queue, for 1 producer and 1 consumer thread
    // the queue has 1 block, so it will flood after 32 pushes
    ConcurrentQueue<std::shared_ptr<Dummy>> cq(
        32, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>(), flood_file, 3, 500);

    for (int i = 0; i < 35; i++)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    ASSERT_FALSE(cq.empty());
    ASSERT_EQ(cq.size(), 32);

    std::ifstream floodfile(flood_file);
    int num_flooded = 0;
    std::string line;
    while (std::getline(floodfile, line))
    {
        num_flooded++;
    }

    ASSERT_EQ(num_flooded, 3);
    floodfile.close();
    std::filesystem::remove(flood_file);
}

TEST_F(ConcurrentQueueTest, Timeout)
{
    ConcurrentQueue<std::shared_ptr<Dummy>> cq(
        2, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
    auto d = std::make_shared<Dummy>(0);
    ASSERT_FALSE(cq.waitPop(d, 0));
    ASSERT_EQ(d->value, 0);
}
