#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include <queue/concurrentQueue.hpp>

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

    std::string toString() const { return "Dummy: " + std::to_string(value); }
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

TEST(ConcurrentQueueTest, CanConstruct)
{
    ConcurrentQueue<Dummy> cq(2);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}

TEST(ConcurrentQueueTest, errorConstructor)
{
    ASSERT_THROW(ConcurrentQueue<Dummy> cq(1, "/nonexistent_dir/nonexistent_file.txt"), std::runtime_error);
}

TEST(ConcurrentQueueTest, CanPushAndPop)
{
    ConcurrentQueue<Dummy> cq(2);
    ASSERT_TRUE(cq.empty());
    cq.push(Dummy(1));
    ASSERT_FALSE(cq.empty());
    ASSERT_EQ(cq.size(), 1);
    Dummy d(0);
    ASSERT_TRUE(cq.waitPop(d));
    ASSERT_EQ(d.value, 1);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}

TEST(ConcurrentQueueTest, FloodsWhenFull)
{
    std::string flood_file = "floodfile.txt";
    // 32 is the size of one block in the queue, for 1 producer and 1 consumer thread
    // the queue has 1 block, so it will flood after 32 pushes
    ConcurrentQueue<Dummy> cq(32, flood_file);

    for (int i = 0; i < 35; i++)
    {
        cq.push(Dummy(i));
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

TEST(ConcurrentQueueTest, Timeout)
{
    ConcurrentQueue<Dummy> cq(2);
    Dummy d(0);
    ASSERT_FALSE(cq.waitPop(d, 0));
    ASSERT_EQ(d.value, 0);
}
