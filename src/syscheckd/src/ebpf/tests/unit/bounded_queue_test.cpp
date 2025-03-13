#include "bounded_queue.hpp"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

using fim::BoundedQueue;

TEST(BoundedQueueTest, PushAndPop) {
    BoundedQueue<int> queue(3);
    int value;

    EXPECT_TRUE(queue.push(1));
    EXPECT_TRUE(queue.push(2));
    EXPECT_TRUE(queue.push(3));
    EXPECT_FALSE(queue.push(4)); // Queue is full

    EXPECT_TRUE(queue.pop(value, 100));
    EXPECT_EQ(value, 1);
    EXPECT_TRUE(queue.pop(value, 100));
    EXPECT_EQ(value, 2);
    EXPECT_TRUE(queue.pop(value, 100));
    EXPECT_EQ(value, 3);
    EXPECT_FALSE(queue.pop(value, 100)); // Queue is empty
}

TEST(BoundedQueueTest, PushMove) {
    BoundedQueue<std::string> queue(1);
    std::string str = "test";

    EXPECT_TRUE(queue.push(std::move(str)));
    std::string out_value;
    EXPECT_TRUE(queue.pop(out_value, 100));
    EXPECT_EQ(out_value, "test");
}

TEST(BoundedQueueTest, SetMaxSize) {
    BoundedQueue<int> queue(2);

    EXPECT_TRUE(queue.push(1));
    EXPECT_TRUE(queue.push(2));
    EXPECT_FALSE(queue.push(3)); // Queue is full

    queue.setMaxSize(1);
    EXPECT_EQ(queue.size(), 1);

    int value;
    EXPECT_TRUE(queue.pop(value, 100));
    EXPECT_EQ(value, 2);
    EXPECT_FALSE(queue.pop(value, 100)); // Queue is empty
}

TEST(BoundedQueueTest, EmptyAndSize) {
    BoundedQueue<int> queue(3);

    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.size(), 0);

    EXPECT_TRUE(queue.push(1));
    EXPECT_FALSE(queue.empty());
    EXPECT_EQ(queue.size(), 1);

    int value;
    EXPECT_TRUE(queue.pop(value, 100));
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.size(), 0);
}

TEST(BoundedQueueTest, Timeout) {
    BoundedQueue<int> queue(1);
    int value;

    EXPECT_FALSE(queue.pop(value, 100)); // Timeout
    std::thread producer([&queue]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        queue.push(1);
    });
    EXPECT_TRUE(queue.pop(value, 500));
    producer.join();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
