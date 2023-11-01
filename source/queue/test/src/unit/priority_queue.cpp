#include <gtest/gtest.h>
#include <queue/concurrentQueue.hpp>
#include <baseTypes.hpp>
#include <queue/mockQueue.hpp>

// Número de productores y consumidores
const int numProducers = 5;
const int numConsumers = 5;
const int totalItems = numProducers * 10;
const int numItemsPerProducer = 10;

TEST(ConcurrentQueueTest, SingleProducerAndConsumer) {
    moodycamel::ConcurrentQueue<int> q;

    moodycamel::ProducerToken ptok(q);
    moodycamel::ConsumerToken ctok(q);

    // Productor
    std::thread producer([&q, &ptok]() {
        for (int i = 0; i < 10; ++i) {
            q.enqueue(ptok, i);
        }
    });

    // Consumidor
    std::thread consumer([&q, &ctok]() {
        int sum = 0;
        for (int i = 0; i < 10; ++i) {
            int item;
            while (!q.try_dequeue(ctok, item)) {
                // Espera si la cola está vacía
            }
            sum += item;
        }
        EXPECT_EQ(sum, 45);  // Suma de 0 a 9
    });

    producer.join();
    consumer.join();
}

TEST(ConcurrentQueueTest, MultipleProducersAndConsumers) {
    moodycamel::ConcurrentQueue<int> q;

    std::vector<std::thread> producerThreads;
    std::vector<std::thread> consumerThreads;

    // Variables compartidas para contar elementos y la suma
    std::atomic<int> itemCount(0);
    std::atomic<int> sum(0);

    // Productores
    for (int i = 0; i < numProducers; ++i) {
        producerThreads.emplace_back([i, &q, &itemCount]() {
            moodycamel::ProducerToken ptok(q);
            for (int j = 0; j < 10; ++j) {
                q.enqueue(ptok, i * 10 + j);
                itemCount.fetch_add(1);
            }
        });
    }

    // Consumidores
    for (int i = 0; i < numConsumers; ++i) {
        consumerThreads.emplace_back([i, &q, &sum, &itemCount]() {
            moodycamel::ConsumerToken ctok(q);
            int localSum = 0;
            int item;

            while (itemCount.load() > 0) {
                while (q.try_dequeue(ctok, item)) {
                    localSum += item;
                    itemCount.fetch_sub(1);
                }
            }

            sum.fetch_add(localSum);
        });
    }

    for (auto& producerThread : producerThreads) {
        producerThread.join();
    }

    for (auto& consumerThread : consumerThreads) {
        consumerThread.join();
    }

    EXPECT_EQ(sum.load(), (totalItems - 1) * totalItems / 2); // suma de gauss
}

TEST(ConcurrentQueueTest, MultipleProducersWithTryDequeueFromProducer) {
    moodycamel::ConcurrentQueue<int> q;

    for (auto i = 0; i < 2048; i++)
    {
        std::cout << i << std::endl;
        q.try_enqueue(i);
    }
    std::cout << "tamanio: " <<  q.size_approx() << std::endl;
}
