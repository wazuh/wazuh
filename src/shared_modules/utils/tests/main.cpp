#include "gtest/gtest.h"

int ALLOCATION_COUNTER = 0;
bool ENABLE_ALLOCATION_COUNTER = false;

void* operator new(size_t size)
{
    if (ENABLE_ALLOCATION_COUNTER)
    {
        ALLOCATION_COUNTER++;
    }
    return malloc(size);
}

void operator delete(void* ptr) noexcept
{
    free(ptr);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
