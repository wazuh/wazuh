#include <Tracy.hpp>

void *operator new(std::size_t count)
{
    auto ptr = malloc(count);
    //TracyAlloc(ptr, count);
    TracyAllocS(ptr, count, 2);
    return ptr;
}

void operator delete(void *ptr) noexcept
{
    //TracyFree(ptr);
    TracyFreeS(ptr, 2);
    free(ptr);
}
