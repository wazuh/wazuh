#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <gtest/gtest.h>

#define GTEST_COUT std::cout << std::boolalpha << "[          ] [ INFO ] "

using namespace std;
namespace builder
{
namespace internals
{
}
} // namespace builder

using namespace builder::internals;

#endif // _TEST_UTILS_H
