#ifndef _H_TESTS_COMMON
#define _H_TESTS_COMMON

#include <iostream>
#include <random>

#include <logging/logging.hpp>

std::string inline getRandomNumber(unsigned int length)
{
    const std::string digits = "0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, digits.size() - 1);

    std::string randomNumber;
    for (unsigned int i = 0; i < length; ++i)
    {
        randomNumber += digits[distribution(generator)];
    }

    return randomNumber;
}

std::string inline generateRandomStringWithPrefix(const unsigned int length, const std::string& prefix)
{
    std::string randomNumber = getRandomNumber(length);
    return prefix + randomNumber;
}

#endif // _H_TESTS_COMMON
