#ifndef _HAS_MEMBER_H
#define _HAS_MEMBER_H

#include <type_traits>
#include <string>
#include <iostream>

namespace utils
{

/*
    Based on:
    https://stackoverflow.com/questions/257288/templated-check-for-the-existence-of-a-class-member-function
*/
template<typename T, typename F>
constexpr auto has_member_impl(F&& f) -> decltype(f(std::declval<T>()), true)
{
  return true;
}

template<typename>
constexpr bool has_member_impl(...) { return false; }

#define has_member(T, EXPR) \
 has_member_impl<T>( [](auto&& obj)->decltype(obj.EXPR){} )

} // namespace utils

#endif
