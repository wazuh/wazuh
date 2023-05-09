#ifndef HLP_COMMON_DEF_HPP
#define HLP_COMMON_DEF_HPP

#include <deque>
#include <functional>

namespace hlp {
/**
 * @brief Result of a mergeable parser, returns a list of a callback functions to be called
 *       when the parser is finished to get the result in one object.
 *
 * @tparam T Type of the result
 */
template<typename T>
using fnList = std::deque<std::function<void(T&)>>;
using jFnList = fnList<json::Json>;
}
#endif // HLP_COMMON_DEF_HPP
