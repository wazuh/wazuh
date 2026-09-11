#ifndef VECTOR_HELPERS_HPP
#define VECTOR_HELPERS_HPP

#include <algorithm>
#include <utility>
#include <vector>

namespace base::utils
{

/**
 * @brief Erase the first element of a vector matching a predicate, in O(1), without preserving order.
 *
 * Finds the first element satisfying @p predicate and removes it by swapping it with the last element of
 * the container (skipped when it already is the last element) and then popping the back, instead of the
 * O(n) `erase(it)`. Only use this when the relative order of the remaining elements is not semantically
 * observed by callers.
 *
 * @tparam T Element type of the container
 * @tparam Predicate Callable type accepting `const T&` and returning something contextually convertible to bool
 * @param container Vector to erase from
 * @param predicate Predicate used to find the element to erase
 * @return true if a matching element was found and erased
 * @return false if no element matched @p predicate (container is left untouched)
 */
template<typename T, typename Predicate>
bool eraseFirstBySwap(std::vector<T>& container, Predicate predicate)
{
    auto it = std::find_if(container.begin(), container.end(), predicate);
    if (it == container.end())
    {
        return false;
    }

    if (it != std::prev(container.end()))
    {
        std::swap(*it, container.back());
    }
    container.pop_back();

    return true;
}

} // namespace base::utils

#endif // VECTOR_HELPERS_HPP
