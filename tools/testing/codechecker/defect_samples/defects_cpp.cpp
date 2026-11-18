/*
 * defects_cpp.cpp — CodeChecker detection validation samples (C++).
 *
 * Defect map
 * ----------
 *   defect_auto_copy     -> performance-unnecessary-copy-initialization
 *   defect_dangling_ptr  -> clang.core.StackAddressEscape
 */
#include <string>
#include <vector>

/* performance-unnecessary-copy-initialization --------------------------------
 * 's' copies v[0] by value even though it is only read.
 * Fix: const auto& s = v[0];
 */
std::string defect_auto_copy(const std::vector<std::string> &v)
{
    const auto s = v[0];   /* unnecessary copy of std::string */
    return s;
}

/* clang.core.StackAddressEscape ---------------------------------------------
 * Returns the address of a local variable; the pointer is dangling as soon
 * as the function returns.
 */
const int *defect_dangling_ptr(void)
{
    int local = 42;
    return &local;   /* address of local variable escapes */
}
