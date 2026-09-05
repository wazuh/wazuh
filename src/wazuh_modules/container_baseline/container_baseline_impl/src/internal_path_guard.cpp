#include "internal_path_guard.hpp"

namespace wazuh::container_baseline {

bool IsSafeInternalPath(const std::string& path)
{
    if (path.empty() || path.size() > kMaxInternalPathLength) return false;
    if (path.front() != '/') return false;

    // An embedded NUL makes the string that is validated here different from the
    // C string the kernel later sees, so the check would be meaningless.
    if (path.find('\0') != std::string::npos) return false;

    if (path == "/") return true;

    // Walk the components without allocating. `start` is always just past a '/'.
    for (std::size_t start = 1; start <= path.size();) {
        const auto slash = path.find('/', start);
        const auto end   = (slash == std::string::npos) ? path.size() : slash;
        const auto len   = end - start;

        // len == 0 catches both "//" and a trailing '/', which reach here as an
        // empty component.
        if (len == 0) return false;
        if (len == 1 && path[start] == '.') return false;
        if (len == 2 && path[start] == '.' && path[start + 1] == '.') return false;

        if (slash == std::string::npos) break;
        start = slash + 1;
    }

    return true;
}

} // namespace wazuh::container_baseline
