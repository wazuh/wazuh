#ifndef _DOT_PATH_HPP
#define _DOT_PATH_HPP

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/core.h>
#include <fmt/format.h>

#include <base/utils/stringUtils.hpp>

/**
 * @brief A dot-separated path, used to navigate nested field structures.
 *
 */
class DotPath
{
private:
    std::string m_str;                ///< The string representation of the path
    std::vector<std::string> m_parts; ///< The parts of the path

    /**
     * @brief Parse the string representation of the path into its parts.
     *
     * @throws std::runtime_error if the path is empty or has empty parts
     */
    void parse()
    {
        m_parts.clear();

        // Remove optional leading dot
        if (base::utils::string::startsWith(m_str, "."))
        {
            m_str = m_str.substr(1);
        }

        // Handle root path (empty string)
        if (m_str.empty())
        {
            return;
        }

        m_parts = base::utils::string::splitEscaped(m_str, '.', '\\');

        for (auto part : m_parts)
        {
            if (part.empty() && m_str != ".")
            {
                throw std::runtime_error("DotPath cannot have empty parts");
            }
        }
    }

    void copy(const DotPath& rhs)
    {
        m_str = rhs.m_str;
        m_parts = rhs.m_parts;
    }

    void move(DotPath&& rhs) noexcept
    {
        m_str = std::move(rhs.m_str);
        m_parts = std::move(rhs.m_parts);
    }

public:
    DotPath() = default;
    ~DotPath() = default;

    /**
     * @brief Create a new DotPath by appending two paths.
     *
     * @param lhs
     * @param rhs
     * @return DotPath
     */
    static DotPath append(const DotPath& lhs, const DotPath& rhs)
    {
        return DotPath(fmt::format("{}.{}", lhs.str(), rhs.str()));
    }

    /**
     * @brief Construct a new Dot Path object
     *
     * @param str
     * @throws std::runtime_error if the path is empty or has empty parts
     */
    DotPath(const std::string& str)
        : m_str(str)
    {
        parse();
    }

    /**
     * @brief Construct a new Dot Path object
     *
     * @param str
     * @throws std::runtime_error if the path is empty or has empty parts
     */
    DotPath(const char str[])
        : m_str(str)
    {
        parse();
    }

    /**
     * @brief Construct a new Dot Path object
     *
     * @param begin
     * @param end
     * @throws std::runtime_error if the path is empty or has empty parts
     */
    DotPath(decltype(m_parts.cbegin()) begin, const decltype(m_parts.cend())& end)
    {
        m_str = "";
        for (auto it = begin; it != end; ++it)
        {
            m_str += *it;
            if (it != end - 1)
            {
                m_str += ".";
            }
        }
        parse();
    }

    /**
     * @brief Construct a new Dot Path object
     *
     * @param rhs
     */
    DotPath(const DotPath& rhs) { copy(rhs); }

    /**
     * @brief Construct a new Dot Path object
     *
     * @param rhs
     */
    DotPath(DotPath&& rhs) noexcept { move(std::move(rhs)); }

    /**
     * @brief Copy assignment operator
     *
     * @param rhs
     * @return DotPath&
     */
    DotPath& operator=(const DotPath& rhs)
    {
        copy(rhs);
        return *this;
    }

    /**
     * @brief Move assignment operator
     *
     * @param rhs
     * @return DotPath&
     */
    DotPath& operator=(DotPath&& rhs) noexcept
    {
        move(std::move(rhs));
        return *this;
    }

    /**
     * @brief Constant iterator to the beginning of the path parts
     *
     * @return auto
     */
    auto cbegin() const { return m_parts.cbegin(); }

    /**
     * @brief Constant iterator to the end of the path parts
     *
     * @return auto
     */
    auto cend() const { return m_parts.cend(); }

    friend bool operator==(const DotPath& lhs, const DotPath& rhs) { return lhs.m_str == rhs.m_str; }
    friend bool operator!=(const DotPath& lhs, const DotPath& rhs) { return !(lhs == rhs); }

    friend std::ostream& operator<<(std::ostream& os, const DotPath& dp)
    {
        os << dp.m_str;
        return os;
    }

    /**
     * @brief Implicit conversion to std::string
     *
     * @return std::string
     */
    explicit operator std::string() const { return m_str; }

    /**
     * @brief Get the string representation of the path
     *
     * @return const std::string&
     */
    const std::string& str() const { return m_str; }

    /**
     * @brief Get the parts of the path
     *
     * @return const std::vector<std::string>&
     */
    const std::vector<std::string>& parts() const { return m_parts; }

    /**
     * @brief Transform pointer path string to dot path string
     *
     * @param jsonPath Pointer path string
     * @return DotPath string
     */
    static DotPath fromJsonPath(const std::string& jsonPath)
    {
        if (jsonPath.empty())
        {
            return DotPath();
        }

        std::string path = (jsonPath[0] == '/') ? jsonPath.substr(1) : jsonPath;
        auto parts = base::utils::string::split(path, '/');

        std::transform(parts.begin(),
                       parts.end(),
                       parts.begin(),
                       [](const std::string& part)
                       {
                           size_t index = 0;
                           auto partCopy = part;
                           // Replace all ~0 with ~
                           while (true)
                           {
                               index = partCopy.find("~0", index);
                               if (index == std::string::npos)
                                   break;
                               partCopy.replace(index, 2, "~");
                               index += 3;
                           }

                           // Replace all ~1 with /
                           index = 0;
                           while (true)
                           {
                               index = partCopy.find("~1", index);
                               if (index == std::string::npos)
                                   break;
                               partCopy.replace(index, 2, "/");
                               index += 3;
                           }

                           return partCopy;
                       });

        return DotPath(parts.begin(), parts.end());
    }
};

// Make DotPath formatable by fmt
template<>
struct fmt::formatter<DotPath> : formatter<std::string>
{
    // parse is inherited from formatter<string_view>.
    template<typename FormatContext>
    auto format(const DotPath& path, FormatContext& ctx)
    {
        return formatter<std::string>::format(path.str(), ctx);
    }
};

// Make DotPath hashable
namespace std
{
template<>
struct hash<DotPath>
{
    std::size_t operator()(const DotPath& path) const { return std::hash<std::string> {}(path.str()); }
};
} // namespace std

#endif // _DOT_PATH_HPP
