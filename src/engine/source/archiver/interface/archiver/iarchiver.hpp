#ifndef _ARCHIVER_IARCHIVER_HPP
#define _ARCHIVER_IARCHIVER_HPP

#include <string>

#include <base/error.hpp>

namespace archiver
{

class IArchiver
{
public:
    virtual ~IArchiver() = default;

    /**
     * @brief Archive the given data if the archiver is active (ignore errors)
     *
     * @param data The data to archive, as a std::string.
     */
    virtual void archive(const std::string& data) = 0;

    /**
     * @brief  Archive the given data if the archiver is active (ignore errors
     *
     * @param data The data to archive, as a C-style string (To avoid copies in some cases).
     */
    virtual void archive(const char* data) = 0;

    /**
     * @brief Activate the archiver.
     *
     */
    virtual void activate() = 0;

    /**
     * @brief Deactivate the archiver.
     *
     */
    virtual void deactivate() = 0;

    /**
     * @brief Check if the archiver is active.
     *
     * @return true if the archiver is active, false otherwise.
     */
    virtual bool isActive() const = 0;
};

} // namespace archiver

#endif // _ARCHIVER_IARCHIVER_HPP
