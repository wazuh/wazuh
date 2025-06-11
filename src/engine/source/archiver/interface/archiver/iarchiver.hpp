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
     * @brief Archive the given data.
     *
     * @param data The data to archive.
     * @return base::OptError An optional error if the archiving fails.
     */
    virtual base::OptError archive(const std::string& data) = 0;

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
