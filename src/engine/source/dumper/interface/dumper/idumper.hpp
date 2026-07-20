#ifndef _DUMPER_IDUMPER_HPP
#define _DUMPER_IDUMPER_HPP

#include <string>
#include <string_view>

#include <base/error.hpp>

namespace dumper
{

class IDumper
{
public:
    virtual ~IDumper() = default;

    /**
     * @brief Dump the given data if the dumper is active (ignore errors)
     *
     * @param data The data to dump, as a std::string.
     */
    virtual void dump(const std::string& data) = 0;

    /**
     * @brief  Dump the given data if the dumper is active (ignore errors)
     *
     * @param data The data to dump, as a C-style string (To avoid copies in some cases).
     */
    virtual void dump(const char* data) = 0;

    /**
     * @brief Dump the given data if the dumper is active (ignore errors)
     *
     * @param data The data to dump, as a std::string_view (zero-copy view).
     */
    virtual void dump(std::string_view data) = 0;

    /**
     * @brief Activate the dumper.
     *
     */
    virtual void activate() = 0;

    /**
     * @brief Deactivate the dumper.
     *
     */
    virtual void deactivate() = 0;

    /**
     * @brief Check if the dumper is active.
     *
     * @return true if the dumper is active, false otherwise.
     */
    virtual bool isActive() const = 0;
};

} // namespace dumper

#endif // _DUMPER_IDUMPER_HPP
