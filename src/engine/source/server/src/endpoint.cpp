#include <server/endpoint.hpp>

#include <unistd.h> // Unlink

#include <base/logging.hpp>

namespace engineserver
{
void Endpoint::unlinkUnixSocket()
{
    struct stat st;
    if (0 == stat(m_address.c_str(), &st))
    {
        if (S_ISSOCK(st.st_mode))
        {
            if (0 != unlink(m_address.c_str()))
            {
                auto msg = fmt::format("Cannot remove the socket '{}': {} ({})", m_address, strerror(errno), errno);
                throw std::runtime_error(std::move(msg));
            }
        }
        else
        {
            auto msg = fmt::format("Path '{}' already exists and it is not a socket", m_address);
            throw std::runtime_error(std::move(msg));
        }
    }
}
} // namespace engineserver
