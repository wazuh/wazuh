#include <archiver/archiver.hpp>

namespace archiver
{

void Archiver::archive(const std::string& data)
{
    std::shared_lock<std::shared_mutex> lock(m_loggerMutex);
    if (m_logWriter)
    {
        m_logWriter->operator()(std::string(data));
    }
}

void Archiver::archive(const char* data)
{

    if (!data || *data == '\0')
    {
        return;
    }

    std::shared_lock<std::shared_mutex> lock(m_loggerMutex);
    if (m_logWriter)
    {
        m_logWriter->operator()(std::string(data));
    }
}

} // namespace archiver
