#include <dumper/dumper.hpp>

namespace dumper
{

void Dumper::dump(const std::string& data)
{
    std::shared_lock<std::shared_mutex> lock(m_loggerMutex);
    if (m_logWriter)
    {
        m_logWriter->operator()(std::string(data));
    }
}

void Dumper::dump(const char* data)
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

void Dumper::dump(std::string_view data)
{
    if (data.empty())
    {
        return;
    }

    std::shared_lock<std::shared_mutex> lock(m_loggerMutex);
    if (m_logWriter)
    {
        m_logWriter->operator()(std::string(data));
    }
}

} // namespace dumper
