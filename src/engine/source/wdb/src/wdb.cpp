#include <wdb/wdb.hpp>

#include <unistd.h>

#include <logging/logging.hpp>

#include "unixSocketInterface.hpp"

WazuhDB::WazuhDB(std::string_view strPath) : path(strPath)
{

    if (std::filesystem::exists(path) == false)
    {
        const std::string msg {"The wdb socket does not exist:" + path.string()};
        throw std::runtime_error(msg);
    }
    else if (std::filesystem::is_socket(path) == false)
    {
        const std::string msg {"The wdb socket does not a socket:" + path.string()};
        throw std::runtime_error(msg);
    }

}

WazuhDB::~WazuhDB()
{
    if (fd != -1)
    {
        close(fd);
    }
};

int WazuhDB::connect()
{

    if (fd > 0)
    {
        WAZUH_LOG_DEBUG("Already connected to the wdb socket.. closing it");
        close(fd);
        fd = -1;
    }

    // change the name socketConnect to connect
    fd = socketinterface::socketConnect(path.c_str());
    return fd;
};
