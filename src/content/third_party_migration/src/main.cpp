#include <iostream>
#include "cmdLineHelper.hpp"
#include "orchestrator.hpp"

int main(int argc, const char* argv[])
{
    try
    {
        CmdLineArgs cmdLineArgs(argc, argv);
        Orchestrator::instance().start(cmdLineArgs);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
